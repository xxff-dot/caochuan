// Package client 是内网侧：主动连接 server，接收数据流并回源到本地服务。
package client

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"

	"github.com/xxff-dot/caochuan/config"
	"github.com/xxff-dot/caochuan/logbuf"
	"github.com/xxff-dot/caochuan/proto"
	"github.com/xxff-dot/caochuan/relay"
)

const (
	dialTimeout  = 5 * time.Second
	backoffMax   = 30 * time.Second
	backoffStart = time.Second
)

type Client struct {
	Cfg     *config.ClientConfig
	Log     *logbuf.Ring
	Version string // 程序版本，鉴权时上报
	rr      atomic.Uint64
}

// Run 阻塞运行：连接 → 鉴权 → 收流；断线后指数退避重连，直到 ctx 取消。
func (c *Client) Run(ctx context.Context) error {
	backoff := backoffStart
	for {
		start := time.Now()
		err := c.serveOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// 连上后存活超过退避上限视为稳定过，重置退避
		if time.Since(start) > backoffMax {
			backoff = backoffStart
		}
		slog.Warn("连接断开，准备重连", "addr", c.Cfg.ServerAddr, "err", err, "backoff", backoff)
		c.Log.Write([]byte(fmt.Sprintf("连接断开: %v，%v 后重连\n", err, backoff)))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > backoffMax {
			backoff = backoffMax
		}
	}
}

// dialServer 建立到 server 的底层连接（TLS 或明文）。
func (c *Client) dialServer() (net.Conn, error) {
	raw, err := net.DialTimeout("tcp", c.Cfg.ServerAddr, dialTimeout)
	if err != nil {
		return nil, err
	}
	if c.Cfg.NoTLS {
		return raw, nil
	}
	host, _, _ := net.SplitHostPort(c.Cfg.ServerAddr)
	tc := tls.Client(raw, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // 证书链不校验；用指纹锁定代替（自签证书无公共信任链）
	})
	if err := tc.HandshakeContext(context.Background()); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("TLS 握手失败: %w", err)
	}
	// 指纹锁定：配置了 tls_fingerprint 时严格比对服务器证书
	if want := c.Cfg.TLSFingerprint; want != "" {
		certs := tc.ConnectionState().PeerCertificates
		if len(certs) == 0 {
			_ = raw.Close()
			return nil, fmt.Errorf("服务器未提供证书")
		}
		sum := sha256.Sum256(certs[0].Raw)
		got := hex.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(got), []byte(strings.ToLower(want))) != 1 {
			_ = raw.Close()
			return nil, fmt.Errorf("服务器证书指纹不匹配（期望 %s，实际 %s），拒绝连接", want, got)
		}
	}
	return tc, nil
}

// serveOnce 建立一次完整会话，阻塞到会话结束。
func (c *Client) serveOnce(ctx context.Context) error {
	conn, err := c.dialServer()
	if err != nil {
		return fmt.Errorf("拨号失败: %w", err)
	}
	defer conn.Close()

	host, _ := os.Hostname()
	req := proto.AuthRequest{Token: c.Cfg.Token, Host: host, Version: c.Version}
	if err := proto.WriteJSONFrame(conn, req); err != nil {
		return fmt.Errorf("发送鉴权失败: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var reply proto.AuthReply
	if err := proto.ReadJSONFrame(conn, &reply); err != nil {
		return fmt.Errorf("读取鉴权响应失败: %w", err)
	}
	if !reply.OK {
		return fmt.Errorf("鉴权被拒绝: %s", reply.Message)
	}
	_ = conn.SetReadDeadline(time.Time{})

	sess, err := smux.Client(conn, nil)
	if err != nil {
		return fmt.Errorf("smux 建立失败: %w", err)
	}
	defer sess.Close()

	// rev 是本会话私有的反向监听管理器：闭包捕获而非存到 Client 上，
	// 旧会话的残留 goroutine 只会触到自己这份，不会污染新会话
	rev := newReverseMgr()
	rev.session = sess
	gone := make(chan struct{})
	rev.gone = gone
	defer close(gone)
	if c.Cfg.Socks5Listen != "" { // 会话级 SOCKS5 出口代理
		addr := c.Cfg.Socks5Listen
		if !strings.Contains(addr, ":") {
			addr = "0.0.0.0:" + addr
		}
		go rev.startSocks5(addr)
	}

	mode := "TLS 加密"
	if c.Cfg.NoTLS {
		mode = "明文"
	}
	slog.Info("已连接服务器", "addr", c.Cfg.ServerAddr, "加密", mode)
	c.Log.Write([]byte(fmt.Sprintf("已连接服务器: %s (%s)\n", c.Cfg.ServerAddr, mode)))

	go func() { // ctx 取消时主动断会话
		select {
		case <-ctx.Done():
			_ = sess.Close()
		case <-gone:
		}
	}()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return fmt.Errorf("接受数据流结束: %w", err)
		}
		go c.handleStream(stream, rev)
	}
}

// handleStream 处理 server 开来的流；rev 是本会话的反向管理器（控制流归属它）。
func (c *Client) handleStream(stream net.Conn, rev *reverseMgr) {
	defer stream.Close()
	var hdr proto.StreamHeader
	_ = stream.SetReadDeadline(time.Now().Add(30 * time.Second))
	if err := proto.ReadJSONFrame(stream, &hdr); err != nil {
		slog.Warn("读取流头失败", "err", err)
		return
	}
	_ = stream.SetDeadline(time.Time{})

	if hdr.ID == proto.ControlID { // server 下发反向规则的控制流
		if rev != nil {
			rev.handleControl(stream)
		}
		return
	}

	if hdr.UDP {
		c.handleUDPStream(stream, hdr.Target)
		return
	}

	backend, err := c.dialBalanced(hdr.Target)
	if err != nil {
		slog.Warn("回源拨号失败", "target", hdr.Target, "err", err)
		return
	}
	defer backend.Close()

	if hdr.ProxyProto > 0 { // 按流头信息向目标写 PROXY 头，传递真实访客 IP
		src, e1 := net.ResolveTCPAddr("tcp", hdr.Visitor)
		dst, e2 := net.ResolveTCPAddr("tcp", hdr.DstAddr)
		if e1 == nil && e2 == nil {
			if b, err := relay.ProxyHeader(hdr.ProxyProto, src, dst); err == nil {
				_, _ = backend.Write(b)
			}
		}
	}

	relay.Pipe(backend, stream, nil, nil, nil, 0)
}

// dialBalanced 轮询拨号多目标（逗号分隔），失败自动尝试下一个。
func (c *Client) dialBalanced(target string) (net.Conn, error) {
	targets := relay.ParseTargets(target)
	if len(targets) == 0 {
		return nil, fmt.Errorf("目标地址为空")
	}
	start := int(c.rr.Add(1) - 1)
	var lastErr error
	for i := 0; i < len(targets); i++ {
		backend, err := net.DialTimeout("tcp", targets[(start+i)%len(targets)], dialTimeout)
		if err == nil {
			return backend, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// handleUDPStream 在一条流里按 connID 分发到多个本地 UDP socket。
func (c *Client) handleUDPStream(stream net.Conn, target string) {
	var wmu sync.Mutex // stream 写入互斥（多个后端 socket 同时回包）
	writeBack := func(connID uint32, payload []byte) {
		wmu.Lock()
		defer wmu.Unlock()
		_ = proto.WriteUDPPacket(stream, &proto.UDPPacket{ConnID: connID, Payload: payload})
	}

	var mu sync.Mutex
	backends := map[uint32]*net.UDPConn{}
	closeAll := func() {
		mu.Lock()
		defer mu.Unlock()
		for _, b := range backends {
			_ = b.Close()
		}
	}
	defer closeAll()

	br := bufio.NewReader(stream)
	for {
		pkt, err := proto.ReadUDPPacket(br)
		if err != nil {
			return // 流关闭，closeAll 兜底
		}
		mu.Lock()
		b := backends[pkt.ConnID]
		if b == nil {
			// 每个新会话轮询拨一个目标（重新解析，多目标故障转移 + DNS 跟随）
			if b, err = relay.DialUDPBalanced(target, &c.rr); err == nil {
				backends[pkt.ConnID] = b
				go func(connID uint32, b *net.UDPConn) { // 回包 → 隧道
					rbuf := make([]byte, 65535)
					for {
						_ = b.SetReadDeadline(time.Now().Add(udpIdleTimeout))
						n, err := b.Read(rbuf)
						if err != nil {
							break // 空闲超时或流关闭
						}
						writeBack(connID, rbuf[:n])
					}
					mu.Lock()
					delete(backends, connID)
					mu.Unlock()
					_ = b.Close()
				}(pkt.ConnID, b)
			}
		}
		mu.Unlock()
		if b != nil && err == nil {
			if _, err := b.Write(pkt.Payload); err != nil {
				mu.Lock()
				delete(backends, pkt.ConnID)
				mu.Unlock()
				_ = b.Close()
			}
		}
	}
}

const udpIdleTimeout = 90 * time.Second
