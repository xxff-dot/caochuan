package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/xxff-dot/caochuan/proto"
	"github.com/xxff-dot/caochuan/relay"
)

// startSocks5 在本地起 SOCKS5（CONNECT only，无鉴权），
// 收到的连接经隧道由 server 侧拨目标——内网设备借此使用服务器的网络出口。
// 监听生命周期跟随当前会话：会话断开监听即关闭，重连后重开。
func (m *reverseMgr) startSocks5(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("SOCKS5 监听失败", "addr", addr, "err", err)
		return
	}
	slog.Info("SOCKS5 出口代理已启动", "addr", addr)
	go func() {
		<-m.gone
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // 会话断开
		}
		go m.handleSocks(conn)
	}
}

// socksReply 按协议回 SOCKS5 应答。
func socksReply(w io.Writer, rep byte) {
	// VER REP RSV ATYP(=IPv4) BND.ADDR BND.PORT
	_, _ = w.Write([]byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0})
}

func (m *reverseMgr) handleSocks(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second)) // 握手限时

	// 1. 方法协商（仅支持无鉴权）
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	hasNone := false
	for _, m := range methods {
		if m == 0 {
			hasNone = true
			break
		}
	}
	if !hasNone {
		_, _ = conn.Write([]byte{5, 0xFF})
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}

	// 2. 请求：VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil || req[0] != 5 {
		return
	}
	if req[1] != 1 { // 仅支持 CONNECT
		socksReply(conn, 0x07)
		return
	}
	var host string
	switch req[3] {
	case 1: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3: // 域名
		n := make([]byte, 1)
		if _, err := io.ReadFull(conn, n); err != nil {
			return
		}
		d := make([]byte, int(n[0]))
		if _, err := io.ReadFull(conn, d); err != nil {
			return
		}
		host = string(d)
	case 4: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		socksReply(conn, 0x01)
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port))))

	// 3. 经隧道开流，server 侧拨目标
	_ = conn.SetDeadline(time.Time{})
	stream, err := m.openSocks(target)
	if err != nil {
		slog.Warn("SOCKS5 回源失败", "target", target, "err", err)
		socksReply(conn, 0x05)
		return
	}
	defer stream.Close()

	socksReply(conn, 0x00)
	relay.Pipe(conn, stream, nil, nil, nil, 0)
}

// openSocks 开一条 server 侧回源流，统计归集到 socks5 虚拟规则。
func (m *reverseMgr) openSocks(target string) (net.Conn, error) {
	m.mu.Lock()
	sess := m.session
	m.mu.Unlock()
	if sess == nil {
		return nil, fmt.Errorf("未连接服务器")
	}
	stream, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	if err := proto.WriteJSONFrame(stream, proto.StreamHeader{ID: "socks5", Target: target}); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return stream, nil
}
