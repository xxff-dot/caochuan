// Package server 是公网侧：隧道端点 + 规则监听 + 转发 + 面板数据源。
package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"

	"github.com/xxff-dot/caochuan/config"
	"github.com/xxff-dot/caochuan/logbuf"
	"github.com/xxff-dot/caochuan/proto"
)

// Stat 单规则实时统计（面板轮询读取）。
type Stat struct {
	BytesIn    atomic.Int64 // visitor → target
	BytesOut   atomic.Int64 // target → visitor
	Conns      atomic.Int64 // 当前并发连接/UDP 会话
	ConnsTotal atomic.Int64
}

type clientConn struct {
	Name    string
	Addr    string
	Session *smux.Session
	Since   time.Time

	cs     net.Conn      // 控制流：下发规则 / 接收状态
	csmu   sync.Mutex    // 控制流写互斥
	status map[string]*proto.ReverseStatus // 反向规则最近一次监听状态（ruleID→status）
}

// runner 一条在跑的规则监听。sig 记录启动时的规则签名，diff 用。
type runner struct {
	proto  string
	listen int
	target string
	client string
	stop   func() // 关闭监听使其 goroutine 退出
}

// sameAs 判断 runner 是否与目标规则一致（不一致则需重启监听）。
func (rn *runner) sameAs(r *config.Rule) bool {
	return rn.proto == r.Proto && rn.listen == r.Listen && rn.target == r.Target && rn.client == r.Client
}

type Server struct {
	CfgPath string
	Log     *logbuf.Ring

	smuxCfg *smux.Config
	certs   *CertManager

	mu       sync.Mutex
	cfg      *config.Server
	clients  map[string]*clientConn // name → 在线 client
	runners  map[string]*runner     // ruleID → 监听
	stats    map[string]*Stat       // ruleID → 统计
	hist     map[string]*history    // ruleID → 流量历史采样
	health   map[string]*healthStatus // ruleID → 目标健康状态
	notifier *notifier
	authFails map[string]*authFail // 隧道来源 IP → token 爆破记录
	started  time.Time
	stopping bool
}

// authFail 隧道 token 爆破记录（同面板登录防爆破逻辑）。
type authFail struct {
	count    int
	lastFail time.Time
	until    time.Time
}

const authMaxFails = 10
const authBlockFor = 10 * time.Minute

// sweepAuthFails 清过期记录。调用方须持有 s.mu。
func (s *Server) sweepAuthFails(now time.Time) {
	for ip, f := range s.authFails {
		if now.After(f.until) && now.Sub(f.lastFail) > authBlockFor {
			delete(s.authFails, ip)
		}
	}
}

func New(cfg *config.Server, cfgPath string, ring *logbuf.Ring) (*Server, error) {
	sc := smux.DefaultConfig()
	sc.KeepAliveInterval = 10 * time.Second
	sc.KeepAliveTimeout = 30 * time.Second
	s := &Server{
		CfgPath:   cfgPath,
		Log:       ring,
		smuxCfg:   sc,
		cfg:       cfg,
		clients:   map[string]*clientConn{},
		runners:   map[string]*runner{},
		stats:     map[string]*Stat{},
		hist:      map[string]*history{},
		health:    map[string]*healthStatus{},
		notifier:  newNotifier(cfg.NotifyURL, cfg.NotifyFormat),
		authFails: map[string]*authFail{},
		started:   time.Now(),
	}
	if !cfg.NoTLS {
		cm, err := LoadOrGenerate(cfgPath, cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, err
		}
		s.certs = cm
	}
	return s, nil
}

// TlsFingerprint 当前隧道证书指纹（未启用 TLS 为空）。
func (s *Server) TlsFingerprint() string {
	if s.certs == nil {
		return ""
	}
	return s.certs.Fingerprint()
}

// Run 启动隧道监听与全部规则，阻塞直到 ctx 取消。
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.TunnelAddr)
	if err != nil {
		return fmt.Errorf("隧道端口监听失败: %w", err)
	}
	if s.certs != nil {
		ln = tls.NewListener(ln, s.certs.TLSConfig())
		slog.Info("隧道端点已启动", "addr", s.cfg.TunnelAddr, "加密", "TLS",
			"证书指纹", s.certs.Fingerprint())
		s.Log.Write([]byte(fmt.Sprintf("隧道 TLS 已启用, 证书指纹: %s\n", s.certs.Fingerprint())))
	} else {
		slog.Info("隧道端点已启动", "addr", s.cfg.TunnelAddr, "加密", "无（明文）")
	}

	s.mu.Lock()
	s.applyRulesLocked()
	s.mu.Unlock()

	go func() { // 流量历史采样
		t := time.NewTicker(histInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.sampleHistory()
			}
		}
	}()

	go s.probeLoop(ctx) // 规则目标健康检查

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if s.isStopping() {
					return
				}
				slog.Warn("隧道 accept 错误", "err", err)
				time.Sleep(time.Second)
				continue
			}
			go s.handleTunnel(conn)
		}
	}()

	<-ctx.Done()
	s.mu.Lock()
	s.stopping = true
	runners := s.runners
	ccs := s.clients
	s.mu.Unlock()
	for _, r := range runners {
		r.stop()
	}
	for _, cc := range ccs {
		cc.Session.Close()
	}
	return ln.Close()
}

func (s *Server) isStopping() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopping
}

// handleTunnel 完成一次 client 接入：鉴权帧 → smux 会话。
func (s *Server) handleTunnel(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	host, _, _ := net.SplitHostPort(remote)

	// token 防爆破：锁定期内直接断开
	s.mu.Lock()
	s.sweepAuthFails(time.Now())
	if f := s.authFails[host]; f != nil && time.Now().Before(f.until) {
		s.mu.Unlock()
		slog.Warn("隧道来源被锁定，拒绝连接", "ip", host)
		return
	}
	s.mu.Unlock()

	var req proto.AuthRequest
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := proto.ReadJSONFrame(conn, &req); err != nil {
		slog.Warn("隧道鉴权读取失败", "remote", remote, "err", err)
		return
	}
	name, ok := s.authToken(req.Token)
	if !ok {
		s.recordAuthFail(host)
		slog.Warn("隧道鉴权失败（token 无效）", "remote", remote)
		_ = proto.WriteJSONFrame(conn, proto.AuthReply{OK: false, Message: "invalid token"})
		return
	}
	s.mu.Lock()
	delete(s.authFails, host)
	s.mu.Unlock()
	if err := proto.WriteJSONFrame(conn, proto.AuthReply{OK: true}); err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	sess, err := smux.Server(conn, s.smuxCfg)
	if err != nil {
		slog.Warn("smux 建立失败", "client", name, "err", err)
		return
	}

	cc := &clientConn{Name: name, Addr: conn.RemoteAddr().String(), Session: sess, Since: time.Now(),
		status: map[string]*proto.ReverseStatus{}}
	s.mu.Lock()
	if old := s.clients[name]; old != nil {
		slog.Info("client 重连，断开旧会话", "client", name, "old", old.Addr)
		old.Session.Close()
	}
	s.clients[name] = cc
	s.mu.Unlock()
	slog.Info("client 上线", "client", name, "addr", cc.Addr, "host", req.Host)
	s.Log.Write([]byte(fmt.Sprintf("client 上线: %s (%s, 主机名 %s)\n", name, cc.Addr, req.Host)))
	s.notifier.send("client_up|"+name, "client_up", fmt.Sprintf("客户端 %s 上线（%s）", name, cc.Addr))

	go s.acceptReverse(cc) // 客户端反向规则的回源流
	go s.setupControl(cc)  // 控制流：推送反向规则

	// smux v1 没有 Wait()：轮询会话关闭（1s 粒度足够面板展示）
	for !sess.IsClosed() {
		time.Sleep(time.Second)
	}
	s.mu.Lock()
	// 只清理自己这个会话，避免误删重连后的新会话
	if cur := s.clients[name]; cur == cc {
		delete(s.clients, name)
	}
	s.mu.Unlock()
	slog.Info("client 下线", "client", name)
	s.Log.Write([]byte(fmt.Sprintf("client 下线: %s\n", name)))
	s.notifier.send("client_down|"+name, "client_down", fmt.Sprintf("客户端 %s 下线", name))
}

func (s *Server) authToken(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.cfg.Clients {
		if subtle.ConstantTimeCompare([]byte(c.Token), []byte(token)) == 1 {
			return c.Name, true
		}
	}
	return "", false
}

// recordAuthFail 记录一次隧道鉴权失败，达到阈值锁定该来源 IP。
func (s *Server) recordAuthFail(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.authFails[host] == nil {
		s.authFails[host] = &authFail{}
	}
	f := s.authFails[host]
	f.count++
	f.lastFail = time.Now()
	if f.count >= authMaxFails {
		f.until = time.Now().Add(authBlockFor)
		f.count = 0
		slog.Warn("隧道来源因多次鉴权失败被锁定", "ip", host, "minutes", int(authBlockFor.Minutes()))
		s.notifier.send("auth_block|"+host, "auth_block",
			fmt.Sprintf("隧道来源 %s 多次 token 鉴权失败，已锁定 %d 分钟", host, int(authBlockFor.Minutes())))
	}
}

// applyRulesLocked 按当前配置 diff 启停 server 侧规则监听（Side=server）。
// Side=client 的反向规则不在这里监听——它们由控制流下发给客户端。
// 传入 goroutine 的是规则值拷贝，避免与配置更新产生数据竞争。调用方须持有 s.mu。
func (s *Server) applyRulesLocked() {
	desired := map[string]config.Rule{}
	for i := range s.cfg.Rules {
		r := s.cfg.Rules[i]
		if r.Enabled && r.SideOf() == "server" {
			desired[r.ID] = r
		}
	}
	for id, r := range desired {
		if cur, ok := s.runners[id]; ok && cur.sameAs(&r) {
			continue // 未变化，继续用
		}
		if cur, ok := s.runners[id]; ok {
			cur.stop()
			delete(s.runners, id)
		}
		if rn, err := s.startRule(r); err != nil {
			slog.Error("规则启动失败", "rule", r.Name, "err", err)
			s.Log.Write([]byte(fmt.Sprintf("规则启动失败: %s: %v\n", r.Name, err)))
			s.notifier.send("rule_error|"+id, "rule_error", fmt.Sprintf("规则 %s 启动失败: %v", r.Name, err))
		} else {
			s.runners[id] = rn
			slog.Info("规则已启动", "rule", r.Name, "proto", r.Proto, "listen", r.Listen, "client", r.Client, "target", r.Target)
		}
	}
	for id, cur := range s.runners {
		if _, ok := desired[id]; !ok {
			cur.stop()
			delete(s.runners, id)
		}
	}
}

// startRule 启动一条 server 侧监听。接收规则值拷贝，goroutine 不共享配置内存。
func (s *Server) startRule(r config.Rule) (*runner, error) {
	if r.Proto == "tcp" {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", r.Listen))
		if err != nil {
			return nil, err
		}
		go s.acceptTCP(r, ln)
		return &runner{proto: r.Proto, listen: r.Listen, target: r.Target, client: r.Client,
			stop: func() { _ = ln.Close() }}, nil
	}
	if r.Proto == "udp" {
		addr := &net.UDPAddr{Port: r.Listen}
		up, err := net.ListenUDP("udp", addr)
		if err != nil {
			return nil, err
		}
		done := make(chan struct{})
		if r.Client == "" {
			go s.udpLocalRelay(r, up, done)
		} else {
			go s.udpTunnelRelay(r, up, done)
		}
		return &runner{proto: r.Proto, listen: r.Listen, target: r.Target, client: r.Client,
			stop: func() { close(done); _ = up.Close() }}, nil
	}
	return nil, fmt.Errorf("未知协议 %q", r.Proto)
}

func (s *Server) statFor(id string) *Stat {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats[id]
	if st == nil {
		st = &Stat{}
		s.stats[id] = st
	}
	return st
}

// openStreamTo 经隧道向 client 请求一条到 target 的数据流。
func (s *Server) openStreamTo(clientName string, hdr proto.StreamHeader) (net.Conn, error) {
	s.mu.Lock()
	cc := s.clients[clientName]
	s.mu.Unlock()
	if cc == nil {
		return nil, fmt.Errorf("client %q 不在线", clientName)
	}
	stream, err := cc.Session.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("打开数据流失败: %w", err)
	}
	if err := proto.WriteJSONFrame(stream, hdr); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("写入流头失败: %w", err)
	}
	return stream, nil
}

