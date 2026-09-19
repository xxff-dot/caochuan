package server

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xxff-dot/caochuan/config"
	"github.com/xxff-dot/caochuan/proto"
	"github.com/xxff-dot/caochuan/relay"
)

const udpIdle = 90 * time.Second // UDP 会话空闲超时

// udpIP 取 UDP 源地址的 netip.Addr。
func udpIP(a *net.UDPAddr) netip.Addr {
	ip, _ := netip.AddrFromSlice(a.IP)
	return ip.Unmap()
}

// ---- TCP ----

// visitorAllowed 规则监听侧的访客判定：黑名单优先，其次规则白名单。
func (s *Server) visitorAllowed(ruleName string, remote net.Addr, acl *config.ACL, bl *config.ACL) bool {
	var ip netip.Addr
	if ap, err := netip.ParseAddrPort(remote.String()); err == nil {
		ip = ap.Addr()
	} else if a, aerr := netip.ParseAddr(remote.String()); aerr == nil {
		ip = a.Unmap()
	} else {
		return false
	}
	if bl != nil && bl.Allows(ip) && !ip.IsLoopback() { // 回环豁免黑名单，防自锁
		slog.Warn("规则拒绝黑名单来源", "rule", ruleName, "ip", ip)
		return false
	}
	if !acl.Allows(ip) {
		slog.Warn("规则白名单拒绝连接", "rule", ruleName, "ip", ip)
		return false
	}
	return true
}

func (s *Server) acceptTCP(rule config.Rule, ln net.Listener) {
	acl, err := config.NewACL(rule.AllowFrom)
	if err != nil {
		slog.Error("规则白名单无效，按不限制处理", "rule", rule.Name, "err", err)
	}
	s.mu.Lock()
	bl, berr := config.NewACL(s.cfg.IPBlacklist)
	blVer := s.blVer.Load()
	s.mu.Unlock()
	if berr != nil {
		slog.Error("隧道黑名单配置无效，按无黑名单处理", "err", berr)
		bl = nil
	}
	lim := relay.NewLimiter(rule.MaxMbps)
	var rr atomic.Uint64 // 多目标轮询计数
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // 监听已关闭
		}
		if cur := s.blVer.Load(); cur != blVer { // 黑名单被修改，重编译
			s.mu.Lock()
			bl, berr = config.NewACL(s.cfg.IPBlacklist)
			s.mu.Unlock()
			if berr != nil {
				bl = nil
			}
			blVer = cur
		}
		if !s.visitorAllowed(rule.Name, conn.RemoteAddr(), acl, bl) {
			_ = conn.Close()
			continue
		}
		go s.handleTCP(rule, conn, acl, lim, &rr)
	}
}

// dialBalanced 轮询拨号多目标，失败自动尝试下一个。
func dialBalanced(target string, rr *atomic.Uint64, timeout time.Duration) (net.Conn, error) {
	targets := relay.ParseTargets(target)
	if len(targets) == 0 {
		return nil, fmt.Errorf("目标地址为空")
	}
	start := int(rr.Add(1) - 1)
	var lastErr error
	for i := 0; i < len(targets); i++ {
		t := targets[(start+i)%len(targets)]
		c, err := net.DialTimeout("tcp", t, timeout)
		if err == nil {
			return c, nil
		}
		lastErr = err
		slog.Warn("目标拨号失败，尝试下一个", "target", t, "err", err)
	}
	return nil, lastErr
}

// proxyHeaderFor 从访客连接构造 PROXY protocol 头。
func proxyHeaderFor(version int, visitor net.Conn) []byte {
	src, ok1 := visitor.RemoteAddr().(*net.TCPAddr)
	dst, ok2 := visitor.LocalAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return nil
	}
	b, err := relay.ProxyHeader(version, src, dst)
	if err != nil {
		return nil
	}
	return b
}

func (s *Server) handleTCP(rule config.Rule, visitor net.Conn, acl *config.ACL, lim *relay.Limiter, rr *atomic.Uint64) {
	st := s.statFor(rule.ID)
	st.Conns.Add(1)
	if rule.MaxConns > 0 && st.Conns.Load() > int64(rule.MaxConns) {
		st.Conns.Add(-1)
		slog.Warn("超过连接数上限，拒绝连接", "rule", rule.Name, "max", rule.MaxConns)
		_ = visitor.Close()
		return
	}
	st.ConnsTotal.Add(1)
	defer st.Conns.Add(-1)

	var backend net.Conn
	if rule.Client == "" { // 正向转发：server 直接拨目标（多目标轮询+故障转移）
		c, err := dialBalanced(rule.Target, rr, 5*time.Second)
		if err != nil {
			slog.Warn("正向转发拨号失败", "rule", rule.Name, "target", rule.Target, "err", err)
			_ = visitor.Close()
			return
		}
		backend = c
		if rule.ProxyProto > 0 { // 向目标写 PROXY 头传递真实访客 IP
			if hdr := proxyHeaderFor(rule.ProxyProto, visitor); hdr != nil {
				if _, err := backend.Write(hdr); err != nil {
					_ = backend.Close()
					_ = visitor.Close()
					return
				}
			}
		}
	} else { // 穿透：让 client 拨它内网的目标（流头携带访客地址与代理协议版本）
		hdr := proto.StreamHeader{ID: rule.ID, Target: rule.Target}
		if rule.ProxyProto > 0 {
			hdr.ProxyProto = rule.ProxyProto
			hdr.Visitor = visitor.RemoteAddr().String()
			hdr.DstAddr = visitor.LocalAddr().String()
		}
		stream, err := s.openStreamTo(rule.Client, hdr)
		if err != nil {
			slog.Warn("穿透拨号失败", "rule", rule.Name, "client", rule.Client, "err", err)
			_ = visitor.Close()
			return
		}
		backend = stream
	}
	defer backend.Close()
	defer visitor.Close()

	relay.Pipe(visitor, backend, &st.BytesIn, &st.BytesOut, lim, time.Duration(rule.IdleMin)*time.Minute)
}

// ---- UDP：本地正向转发（visitor socket ⇄ target socket 的 NAT 式中继）----

func (s *Server) udpLocalRelay(rule config.Rule, up *net.UDPConn, done <-chan struct{}) {
	st := s.statFor(rule.ID)
	acl, err := config.NewACL(rule.AllowFrom)
	if err != nil {
		slog.Error("规则白名单无效，按不限制处理", "rule", rule.Name, "err", err)
	}
	s.mu.Lock()
	bl, berr := config.NewACL(s.cfg.IPBlacklist)
	blVer := s.blVer.Load()
	s.mu.Unlock()
	if berr != nil {
		slog.Error("隧道黑名单配置无效，按无黑名单处理", "err", berr)
		bl = nil
	}
	var mu sync.Mutex
	lim := relay.NewLimiter(rule.MaxMbps)
	var rr atomic.Uint64
	backends := map[string]*net.UDPConn{} // visitor 地址 → 后端 socket

	getBackend := func(visitor *net.UDPAddr) *net.UDPConn {
		mu.Lock()
		defer mu.Unlock()
		if b, ok := backends[visitor.String()]; ok {
			return b
		}
		// 每个新访客会话轮询拨一个目标（重新解析，多目标故障转移 + DNS 跟随）
		b, err := relay.DialUDPBalanced(rule.Target, &rr)
		if err != nil {
			return nil
		}
		backends[visitor.String()] = b
		st.Conns.Add(1)
		go func(visitor *net.UDPAddr, b *net.UDPConn) { // 后端 → visitor
			buf := make([]byte, 65535)
			for {
				_ = b.SetReadDeadline(time.Now().Add(udpIdle))
				n, err := b.Read(buf)
				if err != nil {
					break // 超时或关闭
				}
				if _, err := up.WriteToUDP(buf[:n], visitor); err != nil {
					break
				}
				st.BytesOut.Add(int64(n))
			}
			mu.Lock()
			delete(backends, visitor.String())
			mu.Unlock()
			_ = b.Close()
			st.Conns.Add(-1)
		}(visitor, b)
		return b
	}

	go func() { // 上游关闭时清掉全部后端
		<-done
		mu.Lock()
		defer mu.Unlock()
		for _, b := range backends {
			_ = b.Close()
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, src, err := up.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if cur := s.blVer.Load(); cur != blVer { // 黑名单被修改，重编译
			s.mu.Lock()
			bl, berr = config.NewACL(s.cfg.IPBlacklist)
			s.mu.Unlock()
			if berr != nil {
				bl = nil
			}
			blVer = cur
		}
		if !acl.Allows(udpIP(src)) || (bl != nil && bl.Allows(udpIP(src))) {
			continue
		}
		mu.Lock()
		full := rule.MaxConns > 0 && len(backends) >= rule.MaxConns &&
			backends[src.String()] == nil
		mu.Unlock()
		if full {
			continue // 超过会话上限，丢弃新访客的包
		}
		lim.Wait(n)
		if b := getBackend(src); b != nil {
			if _, err := b.Write(buf[:n]); err == nil {
				st.BytesIn.Add(int64(n))
			}
		}
	}
}

// ---- UDP：穿透中继（visitor ⇄ 隧道里的 UDP 帧流）----

type visitorEntry struct {
	id       uint32
	addr     *net.UDPAddr
	lastSeen time.Time
}

func (s *Server) udpTunnelRelay(rule config.Rule, up *net.UDPConn, done <-chan struct{}) {
	st := s.statFor(rule.ID)
	acl, err := config.NewACL(rule.AllowFrom)
	if err != nil {
		slog.Error("规则白名单无效，按不限制处理", "rule", rule.Name, "err", err)
	}
	s.mu.Lock()
	bl, berr := config.NewACL(s.cfg.IPBlacklist)
	blVer := s.blVer.Load()
	s.mu.Unlock()
	if berr != nil {
		slog.Error("隧道黑名单配置无效，按无黑名单处理", "err", berr)
		bl = nil
	}
	var mu sync.Mutex
	lim := relay.NewLimiter(rule.MaxMbps)
	var stream net.Conn // 当前隧道流；断线后由下一个包触发重开
	visitors := map[string]*visitorEntry{}
	nextID := uint32(0)

	ensure := func() net.Conn {
		mu.Lock()
		defer mu.Unlock()
		if stream != nil {
			return stream
		}
		sc, err := s.openStreamTo(rule.Client, proto.StreamHeader{ID: rule.ID, Target: rule.Target, UDP: true})
		if err != nil {
			return nil // client 不在线，丢包等重连
		}
		stream = sc
		go func() { // 隧道 → visitor
			br := bufio.NewReader(sc)
			for {
				pkt, err := proto.ReadUDPPacket(br)
				if err != nil {
					mu.Lock()
					if stream == sc {
						stream = nil
					}
					mu.Unlock()
					_ = sc.Close()
					return
				}
				mu.Lock()
				var addr *net.UDPAddr
				for _, v := range visitors {
					if v.id == pkt.ConnID {
						addr = v.addr
						break
					}
				}
				mu.Unlock()
				if addr != nil {
					if _, err := up.WriteToUDP(pkt.Payload, addr); err == nil {
						st.BytesOut.Add(int64(len(pkt.Payload)))
					}
				}
			}
		}()
		return stream
	}

	go func() {
		<-done
		mu.Lock()
		defer mu.Unlock()
		if stream != nil {
			_ = stream.Close()
			stream = nil
		}
	}()

	// 空闲访客过期：每 64 包懒清扫一次，回收表项与 Conns 计数
	packets := 0
	buf := make([]byte, 65535)
	for {
		n, src, err := up.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if cur := s.blVer.Load(); cur != blVer { // 黑名单被修改，重编译
			s.mu.Lock()
			bl, berr = config.NewACL(s.cfg.IPBlacklist)
			s.mu.Unlock()
			if berr != nil {
				bl = nil
			}
			blVer = cur
		}
		mu.Lock()
		if !acl.Allows(udpIP(src)) || (bl != nil && bl.Allows(udpIP(src))) {
			mu.Unlock()
			continue
		}
		key := src.String()
		v := visitors[key]
		if v == nil && rule.MaxConns > 0 && len(visitors) >= rule.MaxConns {
			mu.Unlock()
			continue // 超过会话上限，丢弃新访客的包
		}
		if v == nil {
			nextID++
			v = &visitorEntry{id: nextID, addr: src}
			visitors[key] = v
			st.Conns.Add(1)
		}
		v.lastSeen = time.Now()
		packets++
		if packets%64 == 0 { // 懒清扫
			now := time.Now()
			for k, e := range visitors {
				if now.Sub(e.lastSeen) > udpIdle {
					delete(visitors, k)
					st.Conns.Add(-1)
				}
			}
		}
		sc := stream
		mu.Unlock()

		if sc = ensure(); sc == nil {
			continue
		}
		lim.Wait(n)
		if err := proto.WriteUDPPacket(sc, &proto.UDPPacket{ConnID: v.id, Payload: buf[:n]}); err == nil {
			st.BytesIn.Add(int64(n))
		}
	}
}
