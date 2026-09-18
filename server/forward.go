package server

import (
	"bufio"
	"log/slog"
	"net"
	"net/netip"
	"sync"
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

func (s *Server) acceptTCP(rule config.Rule, ln net.Listener) {
	acl, err := config.NewACL(rule.AllowFrom)
	if err != nil {
		slog.Error("规则白名单无效，按不限制处理", "rule", rule.Name, "err", err)
	}
	lim := relay.NewLimiter(rule.MaxMbps)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // 监听已关闭
		}
		go s.handleTCP(rule, conn, acl, lim)
	}
}

func (s *Server) handleTCP(rule config.Rule, visitor net.Conn, acl *config.ACL, lim *relay.Limiter) {
	if ap, err := netip.ParseAddrPort(visitor.RemoteAddr().String()); err == nil && !acl.Allows(ap.Addr()) {
		slog.Warn("规则白名单拒绝连接", "rule", rule.Name, "ip", ap.Addr())
		_ = visitor.Close()
		return
	}
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
	if rule.Client == "" { // 正向转发：server 直接拨目标
		c, err := net.DialTimeout("tcp", rule.Target, 5*time.Second)
		if err != nil {
			slog.Warn("正向转发拨号失败", "rule", rule.Name, "target", rule.Target, "err", err)
			_ = visitor.Close()
			return
		}
		backend = c
	} else { // 穿透：让 client 拨它内网的目标
		stream, err := s.openStreamTo(rule.Client, proto.StreamHeader{ID: rule.ID, Target: rule.Target})
		if err != nil {
			slog.Warn("穿透拨号失败", "rule", rule.Name, "client", rule.Client, "err", err)
			_ = visitor.Close()
			return
		}
		backend = stream
	}
	defer backend.Close()
	defer visitor.Close()

	relay.Pipe(visitor, backend, &st.BytesIn, &st.BytesOut, lim)
}

// ---- UDP：本地正向转发（visitor socket ⇄ target socket 的 NAT 式中继）----

func (s *Server) udpLocalRelay(rule config.Rule, up *net.UDPConn, done <-chan struct{}) {
	st := s.statFor(rule.ID)
	acl, err := config.NewACL(rule.AllowFrom)
	if err != nil {
		slog.Error("规则白名单无效，按不限制处理", "rule", rule.Name, "err", err)
	}
	tgt, err := net.ResolveUDPAddr("udp", rule.Target)
	if err != nil {
		slog.Error("UDP 目标解析失败", "rule", rule.Name, "err", err)
		return
	}
	// 目标为域名时每 60s 重新解析，跟随 DNS 变化
	var tgtMu sync.Mutex
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if na, err := net.ResolveUDPAddr("udp", rule.Target); err == nil {
					tgtMu.Lock()
					tgt = na
					tgtMu.Unlock()
				}
			}
		}
	}()
	var mu sync.Mutex
	lim := relay.NewLimiter(rule.MaxMbps)
	backends := map[string]*net.UDPConn{} // visitor 地址 → 后端 socket

	getBackend := func(visitor *net.UDPAddr) *net.UDPConn {
		mu.Lock()
		defer mu.Unlock()
		if b, ok := backends[visitor.String()]; ok {
			return b
		}
		tgtMu.Lock()
		cur := tgt
		tgtMu.Unlock()
		b, err := net.DialUDP("udp", nil, cur)
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
		if !acl.Allows(udpIP(src)) {
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
		mu.Lock()
		if !acl.Allows(udpIP(src)) {
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
