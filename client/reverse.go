package client

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"

	"github.com/xxff-dot/caochuan/config"
	"github.com/xxff-dot/caochuan/proto"
	"github.com/xxff-dot/caochuan/relay"
)

// udpIP 取 UDP 源地址的 netip.Addr。
func udpIP(a *net.UDPAddr) netip.Addr {
	ip, _ := netip.AddrFromSlice(a.IP)
	return ip.Unmap()
}

// visitorEntry 反向 UDP 的访客表项（地址 ↔ connID）。
type visitorEntry struct {
	id       uint32
	addr     *net.UDPAddr
	lastSeen time.Time
}

// reverseMgr 管理 client 侧的反向监听器（Side=client 规则）。
// 规则经控制流全量下发，这里做 diff 启停；监听结果经控制流回传 server。
type reverseMgr struct {
	mu       sync.Mutex
	wmu      sync.Mutex // 控制流写互斥：多个 start goroutine 并发 report 时帧不交错
	session  *smux.Session
	control  net.Conn // 控制流（回传状态用）
	tcpLns   map[string]net.Listener
	udpConns map[string]*net.UDPConn
	rules    map[string]proto.ReverseRule
}

func newReverseMgr() *reverseMgr {
	return &reverseMgr{
		tcpLns:   map[string]net.Listener{},
		udpConns: map[string]*net.UDPConn{},
		rules:    map[string]proto.ReverseRule{},
	}
}

// handleControl 在 server 开来的控制流上循环收规则并回传状态。阻塞到流断开。
func (m *reverseMgr) handleControl(stream net.Conn) {
	m.mu.Lock()
	m.control = stream
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.control = nil
		m.mu.Unlock()
		m.stopAll()
	}()

	br := bufio.NewReader(stream)
	for {
		var push proto.RulePush
		if err := proto.ReadJSONFrame(br, &push); err != nil {
			return // 会话断开，stopAll 已清理
		}
		m.apply(push.Rules)
	}
}

func (m *reverseMgr) report(st proto.ReverseStatus) {
	m.mu.Lock()
	cs := m.control
	m.mu.Unlock()
	if cs == nil {
		return
	}
	m.wmu.Lock()
	defer m.wmu.Unlock()
	_ = proto.WriteJSONFrame(cs, st)
}

// apply 按下发的规则集 diff 本地监听器。
func (m *reverseMgr) apply(rules []proto.ReverseRule) {
	desired := map[string]proto.ReverseRule{}
	for _, r := range rules {
		desired[r.ID] = r
	}

	m.mu.Lock()
	for id, cur := range m.rules {
		if want, ok := desired[id]; !ok || want.Proto != cur.Proto || want.Listen != cur.Listen || want.Target != cur.Target {
			m.stopLocked(id)
		}
	}
	var toStart []proto.ReverseRule
	for id, want := range desired {
		if _, ok := m.rules[id]; !ok {
			m.rules[id] = want
			toStart = append(toStart, want)
		}
	}
	m.mu.Unlock()

	for _, r := range toStart {
		go m.start(r)
	}
}

func (m *reverseMgr) stopLocked(id string) {
	if ln, ok := m.tcpLns[id]; ok {
		_ = ln.Close()
		delete(m.tcpLns, id)
	}
	if uc, ok := m.udpConns[id]; ok {
		_ = uc.Close()
		delete(m.udpConns, id)
	}
	delete(m.rules, id)
}

func (m *reverseMgr) stopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id := range m.rules {
		m.stopLocked(id)
	}
}

func (m *reverseMgr) start(r proto.ReverseRule) {
	acl, err := config.NewACL(r.AllowFrom)
	if err != nil {
		slog.Error("反向规则白名单无效，按不限制处理", "rule", r.Name, "err", err)
	}
	switch r.Proto {
	case "tcp":
		lim := relay.NewLimiter(r.MaxMbps)
		var cnt atomic.Int64 // 本规则当前连接数
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", r.Listen))
		if err != nil {
			m.report(proto.ReverseStatus{ID: r.ID, OK: false, Err: err.Error()})
			m.mu.Lock()
			delete(m.rules, r.ID)
			m.mu.Unlock()
			return
		}
		m.mu.Lock()
		m.tcpLns[r.ID] = ln
		m.mu.Unlock()
		m.report(proto.ReverseStatus{ID: r.ID, OK: true})
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // 关闭/会话断开
			}
			go m.handleTCP(r, conn, acl, lim, &cnt)
		}
	case "udp":
		up, err := net.ListenUDP("udp", &net.UDPAddr{Port: r.Listen})
		if err != nil {
			m.report(proto.ReverseStatus{ID: r.ID, OK: false, Err: err.Error()})
			m.mu.Lock()
			delete(m.rules, r.ID)
			m.mu.Unlock()
			return
		}
		m.mu.Lock()
		m.udpConns[r.ID] = up
		m.mu.Unlock()
		m.report(proto.ReverseStatus{ID: r.ID, OK: true})
		m.udpRelay(r, up, acl, relay.NewLimiter(r.MaxMbps))
	}
}

// openReverse 开一条到 server 的回源流。
func (m *reverseMgr) openReverse(r proto.ReverseRule, udp bool) (net.Conn, error) {
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
	hdr := proto.StreamHeader{ID: r.ID, Target: r.Target, UDP: udp}
	if err := proto.WriteJSONFrame(stream, hdr); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return stream, nil
}

func (m *reverseMgr) handleTCP(r proto.ReverseRule, visitor net.Conn, acl *config.ACL, lim *relay.Limiter, cnt *atomic.Int64) {
	if ap, err := netip.ParseAddrPort(visitor.RemoteAddr().String()); err == nil && !acl.Allows(ap.Addr()) {
		slog.Warn("反向规则白名单拒绝连接", "rule", r.Name, "ip", ap.Addr())
		_ = visitor.Close()
		return
	}
	cnt.Add(1)
	if r.MaxConns > 0 && cnt.Load() > int64(r.MaxConns) {
		cnt.Add(-1)
		slog.Warn("反向规则超过连接数上限，拒绝连接", "rule", r.Name, "max", r.MaxConns)
		_ = visitor.Close()
		return
	}
	defer cnt.Add(-1)
	defer visitor.Close()
	stream, err := m.openReverse(r, false)
	if err != nil {
		slog.Warn("反向回源开流失败", "rule", r.Name, "err", err)
		return
	}
	defer stream.Close()

	relay.Pipe(visitor, stream, nil, nil, lim)
}

// udpRelay 本地 visitor ⇄ 隧道 UDP 帧流（镜像 server.udpTunnelRelay，方向相反）。
func (m *reverseMgr) udpRelay(r proto.ReverseRule, up *net.UDPConn, acl *config.ACL, lim *relay.Limiter) {
	stream, err := m.openReverse(r, true)
	if err != nil {
		slog.Warn("反向 UDP 开流失败", "rule", r.Name, "err", err)
		return
	}

	var mu sync.Mutex
	var wmu sync.Mutex
	visitors := map[string]*visitorEntry{}
	nextID := uint32(0)

	// 隧道回包 → visitor
	go func() {
		br := bufio.NewReader(stream)
		for {
			pkt, err := proto.ReadUDPPacket(br)
			if err != nil {
				_ = up.Close()
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
				_, _ = up.WriteToUDP(pkt.Payload, addr)
			}
		}
	}()

	// 空闲访客过期：每 64 包懒清扫
	packets := 0
	buf := make([]byte, 65535)
	for {
		n, src, err := up.ReadFromUDP(buf)
		if err != nil {
			_ = stream.Close()
			return
		}
		mu.Lock()
		if !acl.Allows(udpIP(src)) {
			mu.Unlock()
			continue
		}
		key := src.String()
		v := visitors[key]
		if v == nil && r.MaxConns > 0 && len(visitors) >= r.MaxConns {
			mu.Unlock()
			continue // 超过会话上限，丢弃新访客的包
		}
		if v == nil {
			nextID++
			v = &visitorEntry{id: nextID, addr: src}
			visitors[key] = v
		}
		v.lastSeen = time.Now()
		packets++
		if packets%64 == 0 {
			now := time.Now()
			for k, e := range visitors {
				if now.Sub(e.lastSeen) > udpIdleTimeout {
					delete(visitors, k)
				}
			}
		}
		mu.Unlock()

		lim.Wait(n)
		wmu.Lock()
		err = proto.WriteUDPPacket(stream, &proto.UDPPacket{ConnID: v.id, Payload: buf[:n]})
		wmu.Unlock()
		if err != nil {
			_ = stream.Close()
			_ = up.Close()
			return
		}
	}
}
