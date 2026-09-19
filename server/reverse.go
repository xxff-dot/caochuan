package server

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/xxff-dot/caochuan/proto"
	"github.com/xxff-dot/caochuan/relay"
)

// acceptReverse 接收 client 主动开来的反向数据流（Side=client 规则的回源）。
func (s *Server) acceptReverse(cc *clientConn) {
	for {
		stream, err := cc.Session.AcceptStream()
		if err != nil {
			return // 会话关闭
		}
		go s.handleReverseStream(cc, stream)
	}
}

func (s *Server) handleReverseStream(cc *clientConn, stream net.Conn) {
	defer stream.Close()
	var hdr proto.StreamHeader
	_ = stream.SetReadDeadline(time.Now().Add(30 * time.Second))
	if err := proto.ReadJSONFrame(stream, &hdr); err != nil {
		slog.Warn("反向流头读取失败", "client", cc.Name, "err", err)
		return
	}
	_ = stream.SetDeadline(time.Time{})
	if hdr.ID == proto.ControlID {
		return // 控制流由 setupControl 管理，不该出现在这里
	}

	st := s.statFor(hdr.ID)
	if hdr.UDP {
		s.udpBackendFromStream(st, hdr.Target, stream)
		return
	}

	backend, err := dialBalanced(hdr.Target, &s.rr, 5*time.Second)
	if err != nil {
		slog.Warn("反向回源拨号失败", "client", cc.Name, "target", hdr.Target, "err", err)
		return
	}
	defer backend.Close()
	if hdr.ProxyProto > 0 && hdr.Visitor != "" { // 把真实访客 IP 写进 PROXY 头
		if src, e1 := net.ResolveTCPAddr("tcp", hdr.Visitor); e1 == nil {
			if dst, e2 := net.ResolveTCPAddr("tcp", hdr.DstAddr); e2 == nil {
				if b, perr := relay.ProxyHeader(hdr.ProxyProto, src, dst); perr == nil {
					_, _ = backend.Write(b)
				}
			}
		}
	}
	st.ConnsTotal.Add(1)
	st.Conns.Add(1)
	defer st.Conns.Add(-1)

	relay.Pipe(stream, backend, &st.BytesIn, &st.BytesOut, nil, 0) // 限速在 client 监听侧执行
}

// udpBackendFromStream 处理反向 UDP 流：connID → 服务器侧到 target 的 socket（镜像 client 同名逻辑）。
func (s *Server) udpBackendFromStream(st *Stat, target string, stream net.Conn) {
	if relay.ParseTargets(target) == nil {
		slog.Warn("反向 UDP 目标为空", "target", target)
		return
	}

	var wmu sync.Mutex
	writeBack := func(connID uint32, payload []byte) {
		wmu.Lock()
		defer wmu.Unlock()
		_ = proto.WriteUDPPacket(stream, &proto.UDPPacket{ConnID: connID, Payload: payload})
	}

	var mu sync.Mutex
	backends := map[uint32]*net.UDPConn{}
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, b := range backends {
			_ = b.Close()
		}
	}()

	br := bufio.NewReader(stream)
	for {
		pkt, err := proto.ReadUDPPacket(br)
		if err != nil {
			return
		}
		mu.Lock()
		b := backends[pkt.ConnID]
		if b == nil {
			// 每个新会话轮询拨一个目标（重新解析，多目标故障转移 + DNS 跟随）
			nb, derr := relay.DialUDPBalanced(target, &s.rr)
			if derr != nil {
				mu.Unlock()
				continue
			}
			b = nb
			backends[pkt.ConnID] = b
			st.Conns.Add(1)
			go func(connID uint32, b *net.UDPConn) { // target 回包 → 隧道
				rbuf := make([]byte, 65535)
				for {
					_ = b.SetReadDeadline(time.Now().Add(udpIdle))
					n, err := b.Read(rbuf)
					if err != nil {
						break
					}
					writeBack(connID, rbuf[:n])
					st.BytesOut.Add(int64(n))
				}
				mu.Lock()
				delete(backends, connID)
				mu.Unlock()
				_ = b.Close()
				st.Conns.Add(-1)
			}(pkt.ConnID, b)
		}
		mu.Unlock()
		if b != nil && err == nil {
			if _, err := b.Write(pkt.Payload); err == nil {
				st.BytesIn.Add(int64(len(pkt.Payload)))
			} else {
				mu.Lock()
				delete(backends, pkt.ConnID)
				mu.Unlock()
				_ = b.Close()
			}
		}
	}
}

// setupControl 开控制流：先推一次全量反向规则，再循环接收 client 的状态回传。
func (s *Server) setupControl(cc *clientConn) {
	stream, err := cc.Session.OpenStream()
	if err != nil {
		return
	}
	s.mu.Lock()
	cc.cs = stream
	s.mu.Unlock()
	defer func() { // 流断开时清掉引用，避免 pushRulesTo 拿死流
		s.mu.Lock()
		if cc.cs == stream {
			cc.cs = nil
		}
		s.mu.Unlock()
	}()

	if err := proto.WriteJSONFrame(stream, proto.StreamHeader{ID: proto.ControlID, Target: "control"}); err != nil {
		return
	}
	s.pushRulesTo(cc)

	br := bufio.NewReader(stream)
	for {
		var st proto.ReverseStatus
		if err := proto.ReadJSONFrame(br, &st); err != nil {
			return // 会话断开
		}
		s.mu.Lock()
		cc.status[st.ID] = &st
		s.mu.Unlock()
		if !st.OK {
			slog.Warn("client 反向监听失败", "client", cc.Name, "rule", st.ID, "err", st.Err)
			s.Log.Write([]byte(fmt.Sprintf("client %s 反向监听失败 (规则 %s): %s\n", cc.Name, st.ID, st.Err)))
			s.notifier.send("reverse_error|"+st.ID+"|"+cc.Name, "reverse_error",
				fmt.Sprintf("客户端 %s 反向规则监听失败: %s", cc.Name, st.Err))
		}
	}
}

// pushRulesTo 把属于该 client 且启用的反向规则全量下发。
func (s *Server) pushRulesTo(cc *clientConn) {
	s.mu.Lock()
	var rules []proto.ReverseRule
	for _, r := range s.cfg.Rules {
		if r.SideOf() == "client" && r.Client == cc.Name && r.Enabled {
			rules = append(rules, proto.ReverseRule{ID: r.ID, Name: r.Name, Proto: r.Proto,
				Listen: r.Listen, Target: r.Target, AllowFrom: r.AllowFrom,
				MaxMbps: r.MaxMbps, MaxConns: r.MaxConns, IdleMin: r.IdleMin, ProxyProto: r.ProxyProto})
		}
	}
	cs := cc.cs
	s.mu.Unlock()
	if cs == nil {
		return
	}
	if rules == nil {
		rules = []proto.ReverseRule{}
	}
	cc.csmu.Lock()
	defer cc.csmu.Unlock()
	if err := proto.WriteJSONFrame(cs, proto.RulePush{Rules: rules}); err != nil {
		slog.Warn("规则下发失败", "client", cc.Name, "err", err)
	}
}

// broadcastRules 规则变更后推给所有在线 client。
func (s *Server) broadcastRules() {
	s.mu.Lock()
	ccs := make([]*clientConn, 0, len(s.clients))
	for _, cc := range s.clients {
		ccs = append(ccs, cc)
	}
	s.mu.Unlock()
	for _, cc := range ccs {
		s.pushRulesTo(cc)
	}
}
