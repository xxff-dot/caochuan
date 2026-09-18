package server

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/xxff-dot/caochuan/config"
	"github.com/xxff-dot/caochuan/proto"
)

const probeInterval = 60 * time.Second
const probeTimeout = 3 * time.Second

// healthStatus 规则目标的最近探测结果（仅 TCP 规则；UDP 无通用探测手段）。
type healthStatus struct {
	OK      bool      `json:"ok"`
	Err     string    `json:"err,omitempty"`
	Checked time.Time `json:"checked"`
}

// probeLoop 周期探测所有启用 TCP 规则的目标可达性。
// 正向：直拨目标；穿透：经隧道开流（顺带验证整条链路）；反向：服务器直拨自己侧目标。
func (s *Server) probeLoop(ctx context.Context) {
	t := time.NewTicker(probeInterval)
	defer t.Stop()
	s.probeAll() // 启动先探一轮
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.probeAll()
		}
	}
}

func (s *Server) probeAll() {
	s.mu.Lock()
	var targets []config.Rule
	for _, r := range s.cfg.Rules {
		if r.Enabled && r.Proto == "tcp" {
			targets = append(targets, r)
		}
	}
	s.mu.Unlock()

	var wg sync.WaitGroup
	for _, r := range targets {
		wg.Add(1)
		go func(r config.Rule) {
			defer wg.Done()
			ok, err := s.probeRule(r)
			s.mu.Lock()
			s.health[r.ID] = &healthStatus{OK: ok, Err: err, Checked: time.Now()}
			s.mu.Unlock()
		}(r)
	}
	wg.Wait()
}

func (s *Server) probeRule(r config.Rule) (bool, string) {
	switch {
	case r.SideOf() == "server" && r.Client != "":
		// 穿透：经隧道让 client 拨目标，验证整条链路
		stream, err := s.openStreamTo(r.Client, proto.StreamHeader{ID: r.ID, Target: r.Target})
		if err != nil {
			return false, err.Error()
		}
		_ = stream.Close()
		return true, ""
	default: // 正向与反向：目标都从服务器侧直拨
		c, err := net.DialTimeout("tcp", r.Target, probeTimeout)
		if err != nil {
			return false, err.Error()
		}
		_ = c.Close()
		return true, ""
	}
}
