package server

import (
	"sync"
	"time"
)

// 历史采样：30s 一点，保留 24h（2880 点/规则）。仅存内存，重启清零。
const (
	histInterval = 30 * time.Second
	histMax      = 2880
)

type histPoint struct {
	T   int64 `json:"t"` // unix 秒
	In  int64 `json:"in"`
	Out int64 `json:"out"`
}

type history struct {
	mu  sync.Mutex
	pts []histPoint
}

// sampleHistory 由 Run 的 ticker 周期调用，快照所有规则的累计字节数。
func (s *Server) sampleHistory() {
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, st := range s.stats {
		h := s.hist[id]
		if h == nil {
			h = &history{}
			s.hist[id] = h
		}
		h.mu.Lock()
		h.pts = append(h.pts, histPoint{T: now, In: st.BytesIn.Load(), Out: st.BytesOut.Load()})
		if len(h.pts) > histMax {
			h.pts = h.pts[len(h.pts)-histMax:]
		}
		h.mu.Unlock()
	}
}

// GetHistory 返回某规则的采样点（累计字节）。
func (s *Server) GetHistory(id string) []histPoint {
	s.mu.Lock()
	h := s.hist[id]
	s.mu.Unlock()
	if h == nil {
		return []histPoint{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]histPoint, len(h.pts))
	copy(out, h.pts)
	return out
}
