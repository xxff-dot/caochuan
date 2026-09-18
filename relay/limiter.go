package relay

import (
	"sync"
	"time"
)

// Limiter 规则级共享令牌桶限速器（两方向共用一个桶，即限总带宽）。
// nil 或 rate<=0 时不限速。突发量上限为 1 秒配额。
type Limiter struct {
	mu     sync.Mutex
	rate   float64 // bytes/sec
	tokens float64
	last   time.Time
}

// NewLimiter 按 Mbps 创建限速器；mbps<=0 返回 nil（不限速）。
func NewLimiter(mbps int) *Limiter {
	if mbps <= 0 {
		return nil
	}
	return &Limiter{
		rate:   float64(mbps) * 1024 * 1024 / 8,
		tokens: float64(mbps) * 1024 * 1024 / 8,
		last:   time.Now(),
	}
}

// Wait 阻塞直到 n 字节的配额可用。
func (l *Limiter) Wait(n int) {
	if l == nil || n <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for {
		now := time.Now()
		l.tokens += now.Sub(l.last).Seconds() * l.rate
		l.last = now
		if l.tokens > l.rate {
			l.tokens = l.rate
		}
		if l.tokens >= float64(n) {
			l.tokens -= float64(n)
			return
		}
		need := float64(n) - l.tokens
		l.mu.Unlock()
		time.Sleep(time.Duration(need / l.rate * float64(time.Second)))
		l.mu.Lock()
	}
}
