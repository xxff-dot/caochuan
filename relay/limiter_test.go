package relay

import (
	"testing"
	"time"
)

func TestLimiterPaces(t *testing.T) {
	l := NewLimiter(1) // 131072 B/s，初始突发 131072B
	chunk := 16 << 10  // 16KB
	start := time.Now()
	for i := 0; i < 32; i++ { // 共 512KB
		l.Wait(chunk)
	}
	el := time.Since(start)
	// 理论：突发免 8 块，剩余 24 块 × 125ms ≈ 3s（允许 ±30% 抖动）
	if el < 2100*time.Millisecond {
		t.Fatalf("限速过松: 512KB@1Mbps 耗时 %v，期望 ≈3s", el)
	}
	if el > 4500*time.Millisecond {
		t.Fatalf("限速过紧: %v", el)
	}
	t.Logf("512KB@1Mbps 耗时 %v", el)
}
