// Package relay 提供双向连接拷贝：任一方向结束时通过对端 deadline 中断另一方向。
package relay

import (
	"io"
	"net"
	"sync/atomic"
	"time"
)

type counter struct {
	w io.Writer
	n *atomic.Int64
}

func (c counter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}

// Pipe 在 a/b 间双向拷贝。计数器传 nil 表示不计数（aToB = a→b 方向字节）。
func Pipe(a, b net.Conn, aToB, bToA *atomic.Int64) {
	done := make(chan struct{}, 1)
	go func() {
		if aToB == nil {
			_, _ = io.Copy(b, a)
		} else {
			_, _ = io.Copy(counter{w: b, n: aToB}, a)
		}
		_ = b.SetDeadline(time.Now()) // 中断 b→a 的 Copy
		done <- struct{}{}
	}()
	if bToA == nil {
		_, _ = io.Copy(a, b)
	} else {
		_, _ = io.Copy(counter{w: a, n: bToA}, b)
	}
	_ = a.SetDeadline(time.Now())
	<-done
}
