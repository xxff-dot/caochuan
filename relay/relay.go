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
// lim 为规则级共享限速器（可 nil），限制双向总带宽。
func Pipe(a, b net.Conn, aToB, bToA *atomic.Int64, lim *Limiter) {
	done := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(writer{w: b, n: aToB, lim: lim}, reader{r: a})
		_ = b.SetDeadline(time.Now()) // 中断 b→a 的 Copy
		done <- struct{}{}
	}()
	_, _ = io.Copy(writer{w: a, n: bToA, lim: lim}, reader{r: b})
	_ = a.SetDeadline(time.Now())
	<-done
}

// writer = 计数 + 限速（拷贝时逐块过桶）。
type writer struct {
	w   io.Writer
	n   *atomic.Int64
	lim *Limiter
}

func (c writer) Write(p []byte) (int, error) {
	c.lim.Wait(len(p))
	n, err := c.w.Write(p)
	if c.n != nil {
		c.n.Add(int64(n))
	}
	return n, err
}

// reader 用小切块读，让限速粒度细到 16KB 而不是 io.Copy 默认 32KB。
type reader struct{ r io.Reader }

func (c reader) Read(p []byte) (int, error) {
	if len(p) > 16<<10 {
		p = p[:16<<10]
	}
	return c.r.Read(p)
}
