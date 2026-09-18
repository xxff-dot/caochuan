// Package logbuf 是给面板看的环形日志缓冲，实现 io.Writer 可直接挂到 slog。
package logbuf

import (
	"strings"
	"sync"
)

type Ring struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func New(max int) *Ring { return &Ring{max: max} }

// Write 实现 io.Writer；slog 的文本输出按行切分后入环。
func (r *Ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for line := range strings.SplitSeq(strings.TrimRight(string(p), "\n"), "\n") {
		if line == "" {
			continue
		}
		r.lines = append(r.lines, line)
		if len(r.lines) > r.max {
			r.lines = r.lines[len(r.lines)-r.max:]
		}
	}
	return len(p), nil
}

// Tail 返回最近 n 行（n<=0 表示全部）。
func (r *Ring) Tail(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= 0 || n > len(r.lines) {
		n = len(r.lines)
	}
	out := make([]string, n)
	copy(out, r.lines[len(r.lines)-n:])
	return out
}
