package logbuf

import (
	"os"
	"strconv"
	"sync"
)

// Rotator 按大小轮转的日志文件：path 超过 maxMB 时整体平移为 .1/.2/...（保留 keep 份）。
type Rotator struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
	max  int64
	keep int
}

func NewRotator(path string, maxMB int64, keep int) *Rotator {
	return &Rotator{path: path, max: maxMB << 20, keep: keep}
}

func (r *Rotator) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ensure(); err != nil {
		return 0, err
	}
	if r.size+int64(len(p)) > r.max {
		r.rotate()
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *Rotator) ensure() error {
	if r.f != nil {
		return nil
	}
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, _ := f.Stat()
	r.f = f
	if st != nil {
		r.size = st.Size()
	}
	return nil
}

func (r *Rotator) rotate() {
	_ = r.f.Close()
	r.f = nil
	r.size = 0
	for i := r.keep - 1; i >= 1; i-- { // .2 -> .3, .1 -> .2 ...
		_ = os.Rename(r.path+"."+strconv.Itoa(i), r.path+"."+strconv.Itoa(i+1))
	}
	_ = os.Rename(r.path, r.path+".1")
}
