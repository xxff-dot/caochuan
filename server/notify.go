package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

const notifyTimeout = 5 * time.Second
const notifyDebounce = 60 * time.Second // 同一事件 60s 内不重复推送

type notifier struct {
	mu     sync.Mutex
	url    string
	format string // generic | dingtalk | feishu
	last   map[string]time.Time
}

func newNotifier(url, format string) *notifier {
	if format != "dingtalk" && format != "feishu" {
		format = "generic"
	}
	return &notifier{url: url, format: format, last: map[string]time.Time{}}
}

func (n *notifier) set(url, format string) {
	if format != "dingtalk" && format != "feishu" {
		format = "generic"
	}
	n.mu.Lock()
	n.url, n.format = url, format
	n.mu.Unlock()
}

func (n *notifier) get() (url, format string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.url, n.format
}

// send 异步推送一条通知；同 key 60s 防抖；失败仅记日志不影响业务。
func (n *notifier) send(key, event, msg string) {
	url, format := n.get()
	if url == "" {
		return
	}
	n.mu.Lock()
	if t := n.last[key]; time.Since(t) < notifyDebounce {
		n.mu.Unlock()
		return
	}
	n.last[key] = time.Now()
	n.mu.Unlock()

	go func() {
		var payload any
		text := fmt.Sprintf("【草船】%s", msg)
		switch format {
		case "dingtalk":
			payload = map[string]any{"msgtype": "text", "text": map[string]string{"content": text}}
		case "feishu":
			payload = map[string]any{"msg_type": "text", "content": map[string]string{"text": text}}
		default:
			payload = map[string]any{"event": event, "message": msg, "time": time.Now().Format(time.DateTime)}
		}
		b, err := json.Marshal(payload)
		if err != nil {
			return
		}
		client := &http.Client{Timeout: notifyTimeout}
		resp, err := client.Post(url, "application/json", bytes.NewReader(b))
		if err != nil {
			slog.Warn("通知推送失败", "event", event, "err", err)
			return
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 {
			slog.Warn("通知推送被拒", "event", event, "status", resp.StatusCode)
		}
	}()
}

// sendNow 同步推送（测试按钮用），返回错误给前端。
func (n *notifier) sendNow(event, msg string) error {
	url, format := n.get()
	if url == "" {
		return fmt.Errorf("未配置通知地址")
	}
	var payload any
	text := fmt.Sprintf("【草船】%s", msg)
	switch format {
	case "dingtalk":
		payload = map[string]any{"msgtype": "text", "text": map[string]string{"content": text}}
	case "feishu":
		payload = map[string]any{"msg_type": "text", "content": map[string]string{"text": text}}
	default:
		payload = map[string]any{"event": event, "message": msg, "time": time.Now().Format(time.DateTime)}
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: notifyTimeout}
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("远端返回 %s", resp.Status)
	}
	return nil
}
