// Package panel 提供 Web 面板的 HTTP API：密码登录 + IP 白名单 + 会话 Cookie。
package panel

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xxff-dot/caochuan/config"
	"github.com/xxff-dot/caochuan/server"
)

const (
	sessionCookie = "cc_session"
	sessionTTL    = 24 * time.Hour
	maxBody       = 64 << 10
)

type Panel struct {
	Srv    *server.Server
	UI     fs.FS  // 内嵌前端静态文件
	Prefix string // 面板随机路径前缀（空 = 不启用）
	NoAuth bool   // 免密模式（仍受 IP 白名单限制）
	secret []byte

	mu    sync.Mutex
	fails map[string]*failTrack // IP → 登录失败记录（防爆破）
}

type failTrack struct {
	count    int
	lastFail time.Time
	until    time.Time // 锁定截止时间
}

// sweepFails 清掉过期失败记录，防 map 无界增长。调用方须持有 p.mu。
func (p *Panel) sweepFails(now time.Time) {
	for ip, ft := range p.fails {
		if now.After(ft.until) && now.Sub(ft.lastFail) > 10*time.Minute {
			delete(p.fails, ip)
		}
	}
}

func New(srv *server.Server, secret, prefix string, ui fs.FS) *Panel {
	return &Panel{Srv: srv, UI: ui, Prefix: prefix, secret: []byte(secret), fails: map[string]*failTrack{}}
}

// apiErr 带 HTTP 状态的业务错误。
type apiErr struct {
	status int
	msg    string
}

func (e *apiErr) Error() string { return e.msg }

func (p *Panel) Handler() http.Handler {
	mux := p.apiHandler()
	if p.Prefix == "" {
		return mux
	}
	// 随机路径模式：只暴露 /<prefix>/，其余一律 404，扫描器连登录页都找不到
	mount := "/" + strings.Trim(p.Prefix, "/") + "/"
	outer := http.NewServeMux()
	outer.Handle(mount, http.StripPrefix(strings.TrimSuffix(mount, "/"), mux))
	outer.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		slog.Warn("面板路径拒绝", "ip", clientIP(r), "path", r.URL.Path)
		http.NotFound(w, r)
	})
	return outer
}

func (p *Panel) apiHandler() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", p.handleLogin)
	mux.HandleFunc("POST /api/logout", p.handleLogout)

	mux.HandleFunc("GET /api/me", p.auth(apiOK))
	mux.HandleFunc("GET /api/overview", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		writeJSON(w, p.Srv.Overview())
		return nil
	}))
	mux.HandleFunc("GET /api/rules", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		writeJSON(w, p.Srv.ListRules())
		return nil
	}))
	mux.HandleFunc("GET /api/history/{id}", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		writeJSON(w, map[string]any{"points": p.Srv.GetHistory(r.PathValue("id"))})
		return nil
	}))
	mux.HandleFunc("POST /api/rules", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		req, err := decode[config.Rule](r)
		if err != nil {
			return err
		}
		return p.Srv.AddRule(*req)
	}))
	mux.HandleFunc("PUT /api/rules/{id}", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		req, err := decode[config.Rule](r)
		if err != nil {
			return err
		}
		return p.Srv.UpdateRule(r.PathValue("id"), *req)
	}))
	mux.HandleFunc("DELETE /api/rules/{id}", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		return p.Srv.DeleteRule(r.PathValue("id"))
	}))
	mux.HandleFunc("POST /api/rules/{id}/toggle", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		req, err := decode[struct{ Enabled bool }](r)
		if err != nil {
			return err
		}
		return p.Srv.SetRuleEnabled(r.PathValue("id"), req.Enabled)
	}))

	mux.HandleFunc("GET /api/clients", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		writeJSON(w, p.Srv.ListClients())
		return nil
	}))
	mux.HandleFunc("POST /api/clients", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		req, err := decode[struct {
			Name string `json:"name"`
			Note string `json:"note"`
		}](r)
		if err != nil {
			return err
		}
		return p.Srv.AddClient(req.Name, req.Note)
	}))
	mux.HandleFunc("DELETE /api/clients/{name}", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		return p.Srv.DeleteClient(r.PathValue("name"))
	}))

	mux.HandleFunc("GET /api/whitelist", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		writeJSON(w, map[string]any{"entries": p.Srv.IPWhitelist()})
		return nil
	}))
	mux.HandleFunc("PUT /api/whitelist", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		req, err := decode[struct{ Entries []string }](r)
		if err != nil {
			return err
		}
		return p.Srv.SetIPWhitelist(req.Entries)
	}))

	mux.HandleFunc("GET /api/blacklist", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		writeJSON(w, map[string]any{"entries": p.Srv.IPBlacklist()})
		return nil
	}))
	mux.HandleFunc("PUT /api/blacklist", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		req, err := decode[struct{ Entries []string }](r)
		if err != nil {
			return err
		}
		return p.Srv.SetIPBlacklist(req.Entries)
	}))

	mux.HandleFunc("GET /api/config/export", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Disposition", "attachment; filename=caochuan-server.json")
		writeJSON(w, p.Srv.ExportConfig())
		return nil
	}))
	mux.HandleFunc("POST /api/config/import", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		req, err := decode[config.Server](r)
		if err != nil {
			return err
		}
		return p.Srv.ImportConfig(*req)
	}))

	// Prometheus 指标：无需登录（供采集器抓取），仍受白名单与随机路径保护
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		if !p.Srv.IPAllowed(clientIP(r)) {
			writeErr(w, &apiErr{http.StatusForbidden, "IP 不在白名单"})
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		p.writeMetrics(w)
	})
	mux.HandleFunc("PUT /api/password", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		req, err := decode[struct{ Password string }](r)
		if err != nil {
			return err
		}
		return p.Srv.SetPassword(req.Password)
	}))

	mux.HandleFunc("GET /api/notify", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		url, format := p.Srv.NotifySettings()
		writeJSON(w, map[string]string{"url": url, "format": format})
		return nil
	}))
	mux.HandleFunc("PUT /api/notify", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		req, err := decode[struct {
			URL    string `json:"url"`
			Format string `json:"format"`
		}](r)
		if err != nil {
			return err
		}
		return p.Srv.SetNotify(req.URL, req.Format)
	}))
	mux.HandleFunc("POST /api/notify/test", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		return p.Srv.NotifyTest()
	}))

	mux.HandleFunc("GET /api/logs", p.auth(func(w http.ResponseWriter, r *http.Request) error {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		writeJSON(w, map[string]any{"lines": p.Srv.Log.Tail(n)})
		return nil
	}))

	// 前端 JS 报错回传：白名单 IP 可写，只打日志不落盘
	mux.HandleFunc("POST /api/client-error", func(w http.ResponseWriter, r *http.Request) {
		if !p.Srv.IPAllowed(clientIP(r)) {
			http.NotFound(w, r)
			return
		}
		var v map[string]any
		_ = json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&v)
		slog.Error("前端JS错误", "ip", clientIP(r), "detail", v)
		writeJSON(w, map[string]bool{"ok": true})
	})

	mux.HandleFunc("/", p.handleIndex)
	return mux
}

// ---- 中间件 ----

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// auth = IP 白名单（手动 CIDR ∪ 在线 client 来源 IP）+ 会话校验。
func (p *Panel) auth(next func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store") // 401/200 不能被浏览器缓存
		if !p.Srv.IPAllowed(clientIP(r)) {
			slog.Warn("面板拒绝", "ip", clientIP(r), "reason", "IP不在白名单", "path", r.URL.Path)
			writeErr(w, &apiErr{http.StatusForbidden, fmt.Sprintf("IP %s 不在白名单", clientIP(r))})
			return
		}
		if !p.NoAuth && !p.validSession(r) {
			writeErr(w, &apiErr{http.StatusUnauthorized, "未登录"})
			return
		}
		if err := next(w, r); err != nil {
			writeErr(w, err)
		} else if w.Header().Get("Content-Type") == "" {
			// 写操作统一回个 JSON，前端不用猜
			writeJSON(w, map[string]bool{"ok": true})
		}
	}
}

func apiOK(w http.ResponseWriter, r *http.Request) error {
	writeJSON(w, map[string]bool{"ok": true})
	return nil
}

func writeErr(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	var ae *apiErr
	switch {
	case errors.Is(err, server.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, server.ErrConflict):
		status = http.StatusConflict
	case errors.As(err, &ae):
		status = ae.status
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func decode[T any](r *http.Request) (*T, error) {
	var v T
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&v); err != nil {
		return nil, &apiErr{http.StatusBadRequest, fmt.Sprintf("请求体解析失败: %v", err)}
	}
	return &v, nil
}

// ---- 会话 ----

func (p *Panel) sign(expiry int64) string {
	mac := hmac.New(sha256.New, p.secret)
	fmt.Fprintf(mac, "caochuan:%d", expiry)
	return hex.EncodeToString(mac.Sum(nil))
}

func (p *Panel) setSession(w http.ResponseWriter) {
	exp := time.Now().Add(sessionTTL).Unix()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: fmt.Sprintf("%d|%s", exp, p.sign(exp)),
		Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func (p *Panel) validSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	parts := strings.SplitN(c.Value, "|", 2)
	if len(parts) != 2 {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(parts[1]), []byte(p.sign(exp))) == 1
}

// ---- 登录/登出 ----

func (p *Panel) handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !p.Srv.IPAllowed(clientIP(r)) {
		ip := clientIP(r)
		slog.Warn("面板拒绝", "ip", ip, "reason", "IP不在白名单", "path", r.URL.Path)
		writeErr(w, &apiErr{http.StatusForbidden, fmt.Sprintf("IP %s 不在白名单（可在服务器 conf/server.json 的 ip_whitelist 中添加）", ip)})
		return
	}
	ip := clientIP(r)
	p.mu.Lock()
	p.sweepFails(time.Now())
	ft := p.fails[ip]
	if ft != nil && time.Now().Before(ft.until) {
		p.mu.Unlock()
		writeErr(w, &apiErr{http.StatusTooManyRequests, "失败次数过多，请 10 分钟后再试"})
		return
	}
	p.mu.Unlock()

	req, err := decode[struct {
		Password string `json:"password"`
	}](r)
	if err != nil {
		writeErr(w, err)
		return
	}
	if !p.Srv.CheckPassword(req.Password) {
		slog.Warn("面板登录失败", "ip", ip)
		p.mu.Lock()
		if p.fails[ip] == nil {
			p.fails[ip] = &failTrack{}
		}
		ft = p.fails[ip]
		ft.count++
		ft.lastFail = time.Now()
		if ft.count >= 5 {
			ft.until = time.Now().Add(10 * time.Minute)
			ft.count = 0
		}
		p.mu.Unlock()
		time.Sleep(300 * time.Millisecond) // 拖慢爆破
		writeErr(w, &apiErr{http.StatusUnauthorized, "密码错误"})
		return
	}
	p.mu.Lock()
	delete(p.fails, ip)
	p.mu.Unlock()
	p.setSession(w)
	writeJSON(w, map[string]bool{"ok": true})
}

func (p *Panel) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", MaxAge: -1, Path: "/"})
	writeJSON(w, map[string]bool{"ok": true})
}

// handleIndex 兜底：/api/* 返回 404，其余走内嵌前端。
func (p *Panel) handleIndex(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	if p.UI == nil {
		http.Error(w, "前端未打包", http.StatusNotFound)
		return
	}
	// 单页应用：每次都重新验证，避免浏览器（尤其 Chrome）吃旧版本
	w.Header().Set("Cache-Control", "no-cache")
	http.FileServerFS(p.UI).ServeHTTP(w, r)
}
