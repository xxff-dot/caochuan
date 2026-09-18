package server

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/xxff-dot/caochuan/config"
)

var (
	ErrNotFound = errors.New("caochuan: not found")
	ErrConflict = errors.New("caochuan: conflict")
)

// RuleView 规则 + 实时统计，给面板。速率由前端按采样差值计算，不在此处。
type RuleView struct {
	config.Rule
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
	Conns      int64  `json:"conns"`
	ConnsTotal int64  `json:"conns_total"`
	Running    bool   `json:"running"`
	Note       string `json:"note,omitempty"`   // 反向规则：client 侧监听失败原因等
	Health     string `json:"health,omitempty"` // "ok" | "fail"（仅 TCP 规则有探测结果）
	HealthErr  string `json:"health_err,omitempty"`
}

// ClientView 客户端条目（含 token，面板要展示给用户配 client 用）。
type ClientView struct {
	Name    string `json:"name"`
	Token   string `json:"token"`
	Note    string `json:"note"`
	Online  bool   `json:"online"`
	Addr    string `json:"addr,omitempty"`
	Since   string `json:"since,omitempty"`
	Version string `json:"version,omitempty"`
}

func (s *Server) ListRules() []RuleView {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]RuleView, 0, len(s.cfg.Rules))
	for _, r := range s.cfg.Rules {
		v := RuleView{Rule: r}
		if st, ok := s.stats[r.ID]; ok {
			v.BytesIn = st.BytesIn.Load()
			v.BytesOut = st.BytesOut.Load()
			v.Conns = st.Conns.Load()
			v.ConnsTotal = st.ConnsTotal.Load()
		}
		if r.Proto == "tcp" {
			if h := s.health[r.ID]; h != nil {
				if h.OK {
					v.Health = "ok"
				} else {
					v.Health = "fail"
					v.HealthErr = h.Err
				}
			}
		}
		if r.SideOf() == "server" {
			_, v.Running = s.runners[r.ID]
		} else if cc := s.clients[r.Client]; cc != nil { // 反向：看 client 侧回传的监听状态
			v.Running = r.Enabled && cc.status[r.ID] != nil && cc.status[r.ID].OK
			if st := cc.status[r.ID]; st != nil && !st.OK {
				v.Note = st.Err
			}
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Listen < out[j].Listen })
	return out
}

func validateRule(r *config.Rule, clients []config.ClientUser) error {
	if r.Name == "" {
		return fmt.Errorf("名称不能为空")
	}
	if r.Side != "" && r.Side != "server" && r.Side != "client" {
		return fmt.Errorf("side 必须是 server 或 client")
	}
	if r.Proto != "tcp" && r.Proto != "udp" {
		return fmt.Errorf("协议必须是 tcp 或 udp")
	}
	if r.Listen < 1 || r.Listen > 65535 {
		return fmt.Errorf("监听端口无效")
	}
	if r.Target == "" {
		return fmt.Errorf("目标地址不能为空")
	}
	if r.SideOf() == "client" && r.Client == "" {
		return fmt.Errorf("反向规则必须指定客户端")
	}
	if _, err := config.NewACL(r.AllowFrom); err != nil {
		return fmt.Errorf("来源白名单无效: %w", err)
	}
	if r.MaxMbps < 0 || r.MaxConns < 0 {
		return fmt.Errorf("限速/连接数上限不能为负数")
	}
	if r.IdleMin < 0 || r.IdleMin > 24*60 {
		return fmt.Errorf("空闲超时须在 0-1440 分钟之间")
	}
	if r.Client != "" { // 穿透/反向规则必须指向已登记的客户端
		found := false
		for _, c := range clients {
			if c.Name == r.Client {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("客户端 %q 不存在", r.Client)
		}
	}
	return nil
}

// portConflict 端口占用检查：server 侧规则全局限重；client 侧规则按客户端限重。
func portConflict(rules []config.Rule, skipIdx, listen int, r config.Rule, skip string) *config.Rule {
	for i, cur := range rules {
		if i == skipIdx || cur.Listen != listen || cur.ID == skip {
			continue
		}
		if r.SideOf() == "server" && cur.SideOf() == "server" {
			return &cur
		}
		if r.SideOf() == "client" && cur.SideOf() == "client" && cur.Client == r.Client {
			return &cur
		}
	}
	return nil
}

func (s *Server) AddRule(r config.Rule) error {
	s.mu.Lock()
	if err := validateRule(&r, s.cfg.Clients); err != nil {
		s.mu.Unlock()
		return err
	}
	if cur := portConflict(s.cfg.Rules, -1, r.Listen, r, ""); cur != nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: 端口 %d 已被规则 %q 占用", ErrConflict, r.Listen, cur.Name)
	}
	r.ID = config.RandToken()[:8]
	r.Enabled = true
	s.cfg.Rules = append(s.cfg.Rules, r)
	if err := s.cfg.Save(s.CfgPath); err != nil {
		s.cfg.Rules = s.cfg.Rules[:len(s.cfg.Rules)-1]
		s.mu.Unlock()
		return err
	}
	s.applyRulesLocked()
	s.mu.Unlock()
	s.broadcastRules() // 广播需重新拿锁，必须在解锁后调用
	return nil
}

func (s *Server) UpdateRule(id string, nr config.Rule) error {
	s.mu.Lock()
	idx := -1
	for i := range s.cfg.Rules {
		if s.cfg.Rules[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		s.mu.Unlock()
		return ErrNotFound
	}
	old := s.cfg.Rules[idx]
	nr.ID = id
	nr.Enabled = old.Enabled
	if err := validateRule(&nr, s.cfg.Clients); err != nil {
		s.mu.Unlock()
		return err
	}
	if cur := portConflict(s.cfg.Rules, idx, nr.Listen, nr, id); cur != nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: 端口 %d 已被规则 %q 占用", ErrConflict, nr.Listen, cur.Name)
	}
	s.cfg.Rules[idx] = nr
	if err := s.cfg.Save(s.CfgPath); err != nil {
		s.cfg.Rules[idx] = old
		s.mu.Unlock()
		return err
	}
	s.applyRulesLocked()
	s.mu.Unlock()
	s.broadcastRules()
	return nil
}

func (s *Server) DeleteRule(id string) error {
	s.mu.Lock()
	found := false
	for i, cur := range s.cfg.Rules {
		if cur.ID == id {
			s.cfg.Rules = append(s.cfg.Rules[:i], s.cfg.Rules[i+1:]...)
			if rn, ok := s.runners[id]; ok {
				rn.stop()
				delete(s.runners, id)
			}
			found = true
			break
		}
	}
	if !found {
		s.mu.Unlock()
		return ErrNotFound
	}
	err := s.cfg.Save(s.CfgPath)
	s.mu.Unlock()
	s.broadcastRules()
	return err
}

func (s *Server) SetRuleEnabled(id string, on bool) error {
	s.mu.Lock()
	done := false
	var retErr error
	for i := range s.cfg.Rules {
		if s.cfg.Rules[i].ID == id {
			old := s.cfg.Rules[i].Enabled
			s.cfg.Rules[i].Enabled = on
			if err := s.cfg.Save(s.CfgPath); err != nil {
				s.cfg.Rules[i].Enabled = old
				retErr = err
			} else {
				s.applyRulesLocked()
				done = true
			}
			break
		}
	}
	s.mu.Unlock()
	if retErr != nil {
		return retErr
	}
	if !done {
		return ErrNotFound
	}
	s.broadcastRules()
	return nil
}

func (s *Server) ListClients() []ClientView {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ClientView, 0, len(s.cfg.Clients))
	for _, c := range s.cfg.Clients {
		v := ClientView{Name: c.Name, Token: c.Token, Note: c.Note}
		if cc := s.clients[c.Name]; cc != nil {
			v.Online = true
			v.Addr = cc.Addr
			v.Since = cc.Since.Format(time.DateTime)
			v.Version = cc.Version
		}
		out = append(out, v)
	}
	return out
}

func (s *Server) AddClient(name, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if name == "" {
		return fmt.Errorf("名称不能为空")
	}
	for _, c := range s.cfg.Clients {
		if c.Name == name {
			return fmt.Errorf("%w: 客户端 %q 已存在", ErrConflict, name)
		}
	}
	s.cfg.Clients = append(s.cfg.Clients, config.ClientUser{Name: name, Token: config.RandToken(), Note: note})
	return s.cfg.Save(s.CfgPath)
}

func (s *Server) DeleteClient(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.cfg.Clients {
		if c.Name == name {
			for _, r := range s.cfg.Rules {
				if r.Client == name {
					return fmt.Errorf("%w: 规则 %q 仍引用该客户端，先删除规则", ErrConflict, r.Name)
				}
			}
			s.cfg.Clients = append(s.cfg.Clients[:i], s.cfg.Clients[i+1:]...)
			if cc := s.clients[name]; cc != nil {
				cc.Session.Close()
			}
			return s.cfg.Save(s.CfgPath)
		}
	}
	return ErrNotFound
}

// ---- 面板白名单：手动 CIDR + 在线 client 来源 IP 自动放行 ----

func (s *Server) IPWhitelist() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.cfg.IPWhitelist...)
}

func (s *Server) SetIPWhitelist(entries []string) error {
	if _, err := config.NewACL(entries); entries != nil && err != nil {
		return fmt.Errorf("无效的 IP/CIDR: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.cfg.IPWhitelist
	s.cfg.IPWhitelist = entries
	if err := s.cfg.Save(s.CfgPath); err != nil {
		s.cfg.IPWhitelist = old
		return err
	}
	return nil
}

// IPBlacklist 返回黑名单条目。
func (s *Server) IPBlacklist() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.cfg.IPBlacklist...)
}

// SetIPBlacklist 设置黑名单（IP/CIDR）。黑名单优先于一切放行规则。
func (s *Server) SetIPBlacklist(entries []string) error {
	if _, err := config.NewACL(entries); entries != nil && err != nil {
		return fmt.Errorf("无效的 IP/CIDR: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.cfg.IPBlacklist
	s.cfg.IPBlacklist = entries
	if err := s.cfg.Save(s.CfgPath); err != nil {
		s.cfg.IPBlacklist = old
		return err
	}
	s.blVer.Add(1) // 通知监听循环重编译黑名单
	return nil
}

// ExportConfig 返回完整配置的深拷贝（含密码/token，供面板导出）。
func (s *Server) ExportConfig() config.Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *s.cfg
	cp.Clients = append([]config.ClientUser{}, s.cfg.Clients...)
	cp.Rules = append([]config.Rule{}, s.cfg.Rules...)
	cp.IPWhitelist = append([]string{}, s.cfg.IPWhitelist...)
	cp.IPBlacklist = append([]string{}, s.cfg.IPBlacklist...)
	return cp
}

// ImportConfig 从导出的配置恢复业务数据（规则/客户端/白名单/黑名单/通知/密码）。
// 网络身份字段（监听地址、随机路径、secret、TLS）保持本机现值，避免导入后面板失联。
func (s *Server) ImportConfig(in config.Server) error {
	s.mu.Lock()
	old := *s.cfg
	oldClients := append([]config.ClientUser{}, s.cfg.Clients...)
	oldRules := append([]config.Rule{}, s.cfg.Rules...)
	oldWl := append([]string{}, s.cfg.IPWhitelist...)
	oldBl := append([]string{}, s.cfg.IPBlacklist...)

	s.cfg.Password = in.Password
	s.cfg.NoAuth = in.NoAuth
	s.cfg.IPWhitelist = in.IPWhitelist
	s.cfg.IPBlacklist = in.IPBlacklist
	s.cfg.NotifyURL = in.NotifyURL
	s.cfg.NotifyFormat = in.NotifyFormat
	s.cfg.LogFile = in.LogFile
	s.cfg.Clients = in.Clients
	s.cfg.Rules = in.Rules

	if _, err := config.NewACL(s.cfg.IPWhitelist); err != nil {
		s.restoreCfg(old, oldClients, oldRules, oldWl, oldBl)
		s.mu.Unlock()
		return fmt.Errorf("白名单无效: %w", err)
	}
	if _, err := config.NewACL(s.cfg.IPBlacklist); err != nil {
		s.restoreCfg(old, oldClients, oldRules, oldWl, oldBl)
		s.mu.Unlock()
		return fmt.Errorf("黑名单无效: %w", err)
	}
	for i := range s.cfg.Rules {
		if err := validateRule(&s.cfg.Rules[i], s.cfg.Clients); err != nil {
			s.restoreCfg(old, oldClients, oldRules, oldWl, oldBl)
			s.mu.Unlock()
			return fmt.Errorf("规则 %q 无效: %w", s.cfg.Rules[i].Name, err)
		}
	}
	if err := s.cfg.Save(s.CfgPath); err != nil {
		s.restoreCfg(old, oldClients, oldRules, oldWl, oldBl)
		s.mu.Unlock()
		return err
	}
	s.notifier.set(in.NotifyURL, in.NotifyFormat)
	// 客户端可能有变化：重连校验（在线但已删的踢掉），规则重新 diff，最后广播
	for name, cc := range s.clients {
		found := false
		for _, c := range s.cfg.Clients {
			if c.Name == name {
				found = true
				break
			}
		}
		if !found {
			cc.Session.Close()
		}
	}
	s.applyRulesLocked()
	s.mu.Unlock()
	s.broadcastRules()
	return nil
}

// restoreCfg 导入失败时回滚（调用方持有 s.mu）。
func (s *Server) restoreCfg(old config.Server, clients []config.ClientUser, rules []config.Rule, wl, bl []string) {
	s.cfg.Password = old.Password
	s.cfg.NoAuth = old.NoAuth
	s.cfg.IPWhitelist = wl
	s.cfg.IPBlacklist = bl
	s.cfg.NotifyURL = old.NotifyURL
	s.cfg.NotifyFormat = old.NotifyFormat
	s.cfg.LogFile = old.LogFile
	s.cfg.Clients = clients
	s.cfg.Rules = rules
	s.notifier.set(old.NotifyURL, old.NotifyFormat)
}

// IPAllowed 面板访问判定：黑名单（回环豁免，防自锁）优先拒绝；否则 本机回环 ∪ 本机任意网卡地址 ∪ 手动白名单 ∪ 在线 client 来源 IP。
// 本机地址放行是为了让「反向隧道访问面板」可用——那种请求的源地址就是服务器自己。
func (s *Server) IPAllowed(ipStr string) bool {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() {
		return true
	}
	s.mu.Lock()
	bl, berr := config.NewACL(s.cfg.IPBlacklist)
	s.mu.Unlock()
	if berr == nil && bl != nil && bl.Allows(ip) {
		return false // 黑名单优先于除回环外的一切放行
	}
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, a := range addrs {
			if p, ok := netip.AddrFromSlice(a.(*net.IPNet).IP); ok && p.Unmap() == ip {
				return true
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.cfg.IPWhitelist {
		if p, err := netip.ParsePrefix(e); err == nil {
			if p.Contains(ip) {
				return true
			}
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil && a.Unmap() == ip {
			return true
		}
	}
	for _, cc := range s.clients {
		if a, err := netip.ParseAddrPort(cc.Addr); err == nil && a.Addr().Unmap() == ip {
			return true
		}
	}
	return false
}

func (s *Server) CheckPassword(pw string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return subtle.ConstantTimeCompare([]byte(s.cfg.Password), []byte(pw)) == 1
}

func (s *Server) SetPassword(pw string) error {
	if pw == "" {
		return fmt.Errorf("密码不能为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.cfg.Password
	s.cfg.Password = pw
	if err := s.cfg.Save(s.CfgPath); err != nil {
		s.cfg.Password = old
		return err
	}
	return nil
}

// ---- 异常通知 ----

func (s *Server) NotifySettings() (url, format string) {
	return s.notifier.get()
}

func (s *Server) SetNotify(url, format string) error {
	if url != "" && format != "dingtalk" && format != "feishu" && format != "generic" {
		return fmt.Errorf("通知格式必须是 generic、dingtalk 或 feishu")
	}
	s.mu.Lock()
	oldURL, oldFmt := s.cfg.NotifyURL, s.cfg.NotifyFormat
	s.cfg.NotifyURL, s.cfg.NotifyFormat = url, format
	s.notifier.set(url, format)
	err := s.cfg.Save(s.CfgPath)
	if err != nil {
		s.cfg.NotifyURL, s.cfg.NotifyFormat = oldURL, oldFmt
		s.notifier.set(oldURL, oldFmt)
	}
	s.mu.Unlock()
	return err
}

func (s *Server) NotifyTest() error {
	return s.notifier.sendNow("test", "这是一条测试通知，收到即配置成功")
}

func (s *Server) Overview() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	online := 0
	for _, c := range s.cfg.Clients {
		if s.clients[c.Name] != nil {
			online++
		}
	}
	return map[string]any{
		"started":         s.started.Format(time.DateTime),
		"uptime":          time.Since(s.started).Round(time.Second).String(),
		"tunnel_addr":     s.cfg.TunnelAddr,
		"panel_addr":      s.cfg.PanelAddr,
		"clients":         len(s.cfg.Clients),
		"clients_online":  online,
		"rules":           len(s.cfg.Rules),
		"no_auth":         s.cfg.NoAuth,
		"tls":             !s.cfg.NoTLS,
		"tls_fingerprint": s.TlsFingerprint(),
	}
}
