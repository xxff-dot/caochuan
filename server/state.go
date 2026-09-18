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
	Note       string `json:"note,omitempty"` // 反向规则：client 侧监听失败原因等
}

// ClientView 客户端条目（含 token，面板要展示给用户配 client 用）。
type ClientView struct {
	Name   string `json:"name"`
	Token  string `json:"token"`
	Note   string `json:"note"`
	Online bool   `json:"online"`
	Addr   string `json:"addr,omitempty"`
	Since  string `json:"since,omitempty"`
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
	for _, e := range entries {
		if _, err := netip.ParsePrefix(e); err != nil {
			if _, err2 := netip.ParseAddr(e); err2 != nil {
				return fmt.Errorf("无效的 IP/CIDR: %q", e)
			}
		}
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

// IPAllowed 面板访问判定：本机回环 ∪ 本机任意网卡地址 ∪ 手动白名单 ∪ 在线 client 来源 IP。
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
