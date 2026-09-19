// Package config 持有 server/client 的 JSON 配置。
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
)

// Rule 一条转发规则。
// Side 为空或 "server"：监听在服务器 —— Client 为空 = 正向（server 拨 Target），
//
//	Client 非空 = 穿透（该 client 拨 Target）。
//
// Side 为 "client"：反向 —— 该 client 监听 Listen 端口，访问流量经隧道由 server 拨 Target
//
//	（Target 从服务器视角解析，可以是服务器本身或其内网）。
type Rule struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Side       string   `json:"side,omitempty"` // "server"(默认) | "client"
	Proto      string   `json:"proto"`          // "tcp" | "udp"
	Listen     int      `json:"listen"`
	Client     string   `json:"client"`
	Target     string   `json:"target"`
	AllowFrom  []string `json:"allow_from,omitempty"`  // 来源白名单（IP/CIDR），空=不限制
	MaxMbps    int      `json:"max_mbps,omitempty"`    // 规则总带宽上限（Mbps），0=不限
	MaxConns   int      `json:"max_conns,omitempty"`   // 最大并发连接/UDP 会话数，0=不限
	IdleMin    int      `json:"idle_min,omitempty"`    // TCP 空闲超时（分钟），0=不限；UDP 会话固定 90s 过期
	ProxyProto int      `json:"proxy_proto,omitempty"` // 0=关 1=PROXY v1 2=PROXY v2：向目标传递真实访客 IP（仅 TCP）
	Enabled    bool     `json:"enabled"`
}

// SideOf 归一化 side 值。
func (r Rule) SideOf() string {
	if r.Side == "client" {
		return "client"
	}
	return "server"
}

// ClientUser 面板里登记的一台内网机。
type ClientUser struct {
	Name  string `json:"name"`
	Token string `json:"token"`
	Note  string `json:"note,omitempty"`
}

type Server struct {
	TunnelAddr   string       `json:"tunnel_addr"`
	PanelAddr    string       `json:"panel_addr"`
	Password     string       `json:"password"`           // 面板登录密码
	NoAuth       bool         `json:"no_auth,omitempty"`  // 免密模式：跳过登录，仍受 IP 白名单限制
	PanelPrefix  string       `json:"panel_prefix"`       // 面板随机路径前缀，防扫描爆破；留空则启动时自动生成
	IPWhitelist  []string     `json:"ip_whitelist"`       // 手动 CIDR/IP 白名单；client 来源 IP 自动放行
	Secret       string       `json:"secret"`             // 会话签名密钥，自动生成
	NoTLS        bool         `json:"no_tls,omitempty"`   // 关闭隧道 TLS（明文，不推荐）
	TLSCert      string       `json:"tls_cert,omitempty"` // 自有证书路径；留空自动生成自签证书
	TLSKey       string       `json:"tls_key,omitempty"`
	LogFile      string       `json:"log_file,omitempty"`      // 日志文件（空=仅输出到控制台）
	NotifyURL    string       `json:"notify_url,omitempty"`    // WebHook 地址；client 上/下线、规则异常时 POST 通知
	NotifyFormat string       `json:"notify_format,omitempty"` // generic | dingtalk | feishu（默认 generic）
	IPBlacklist  []string     `json:"ip_blacklist,omitempty"`  // IP/CIDR 黑名单，优先于一切放行规则
	Clients      []ClientUser `json:"clients"`
	Rules        []Rule       `json:"rules"`
}

// ACL 来源白名单：nil = 不限制。
type ACL struct {
	prefixes []netip.Prefix
	addrs    []netip.Addr
}

// NewACL 解析 IP/CIDR 列表；空列表返回 nil（不限制）。
func NewACL(entries []string) (*ACL, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	a := &ACL{}
	for _, e := range entries {
		if p, err := netip.ParsePrefix(e); err == nil {
			a.prefixes = append(a.prefixes, p)
			continue
		}
		addr, err := netip.ParseAddr(e)
		if err != nil {
			return nil, err
		}
		a.addrs = append(a.addrs, addr.Unmap())
	}
	return a, nil
}

// Allows 判定访客 IP 是否放行。
func (a *ACL) Allows(ip netip.Addr) bool {
	if a == nil {
		return true
	}
	ip = ip.Unmap()
	for _, p := range a.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	for _, addr := range a.addrs {
		if addr == ip {
			return true
		}
	}
	return false
}

// ClientConfig 内网机侧配置：server 地址 + token + TLS 选项。
type ClientConfig struct {
	ServerAddr     string `json:"server_addr"`
	Token          string `json:"token"`
	NoTLS          bool   `json:"no_tls,omitempty"`          // 与 server 端 no_tls 保持一致
	TLSFingerprint string `json:"tls_fingerprint,omitempty"` // 服务器证书 SHA-256 指纹（推荐填写防中间人）
	LogFile        string `json:"log_file,omitempty"`        // 日志文件（空=仅输出到控制台）
	Socks5Listen   string `json:"socks5_listen,omitempty"`   // SOCKS5 出口代理监听地址（如 "1080"）；留空=关闭
}

func RandToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// LoadServer 读取 server 配置；文件不存在时生成默认配置（含随机密码/token）并落盘，
// generated=true 提示调用方把初始密码打印给用户。
func LoadServer(path string) (*Server, bool, error) {
	cfg := &Server{}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		cfg = &Server{
			TunnelAddr:  "0.0.0.0:7000",
			PanelAddr:   "0.0.0.0:7500",
			Password:    RandToken()[:8],
			PanelPrefix: RandToken()[:8],
			Secret:      RandToken(),
			Clients:     []ClientUser{{Name: "client1", Token: RandToken()}},
			Rules:       []Rule{},
		}
		if err := cfg.Save(path); err != nil {
			return nil, false, err
		}
		return cfg, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, false, err
	}
	if cfg.Rules == nil {
		cfg.Rules = []Rule{}
	}
	// 兜底：手工拷示例配置容易漏 secret（空密钥 = 会话可伪造）
	if cfg.Secret == "" {
		cfg.Secret = RandToken()
		if err := cfg.Save(path); err != nil {
			return nil, false, err
		}
	}
	// 有密码模式但密码为空 = 任何人可登录，生成随机密码并提示
	if !cfg.NoAuth && cfg.Password == "" {
		cfg.Password = RandToken()[:8]
		if err := cfg.Save(path); err != nil {
			return nil, false, err
		}
		return cfg, true, nil // generated=true 提示打印新密码
	}
	return cfg, false, nil
}

// LoadClient 读取 client 配置；文件不存在时生成模板并报错提示填写。
func LoadClient(path string) (*ClientConfig, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		cfg := &ClientConfig{ServerAddr: "1.2.3.4:7000", Token: "从server面板获取"}
		_ = cfg.Save(path)
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	cfg := &ClientConfig{}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Save 原子写回：先写临时文件再 rename。
func save(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Server) Save(path string) error       { return save(path, s) }
func (c *ClientConfig) Save(path string) error { return save(path, c) }
