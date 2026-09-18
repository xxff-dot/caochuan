package panel

import (
	"fmt"
	"net/http"
	"strings"
)

// writeMetrics 输出 Prometheus 文本格式指标（无外部依赖）。
func (p *Panel) writeMetrics(w http.ResponseWriter) {
	var b strings.Builder
	ov := p.Srv.Overview()
	b.WriteString("# HELP caochuan_rules_total 规则总数\n# TYPE caochuan_rules_total gauge\n")
	fmt.Fprintf(&b, "caochuan_rules_total %d\n", ov["rules"].(int))
	b.WriteString("# HELP caochuan_clients_total 注册客户端数\n# TYPE caochuan_clients_total gauge\n")
	fmt.Fprintf(&b, "caochuan_clients_total %d\n", ov["clients"].(int))
	b.WriteString("# HELP caochuan_clients_online 在线客户端数\n# TYPE caochuan_clients_online gauge\n")
	fmt.Fprintf(&b, "caochuan_clients_online %d\n", ov["clients_online"].(int))

	b.WriteString("# HELP caochuan_rule_bytes_total 规则累计流量字节\n# TYPE caochuan_rule_bytes_total counter\n")
	for _, r := range p.Srv.ListRules() {
		name, side := sanitizeLabel(r.Name), sanitizeLabel(r.SideOf())
		fmt.Fprintf(&b, "caochuan_rule_bytes_total{rule=%q,name=%q,side=%q,direction=\"in\"} %d\n", r.ID, name, side, r.BytesIn)
		fmt.Fprintf(&b, "caochuan_rule_bytes_total{rule=%q,name=%q,side=%q,direction=\"out\"} %d\n", r.ID, name, side, r.BytesOut)
	}
	b.WriteString("# HELP caochuan_rule_conns 规则当前连接数\n# TYPE caochuan_rule_conns gauge\n")
	for _, r := range p.Srv.ListRules() {
		fmt.Fprintf(&b, "caochuan_rule_conns{rule=%q,name=%q,side=%q} %d\n", r.ID, sanitizeLabel(r.Name), sanitizeLabel(r.SideOf()), r.Conns)
	}
	b.WriteString("# HELP caochuan_client_online 客户端在线状态\n# TYPE caochuan_client_online gauge\n")
	for _, c := range p.Srv.ListClients() {
		v := 0
		if c.Online {
			v = 1
		}
		fmt.Fprintf(&b, "caochuan_client_online{client=%q} %d\n", sanitizeLabel(c.Name), v)
	}
	fmt.Fprint(w, b.String())
}

func sanitizeLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
