package relay

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
)

// DialUDPBalanced 轮询拨号逗号分隔的多目标（每次调用重新解析，DNS 变更自动跟随）。
func DialUDPBalanced(targets string, rr *atomic.Uint64) (*net.UDPConn, error) {
	list := ParseTargets(targets)
	if len(list) == 0 {
		return nil, fmt.Errorf("目标地址为空")
	}
	start := int(rr.Add(1) - 1)
	var lastErr error
	for i := 0; i < len(list); i++ {
		t := list[(start+i)%len(list)]
		ra, err := net.ResolveUDPAddr("udp", t)
		if err != nil {
			lastErr = err
			continue
		}
		c, err := net.DialUDP("udp", nil, ra)
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// ParseTargets 拆分逗号分隔的多目标列表（去空白、去空项）。
func ParseTargets(s string) []string {
	var out []string
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// ProxyHeader 构造 PROXY protocol 头（version: 1=v1 文本，2=v2 二进制）。
// src 为真实访客地址，dst 为访客连接的目的地址。仅支持 TCP 家族地址。
func ProxyHeader(version int, src, dst *net.TCPAddr) ([]byte, error) {
	if src.IP == nil || dst.IP == nil {
		return nil, fmt.Errorf("地址缺失")
	}
	src4, dst4 := src.IP.To4(), dst.IP.To4()
	switch version {
	case 1:
		fam := "TCP4"
		if src4 == nil || dst4 == nil {
			fam = "TCP6"
		}
		return []byte(fmt.Sprintf("PROXY %s %s %s %d %d\r\n",
			fam, src.IP, dst.IP, src.Port, dst.Port)), nil
	case 2:
		sig := []byte("\r\n\r\n\x00\r\nQUIT\n")
		b := &bytes.Buffer{}
		b.Write(sig)
		if src4 != nil && dst4 != nil {
			b.WriteByte(0x21) // v2 | PROXY
			b.WriteByte(0x11) // TCP4
			binary.Write(b, binary.BigEndian, uint16(16))
			b.Write(src4)
			b.Write(dst4)
		} else {
			b.WriteByte(0x21)
			b.WriteByte(0x22) // TCP6
			binary.Write(b, binary.BigEndian, uint16(36))
			b.Write(src.IP.To16())
			b.Write(dst.IP.To16())
		}
		binary.Write(b, binary.BigEndian, uint16(src.Port))
		binary.Write(b, binary.BigEndian, uint16(dst.Port))
		return b.Bytes(), nil
	default:
		return nil, fmt.Errorf("未知 PROXY 协议版本 %d", version)
	}
}
