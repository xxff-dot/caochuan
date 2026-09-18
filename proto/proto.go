// Package proto 定义隧道上的帧格式：
//
//	鉴权阶段:  [2B 长度][JSON AuthRequest] -> [2B 长度][JSON AuthReply]
//	smux 数据流: 首帧 [2B 长度][JSON StreamHeader] 声明目标
//	UDP 数据流: header 之后每包 [4B connID][2B 长度][payload]
package proto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const maxFrame = 1 << 16 // 64KB，足够任何 JSON 头与单包 UDP 载荷

type AuthRequest struct {
	Token   string `json:"token"`
	Host    string `json:"host,omitempty"`    // client 自报主机名，仅展示用
	Version string `json:"version,omitempty"` // client 程序版本
}

type AuthReply struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

// StreamHeader 每个 smux 数据流的第一帧。
// UDP=true 时，后续载荷为 UDP 帧序列；否则为裸 TCP 字节流。
type StreamHeader struct {
	ID     string `json:"id,omitempty"`  // 规则 ID，供对端归集统计
	Target string `json:"target"`
	UDP    bool   `json:"udp,omitempty"`
}

// UDPPacket UDP 隧道帧。
type UDPPacket struct {
	ConnID  uint32 `json:"-"`
	Payload []byte `json:"-"`
}

// ControlID 控制流标记：server 连上 client 后开的第一个流，
// 下发反向规则（RulePush）并接收状态（ReverseStatus）。
const ControlID = "__control__"

// ReverseRule 下发给 client 的反向监听条目（Side=client 的规则）。
type ReverseRule struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Proto     string   `json:"proto"`
	Listen    int      `json:"listen"`
	Target    string   `json:"target"`
	AllowFrom []string `json:"allow_from,omitempty"`
	MaxMbps   int      `json:"max_mbps,omitempty"`
	MaxConns  int      `json:"max_conns,omitempty"`
	IdleMin   int      `json:"idle_min,omitempty"` // TCP 空闲超时（分钟），0=不限
}

// RulePush 控制流 server→client 帧。
type RulePush struct {
	Rules []ReverseRule `json:"rules"`
}

// ReverseStatus 控制流 client→server 帧：反向监听器启停结果。
type ReverseStatus struct {
	ID  string `json:"id"`
	OK  bool   `json:"ok"`
	Err string `json:"err,omitempty"`
}

var errTooLarge = errors.New("caochuan: frame too large")

func ReadJSONFrame(r io.Reader, v any) error {
	head := [2]byte{}
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint16(head[:])
	if n == 0 {
		return io.ErrUnexpectedEOF
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}

func WriteJSONFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > maxFrame {
		return errTooLarge
	}
	// 单次 Write：帧头+体一起发，smux 每包只产生一个帧
	buf := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(buf, uint16(len(b)))
	copy(buf[2:], b)
	_, err = w.Write(buf)
	return err
}

// WriteUDPPacket 写一个 UDP 帧（头+载荷单次 Write，省一半 smux 帧开销）。
func WriteUDPPacket(w io.Writer, p *UDPPacket) error {
	if len(p.Payload) > 0xFFFF {
		return fmt.Errorf("caochuan: udp payload %d too large", len(p.Payload))
	}
	buf := make([]byte, 6+len(p.Payload))
	binary.BigEndian.PutUint32(buf[0:4], p.ConnID)
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(p.Payload)))
	copy(buf[6:], p.Payload)
	_, err := w.Write(buf)
	return err
}

// ReadUDPPacket 从 br 读一个 UDP 帧（需传入持缓冲的 reader）。
func ReadUDPPacket(br io.Reader) (*UDPPacket, error) {
	head := make([]byte, 6)
	if _, err := io.ReadFull(br, head); err != nil {
		return nil, err
	}
	p := &UDPPacket{
		ConnID:  binary.BigEndian.Uint32(head[0:4]),
		Payload: make([]byte, binary.BigEndian.Uint16(head[4:6])),
	}
	if _, err := io.ReadFull(br, p.Payload); err != nil {
		return nil, err
	}
	return p, nil
}
