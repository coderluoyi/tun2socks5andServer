package tunnel

import (
	"net"
	"strconv"
	"fmt"
)

const (
	TCP Network = iota
	UDP
)

type Network uint8

func (n Network) String() string {
	switch n {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	default:
		return fmt.Sprintf("network(%d)", n)
	}
}

func (n Network) MarshalText() ([]byte, error) {
	return []byte(n.String()), nil
}


// Metadata contains metadata of transport protocol sessions.
type Metadata struct {
	Network Network `json:"network"`
	SrcIP   net.IP  `json:"sourceIP"`
	MidIP   net.IP  `json:"dialerIP"`
	DstIP   net.IP  `json:"destinationIP"`
	SrcPort uint16  `json:"sourcePort"`
	MidPort uint16  `json:"dialerPort"`
	DstPort uint16  `json:"destinationPort"`
}

func (m *Metadata) DestinationAddress() string {
	return net.JoinHostPort(m.DstIP.String(), strconv.FormatUint(uint64(m.DstPort), 10))
}

func (m *Metadata) SourceAddress() string {
	return net.JoinHostPort(m.SrcIP.String(), strconv.FormatUint(uint64(m.SrcPort), 10))
}

func (m *Metadata) Addr() net.Addr {
	return &MetaAddr{metadata: m}
}

func (m *Metadata) TCPAddr() *net.TCPAddr {
	if m.Network != TCP || m.DstIP == nil {
		return nil
	}
	return &net.TCPAddr{
		IP:   m.DstIP,
		Port: int(m.DstPort),
	}
}

func (m *Metadata) UDPAddr() *net.UDPAddr {
	if m.Network != UDP || m.DstIP == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   m.DstIP,
		Port: int(m.DstPort),
	}
}

// 实现 net.Addr 接口
var _ net.Addr = (*MetaAddr)(nil)

type MetaAddr struct {
	metadata *Metadata
}

func (a *MetaAddr) Metadata() *Metadata {
	return a.metadata
}

func (a *MetaAddr) Network() string {
	return a.metadata.Network.String()
}

func (a *MetaAddr) String() string {
	return a.metadata.DestinationAddress()
}
