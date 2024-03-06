package tcpipnet

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/coderluoyi/tun2socks_stu/tcpipnet/adapter"
	"github.com/coderluoyi/tun2socks_stu/tcpipnet/option"
)

type Config struct {
	LinkEndpoint stack.LinkEndpoint

	TransportHandler adapter.TransportHandler
}

func NewStack(cfg *Config) (*stack.Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})

	nicID := tcpip.NICID(s.UniqueID())

	if err := CreateNICWithOptions(s, nicID, cfg.LinkEndpoint); err != nil {
		return nil, err
	}

	if err := setTCPHandler(s, cfg.TransportHandler.HandleTCP); err != nil {
		return nil, err
	}

	if err := setUDPHandler(s, cfg.TransportHandler.HandleUDP); err != nil {
		return nil, err
	}

	if err := setPromiscuousMode(s, nicID, nicPromiscuousModeEnabled); err != nil {
		return nil, err
	}

	if err := setSpoofing(s, nicID, nicSpoofingEnabled); err != nil {
		return nil, err
	}

	if err := setRouteTable(s, nicID); err != nil {
		return nil, err
	}
	
	if err := option.WithDefault()(s); err != nil {
		return nil, err
	}

	return s, nil
}

func setRouteTable(s *stack.Stack, nicID tcpip.NICID) error {
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		},
	})
	return nil
}
