package tcpipnet

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/coderluoyi/tun2socks_stu/tcpipnet/adapter"
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



	return s, nil
}