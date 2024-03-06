package main

import (
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/coderluoyi/tun2socks_stu/tcpipnet"
	"github.com/coderluoyi/tun2socks_stu/tunnel"
	"github.com/coderluoyi/tun2socks_stu/wintun"
	
)

var (
	defaultTun   stack.LinkEndpoint
	defaultStack *stack.Stack
	err          error
)

func main() {
	if defaultTun, err = wintun.Open("wintun", 0); err != nil {
		return
	}
	if defaultStack, err = tcpipnet.NewStack(&tcpipnet.Config{
		LinkEndpoint:     defaultTun,
		TransportHandler: &tunnel.Tunnel{},
	}); err != nil {
		return
	}
}
