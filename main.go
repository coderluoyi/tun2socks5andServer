package main

import (

	tcpipnet "github.com/coderluoyi/tun2socks_stu/tcpip"
	"github.com/coderluoyi/tun2socks_stu/wintun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var (
	defaultTun stack.LinkEndpoint
	defaultStack *stack.Stack
	err error
)

func main() {
	if defaultTun, err = wintun.Open("wintun", 0); err != nil {
		return
	}
	if defaultStack, err = tcpipnet.NewStack(); err != nil {
		return
	}
}
