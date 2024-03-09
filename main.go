package main

import (
	"net"
	"sync"
	"os"
	"os/signal"
	"syscall"

	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/coderluoyi/tun2socks_stu/log"
	"github.com/coderluoyi/tun2socks_stu/tcpipnet"
	"github.com/coderluoyi/tun2socks_stu/tunnel"
	"github.com/coderluoyi/tun2socks_stu/tunnel/dialer"
	"github.com/coderluoyi/tun2socks_stu/wintun"
)

var (
	defaultTun   *wintun.Tun
	defaultStack *stack.Stack
	err          error

	ifaceName    string = "WLAN"
	socks5server string = "192.168.50.135:9000"
	_socks5      tunnel.Dialer

	mut sync.Mutex
)

func main() {

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return
	}
	dialer.DefaultInterfaceName.Store(iface.Name)
	dialer.DefaultInterfaceIndex.Store(int32(iface.Index))
	log.Info("[DIALER] bind to interface: %s", ifaceName)

	if _socks5, err = tunnel.NewSocks5(socks5server); err != nil {
		return
	}
	tunnel.SetDialer(_socks5)

	if defaultTun, err = wintun.Open("wintun", 0); err != nil {
		return
	}

	if defaultStack, err = tcpipnet.NewStack(&tcpipnet.Config{
		LinkEndpoint:     defaultTun,
		TransportHandler: &tunnel.Tunnel{},
	}); err != nil {
		return
	}

	defer Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

}

func Close() {
	mut.Lock()
	if defaultTun != nil {
		err = defaultTun.Close()
	}
	if defaultStack != nil {
		defaultStack.Close()
		defaultStack.Wait()
	}
	mut.Unlock()
	log.Error("%s", err)
}
