package tunnel

import (
	"github.com/coderluoyi/tun2socks_stu/tcpipnet/adapter"
)

var (
	tcpQueue = make(chan adapter.TCPConn)
	udpQueue = make(chan adapter.UDPConn)
)

type Tunnel struct {}

func (*Tunnel) HandleTCP(conn adapter.TCPConn){
	tcpQueue <- conn
}
func (*Tunnel) HandleUDP(conn adapter.UDPConn){
	udpQueue <- conn
}

func init() {
	go process()
}

func process() {
	for {
		select {
		case conn := <-tcpQueue:
			// go handleTCPConn(conn)
			conn.ID()
		case conn := <-udpQueue:
			// go handleUDPConn(conn)
			conn.ID()
		}
	}
}
