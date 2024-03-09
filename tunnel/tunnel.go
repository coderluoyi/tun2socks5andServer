package tunnel

import (
	"net"
	"strconv"
	"time"
	"github.com/coderluoyi/tun2socks_stu/tcpipnet/adapter"
)

var (
	tcpQueue = make(chan adapter.TCPConn)
	udpQueue = make(chan adapter.UDPConn)
)

const tcpKeepAlivePeriod = 30 * time.Second

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
			go handleTCPConn(conn)
		case conn := <-udpQueue:
			go handleUDPConn(conn)
		}
	}
}

// net.Addr -> IP, port.
func parseAddr(addr net.Addr) (net.IP, uint16) {
	switch v := addr.(type) {
	case *net.TCPAddr:
		return v.IP, uint16(v.Port)
	case *net.UDPAddr:
		return v.IP, uint16(v.Port)
	case nil:
		return nil, 0
	default:
		return parseAddrString(addr.String())
	}
}

// addrStr -> IP, port.
func parseAddrString(addr string) (net.IP, uint16) {
	host, port, _ := net.SplitHostPort(addr)
	portInt, _ := strconv.ParseUint(port, 10, 16)
	return net.ParseIP(host), uint16(portInt)
}

// setKeepAlive sets tcp keepalive option for tcp connection.
func setKeepAlive(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(tcpKeepAlivePeriod)
	}
}

// safeConnClose closes tcp connection safely.
func safeConnClose(c net.Conn, err error) {
	if c != nil && err != nil {
		c.Close()
	}
}
