package adapter

import (
	"net"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// 实现 net.Conn
type TCPConn interface {
	net.Conn

	// TCP 连接 元数据
	ID() *stack.TransportEndpointID
}

// 实现 net.Conn、net.PacketConn.
type UDPConn interface {
	net.Conn
	net.PacketConn

	// UDP 连接 元数据
	ID() *stack.TransportEndpointID
}

// 传输层连接 自定义处理方法
type TransportHandler interface {
	HandleTCP(TCPConn)
	HandleUDP(UDPConn)
}
