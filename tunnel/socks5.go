// Package proxy provides implementations of proxy protocols.
package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/coderluoyi/tun2socks_stu/tunnel/dialer"
)


const (
	tcpConnectTimeout = 10 * time.Second
)


var _ Proxy = (*Socks5)(nil)
var __ Dialer = (*Socks5)(nil)

type Proxy interface {
	Addr() string
}

type Dialer interface {
	DialContext(context.Context, *Metadata) (net.Conn, error)
	DialUDP(*Metadata) (net.PacketConn, error)
}

var _defaultDialer Dialer

// SetDialer sets default Dialer.
func SetDialer(d Dialer) {
	_defaultDialer = d
}

// Dial uses default Dialer to dial TCP.
func Dial(metadata *Metadata) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), tcpConnectTimeout)
	defer cancel()
	return _defaultDialer.DialContext(ctx, metadata)
}

// DialContext uses default Dialer to dial TCP with context.
func DialContext(ctx context.Context, metadata *Metadata) (net.Conn, error) {
	return _defaultDialer.DialContext(ctx, metadata)
}

// DialUDP uses default Dialer to dial UDP.
func DialUDP(metadata *Metadata) (net.PacketConn, error) {
	return _defaultDialer.DialUDP(metadata)
}

type Socks5 struct {
	addr  string
}

func NewSocks5(addr string) (*Socks5, error) {
	return &Socks5{
		addr : addr,
	}, nil
}

func (ss *Socks5) Addr() string{
	return ss.addr
}

func (ss *Socks5) DialContext(ctx context.Context, metadata *Metadata) (c net.Conn, err error) {
	network := "tcp"

	c, err = dialer.DialContext(ctx, network, ss.Addr())
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", ss.Addr(), err)
	}
	setKeepAlive(c)

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	_, err = ClientHandshake(c, serializeSocksAddr(metadata), CMD_CONNECT)
	return
}

func (ss *Socks5) DialUDP(*Metadata) (_ net.PacketConn, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), tcpConnectTimeout)
	defer cancel()

	c, err := dialer.DialContext(ctx, "tcp", ss.Addr())
	if err != nil {
		err = fmt.Errorf("connect to %s: %w", ss.Addr(), err)
		return
	}
	setKeepAlive(c)

	defer func() {
		if err != nil && c != nil {
			c.Close()
		}
	}()

	// The UDP ASSOCIATE request is used to establish an association within
	// the UDP relay process to handle UDP datagrams.  The DST.ADDR and
	// DST.PORT fields contain the address and port that the client expects
	// to use to send UDP datagrams on for the association.  The server MAY
	// use this information to limit access to the association.  If the
	// client is not in possession of the information at the time of the UDP
	// ASSOCIATE, the client MUST use a port number and address of all
	// zeros. RFC1928
	var targetAddr Addr = []byte{byte(ATYP_IPV4), 0, 0, 0, 0, 0, 0}

	addr, err := ClientHandshake(c, targetAddr, 0x03)
	if err != nil {
		return nil, fmt.Errorf("client handshake: %w", err)
	}

	pc, err := dialer.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("listen packet: %w", err)
	}

	go func() {
		io.Copy(io.Discard, c)
		c.Close()
		// A UDP association terminates when the TCP connection that the UDP
		// ASSOCIATE request arrived on terminates. RFC1928
		pc.Close()
	}()

	bindAddr := addr.UDPAddr()
	if bindAddr == nil {
		return nil, fmt.Errorf("invalid UDP binding address: %#v", addr)
	}

	if bindAddr.IP.IsUnspecified() { /* e.g. "0.0.0.0" or "::" */
		udpAddr, err := net.ResolveUDPAddr("udp", ss.Addr())
		if err != nil {
			return nil, fmt.Errorf("resolve udp address %s: %w", ss.Addr(), err)
		}
		bindAddr.IP = udpAddr.IP
	}

	return &socksPacketConn{PacketConn: pc, rAddr: bindAddr, tcpConn: c}, nil
}

type socksPacketConn struct {
	net.PacketConn

	rAddr   net.Addr
	tcpConn net.Conn
}

func (pc *socksPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	var packet []byte
	if ma, ok := addr.(*MetaAddr); ok {
		packet, err = EncodeUDPPacket(serializeSocksAddr(ma.Metadata()), b)
	} else {
		packet, err = EncodeUDPPacket(ParseAddr(addr), b)
	}

	if err != nil {
		return
	}
	return pc.PacketConn.WriteTo(packet, pc.rAddr)
}

func (pc *socksPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, err := pc.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}

	addr, payload, err := DecodeUDPPacket(b)
	if err != nil {
		return 0, nil, err
	}

	udpAddr := addr.UDPAddr()
	if udpAddr == nil {
		return 0, nil, fmt.Errorf("convert %s to UDPAddr is nil", addr)
	}

	// due to DecodeUDPPacket is mutable, record addr length
	copy(b, payload)
	return n - len(addr) - 3, udpAddr, nil
}

func (pc *socksPacketConn) Close() error {
	pc.tcpConn.Close()
	return pc.PacketConn.Close()
}

func serializeSocksAddr(m *Metadata) Addr {
	return SerializeAddr("", m.DstIP, m.DstPort)
}

type Method uint8
type Command uint8
type Atyp uint8
type Reply uint8

const SOCKS5_VER      uint8 = 0x05
const METHOD_NO_AUTH Method = 0x00
const CMD_CONNECT   Command = 0x01
const ATYP_IPV4        Atyp = 0x01
const ATYP_DN          Atyp = 0x03
const ATYP_IPV6        Atyp = 0x04
const SUCCEEDED       Reply = 0x00

// const ATYP_IPV6      Atyp    = 0x04

// Command --> string
func (c Command) String() string {
    switch c {
    case CMD_CONNECT:
        return "CONNECT"
    case 0x02:
        return "BIND"
    case 0x03:
        return "UDP ASSOCIATE"
    default:
        return "UNDEFINED"
    }
}

// Reply --> string
func (r Reply) String() string {
    switch r {
    case 0x00:
        return "succeeded"
    case 0x01:
        return "general SOCKS server failure"
    case 0x02:
        return "connection not allowed by ruleset"
    case 0x03:
        return "network unreachable"
    case 0x04:
        return "host unreachable"
    case 0x05:
        return "connection refused"
    case 0x06:
        return "TTL expired"
    case 0x07:
        return "command not supported"
    case 0x08:
        return "address type not supported"
    default:
        return fmt.Sprintf("UNDEFINED:<%#02x>", uint8(r))
    }
}

const MaxAddrLen = 1 + 1 + 255 + 2

type Addr []byte

// Addr valid (bool)
func (a Addr) Valid() bool {
    if len(a) < 1+1+2 /* minimum length */ {
        return false
    }

    switch a[0] {
    case byte(ATYP_DN):
        // atyp|dn_len|[dn...]|port : 1 + 1 + dn_len + 2
        if len(a) < 1+1+int(a[1])+2 {
            return false
        }
    case byte(ATYP_IPV4):
        // atyp|ipv4len|port        : 1 + 4 + 2
        if len(a) < 1+net.IPv4len+2 {
            return false
        }
    }
    return true
}

// Addr --> string
func (a Addr) String() string {
    if !a.Valid() {
        return ""
    }

    var host, port string
    switch a[0] {
    case byte(ATYP_DN):
        hostLen := int(a[1])
        host = string(a[2 : 2+hostLen])
        port = strconv.Itoa(int(binary.BigEndian.Uint16(a[2+hostLen:])))
    case byte(ATYP_IPV4):
        host = net.IP(a[1 : 1+net.IPv4len]).String()
        port = strconv.Itoa(int(binary.BigEndian.Uint16(a[1+net.IPv4len:])))
    }
    return net.JoinHostPort(host, port)
}

// UDPAddr converts a socks5.Addr to *net.UDPAddr.
func (a Addr) UDPAddr() *net.UDPAddr {
	if !a.Valid() {
		return nil
	}

	var ip []byte
	var port int
	switch a[0] {
	case byte(ATYP_DN) /* unsupported */ :
		return nil
	case byte(ATYP_IPV4):
		ip = make([]byte, net.IPv4len)
		copy(ip, a[1:1+net.IPv4len])
		port = int(binary.BigEndian.Uint16(a[1+net.IPv4len:]))
	case byte(ATYP_IPV6):
		ip = make([]byte, net.IPv6len)
		copy(ip, a[1:1+net.IPv6len])
		port = int(binary.BigEndian.Uint16(a[1+net.IPv6len:]))
	}
	return &net.UDPAddr{IP: ip, Port: port}
}

// User provides basic socks5 auth functionality.
type User struct {
	Username string
	Password string
}

// ClientHandshake fast-tracks SOCKS initialization to get target address to connect on client side.
func ClientHandshake(rw io.ReadWriter, addr Addr, command Command) (Addr, error) {
    buf := make([]byte, MaxAddrLen)
    var method = METHOD_NO_AUTH
    // 1. VER, NMETHODS, METHODS
    if _, err := rw.Write([]byte{SOCKS5_VER, 0x01 /* NMETHODS */, byte(method)}); err != nil {
        return nil, err
    }

    // 2. VER, METHOD
    if _, err := io.ReadFull(rw, buf[:2]); err != nil {
        return nil, err
    }

    if buf[0] != SOCKS5_VER {
        return nil, errors.New("socks version mismatched")
    }

    if buf[1] != byte(METHOD_NO_AUTH){
        return nil, errors.New("only support method of no auth")
    }

    // 3. request : VER, CMD, RSV, ADDR
    if _, err := rw.Write(bytes.Join([][]byte{{SOCKS5_VER, byte(command), 0x00 /* RSV */}, addr}, nil)); err != nil {
        return nil, err
    }

    // 4. reply : VER, CMD, RSV, ADDR
    if _, err := rw.Write(bytes.Join([][]byte{{SOCKS5_VER, byte(command), 0x00 /* RSV */}, addr}, nil)); err != nil {
        return nil, err
    }

    return ReadAddr(rw, buf)
}

func ReadAddr(r io.Reader, b []byte) (Addr, error) {
    if len(b) < MaxAddrLen {
        return nil, io.ErrShortBuffer
    }

    // read 1st byte for address type
    if _, err := io.ReadFull(r, b[:1]); err != nil {
        return nil, err
    }

    switch b[0] /* ATYP */ {
    case byte(ATYP_DN):
        // read 2nd byte for domain length
        if _, err := io.ReadFull(r, b[1:2]); err != nil {
            return nil, err
        }
        domainLength := uint16(b[1])
        _, err := io.ReadFull(r, b[2:2 + domainLength + 2])
        return b[:1 + 1 + domainLength + 2], err
    case byte(ATYP_IPV4):
        _, err := io.ReadFull(r, b[1:1 + net.IPv4len + 2])
        return b[:1 + net.IPv4len + 2], err
	case byte(ATYP_IPV6):
		_, err := io.ReadFull(r, b[1:1 + net.IPv6len + 2])
		return b[:1+net.IPv6len+2], err
    default:
        return nil, errors.New("invalid address type")
    }
}

// SplitAddr slices a SOCKS address from beginning of b. Returns nil if failed.
func SplitAddr(b []byte) Addr {
	addrLen := 1
	if len(b) < addrLen {
		return nil
	}

	switch b[0] {
	case byte(ATYP_DN):
		if len(b) < 2 {
			return nil
		}
		addrLen = 1 + 1 + int(b[1]) + 2
	case byte(ATYP_IPV4):
		addrLen = 1 + net.IPv4len + 2
	case byte(ATYP_IPV6):
		addrLen = 1 + net.IPv6len + 2
	default:
		return nil
	}

	if len(b) < addrLen {
		return nil
	}

	return b[:addrLen]
}

// SerializeAddr serializes destination address and port to Addr.
// If a domain name is provided, AtypDomainName would be used first.
func SerializeAddr(domainName string, dstIP net.IP, dstPort uint16) Addr {
	var (
		buf  [][]byte
		port [2]byte
	)
	binary.BigEndian.PutUint16(port[:], dstPort)

	if domainName != "" /* Domain Name */ {
		length := len(domainName)
		buf = [][]byte{{byte(ATYP_DN), uint8(length)}, []byte(domainName), port[:]}
	} else if dstIP.To4() != nil /* IPv4 */ {
		buf = [][]byte{{byte(ATYP_IPV4)}, dstIP.To4(), port[:]}
	} else /* IPv6 */ {
		buf = [][]byte{{byte(ATYP_IPV6)}, dstIP.To16(), port[:]}
	}
	return bytes.Join(buf, nil)
}

// ParseAddr parses a socks addr from net.Addr.
// This is a fast path of ParseAddrString(addr.String())
func ParseAddr(addr net.Addr) Addr {
	switch v := addr.(type) {
	case *net.TCPAddr:
		return SerializeAddr("", v.IP, uint16(v.Port))
	case *net.UDPAddr:
		return SerializeAddr("", v.IP, uint16(v.Port))
	default:
		return ParseAddrString(addr.String())
	}
}

// ParseAddrString parses the address in string s to Addr. Returns nil if failed.
func ParseAddrString(s string) Addr {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil
	}

	dstPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil
	}

	if ip := net.ParseIP(host); ip != nil {
		return SerializeAddr("", ip, uint16(dstPort))
	}
	return SerializeAddr(host, nil, uint16(dstPort))
}

// DecodeUDPPacket split `packet` to addr payload, and this function is mutable with `packet`
func DecodeUDPPacket(packet []byte) (addr Addr, payload []byte, err error) {
	if len(packet) < 5 {
		err = errors.New("insufficient length of packet")
		return
	}

	// packet[0] and packet[1] are reserved
	if !bytes.Equal(packet[:2], []byte{0x00, 0x00}) {
		err = errors.New("reserved fields should be zero")
		return
	}

	// The FRAG field indicates whether or not this datagram is one of a
	// number of fragments.  If implemented, the high-order bit indicates
	// end-of-fragment sequence, while a value of X'00' indicates that this
	// datagram is standalone.  Values between 1 and 127 indicate the
	// fragment position within a fragment sequence.  Each receiver will
	// have a REASSEMBLY QUEUE and a REASSEMBLY TIMER associated with these
	// fragments.  The reassembly queue must be reinitialized and the
	// associated fragments abandoned whenever the REASSEMBLY TIMER expires,
	// or a new datagram arrives carrying a FRAG field whose value is less
	// than the highest FRAG value processed for this fragment sequence.
	// The reassembly timer MUST be no less than 5 seconds.  It is
	// recommended that fragmentation be avoided by applications wherever
	// possible.
	//
	// Ref: https://datatracker.ietf.org/doc/html/rfc1928#section-7
	if packet[2] != 0x00 /* fragments */ {
		err = errors.New("discarding fragmented payload")
		return
	}

	addr = SplitAddr(packet[3:])
	if addr == nil {
		err = errors.New("socks5 UDP addr is nil")
	}

	payload = packet[3+len(addr):]
	return
}

func EncodeUDPPacket(addr Addr, payload []byte) (packet []byte, err error) {
	if addr == nil {
		return nil, errors.New("address is invalid")
	}
	packet = bytes.Join([][]byte{{0x00, 0x00, 0x00}, addr, payload}, nil)
	return
}
