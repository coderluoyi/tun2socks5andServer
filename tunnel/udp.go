package tunnel

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/coderluoyi/tun2socks_stu/log"
	"github.com/coderluoyi/tun2socks_stu/pool"
	"github.com/coderluoyi/tun2socks_stu/tcpipnet/adapter"
	"github.com/coderluoyi/tun2socks_stu/dns" 
)

// _udpSessionTimeout is the default timeout for each UDP session.
var _udpSessionTimeout = 20 * time.Second

func SetUDPTimeout(t time.Duration) {
	_udpSessionTimeout = t
}

// TODO: Port Restricted NAT support.
func handleUDPConn(uc adapter.UDPConn) {
	defer uc.Close()

	id := uc.ID()
	metadata := &Metadata{
		Network: UDP,
		SrcIP:   net.IP(id.RemoteAddress.AsSlice()),
		SrcPort: id.RemotePort,
		DstIP:   net.IP(id.LocalAddress.AsSlice()),
		DstPort: id.LocalPort,
	}

	pc, err := DialUDP(metadata)
	if err != nil {
		log.Warning("[UDP] dial %s: %v", metadata.DestinationAddress(), err)
		return
	}
	defer pc.Close()

	metadata.MidIP, metadata.MidPort = parseAddr(pc.LocalAddr())

	// TODO UDPTracker

	var remote net.Addr

	if udpAddr := metadata.UDPAddr(); udpAddr != nil {
		remote = udpAddr
	} else {
		remote = metadata.Addr()
	}
	// pc = newSymmetricNATPacketConn(pc, metadata)

	if metadata.DstPort == 53 || metadata.SrcPort == 53 {
		log.Info("this is DNS req ...")

		buf := pool.Get(pool.MaxSegmentSize)
		defer pool.Put(buf)

		uc.SetReadDeadline(time.Now().Add(_udpSessionTimeout))
		n, _, err := uc.ReadFrom(buf)
	    // str := string(buf[:n])
		// fmt.Println(str)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return
		} else if err == io.EOF {
			return
		} else if err != nil {
			return
		}
		dns_pdu := buf[:n]
		if _, err = pc.Write(dns_pdu); err != nil {
			log.Info(err.Error())
			return
		}
		res, err := dns.resolve(dns_pdu)
		if err != nil {
			return
		}
		fmt.Println(res)

		pc.SetReadDeadline(time.Now().Add(_udpSessionTimeout))
		uc.SetReadDeadline(time.Now().Add(_udpSessionTimeout))


		n, err = pc.Read(buf)
		// str = string(buf[:n])
		// fmt.Println(str)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return
		} else if err == io.EOF {
			return
		} else if err != nil {
			return
		}
		if _, err = uc.WriteTo(buf[:n], nil); err != nil {
			return
		}
		pc.SetReadDeadline(time.Now().Add(_udpSessionTimeout))
	}

	log.Info("[UDP] %s <-> %s", metadata.SourceAddress(), metadata.DestinationAddress())
	pipePacket(uc, pc, remote)
}

func pipePacket(origin, remote net.PacketConn, to net.Addr) {
	wg := sync.WaitGroup{}
	wg.Add(2)

	go unidirectionalPacketStream(remote, origin, to, "origin->remote", &wg)
	go unidirectionalPacketStream(origin, remote, nil, "remote->origin", &wg)

	wg.Wait()
}

func unidirectionalPacketStream(dst, src net.PacketConn, to net.Addr, dir string, wg *sync.WaitGroup) {
	defer wg.Done()
	if err := copyPacketData(dst, src, to, _udpSessionTimeout); err != nil {
		log.Debug("[UDP] copy data for %s: %v", dir, err)
	}
}

func copyPacketData(dst, src net.PacketConn, to net.Addr, timeout time.Duration) error {
	buf := pool.Get(pool.MaxSegmentSize)
	defer pool.Put(buf)

	for {
		src.SetReadDeadline(time.Now().Add(timeout))
		n, _, err := src.ReadFrom(buf)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil /* ignore I/O timeout */
		} else if err == io.EOF {
			return nil /* ignore EOF */
		} else if err != nil {
			return err
		}

		if _, err = dst.WriteTo(buf[:n], to); err != nil {
			return err
		}
		dst.SetReadDeadline(time.Now().Add(timeout))
	}
}

type symmetricNATPacketConn struct {
	net.PacketConn
	src string
	dst string
}

func newSymmetricNATPacketConn(pc net.PacketConn, metadata *Metadata) *symmetricNATPacketConn {
	return &symmetricNATPacketConn{
		PacketConn: pc,
		src:        metadata.SourceAddress(),
		dst:        metadata.DestinationAddress(),
	}
}

func (pc *symmetricNATPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, from, err := pc.PacketConn.ReadFrom(p)

		if from != nil && from.String() != pc.dst {
			log.Warning("[UDP] symmetric NAT %s->%s: drop packet from %s", pc.src, pc.dst, from)
			continue
		}

		return n, from, err
	}
}
