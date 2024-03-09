package wintun

import (
	"fmt"
	"io"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	offset     = 0
	defaultMTU = 0 // nt.MTU() 获取 mtu
)

type Tun struct {
	*TunEndpoint

	nt     *tun.NativeTun
	mtu    uint32
	name   string
	offset int

	rSizes []int
	rBuffs [][]byte
	wBuffs [][]byte
	rMutex sync.Mutex
	wMutex sync.Mutex
}

// Wintun 实现 io.ReadWriter 接口
var _ io.ReadWriter = (*Tun)(nil)
// Read(p []byte)
// Write(p []byte)

func (t *Tun) Read(packet []byte) (int, error) {
	t.rMutex.Lock()
	defer t.rMutex.Unlock()
	t.rBuffs[0] = packet
	_, err := t.nt.Read(t.rBuffs, t.rSizes, t.offset)
	return t.rSizes[0], err
}

func (t *Tun) Write(packet []byte) (int, error) {
	t.wMutex.Lock()
	defer t.wMutex.Unlock()
	t.wBuffs[0] = packet
	return t.nt.Write(t.wBuffs, t.offset)
}

func (t *Tun) Close() error{
	defer t.Endpoint.Close()
	return t.nt.Close()
}

func Open(name string, mtu uint32) (_ *Tun, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("open tun: %v", r)
		}
	}()

	t := &Tun{
		name:   name,
		mtu:    mtu,
		offset: offset,
		rSizes: make([]int, 1),
		rBuffs: make([][]byte, 1),
		wBuffs: make([][]byte, 1),
	}

	forcedMTU := defaultMTU
	if t.mtu > 0 {
		forcedMTU = int(t.mtu)
	}

	nt, err := tun.CreateTUN(t.name, forcedMTU)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}
	t.nt = nt.(*tun.NativeTun)

	tunMTU, err := nt.MTU()
	if err != nil {
		return nil, fmt.Errorf("get mtu: %w", err)
	}
	t.mtu = uint32(tunMTU)

	ep, err := NewTunEndpoint(t, t.mtu, offset)
	if err != nil {
		return nil, fmt.Errorf("create endpoint: %w", err)
	}
	t.TunEndpoint = ep

	return t, nil
}

