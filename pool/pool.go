package pool

import (
	"errors"
	"math/bits"
	"sync"
)


// 获取 32 位整数的最高 bit 位位置
func msb(size int) uint16 {
	return uint16(bits.Len32(uint32(size)) - 1)
}

var bufPool = NewPool()

type Pool struct {
	buffers []sync.Pool
}

const (
	// UDP 数据报的最大可能的长度
	MaxSegmentSize = (1 << 16) - 1

	// TCP 中继需要的缓冲区大小
	RelayBufferSize = 20 << 10
)

func NewPool() *Pool {
	bufPool := &Pool{}
	bufPool.buffers = make([]sync.Pool, 17) // 1B -> 64K
	for k := range bufPool.buffers {
		i := k
		bufPool.buffers[k].New = func() any {
			return make([]byte, 1<<uint32(i))
		}
	}
	return bufPool
}

// 调用所需 []byte 大小对应 bufPool 的 Get (若其无可用 buf，则调用它的 New 方法)
func (bufPool *Pool) Get(size int) []byte {
	if size <= 0 || size > 65536 {
		return nil
	}

	b := msb(size)
	if size == 1<<b {
		return bufPool.buffers[b].Get().([]byte)[:size]
	}

	return bufPool.buffers[b+1].Get().([]byte)[:size]
}

// 必须是 2^n 且在 1B -> 64KB 之间的 []byte 才能放回 
func (bufPool *Pool) Put(buf []byte) error {
	b := msb(cap(buf))
	if cap(buf) == 0 || cap(buf) > 65536 || cap(buf) != 1<<b {
		return errors.New("bufPool Put() buffer size must be 2^n and range(1B, 64KB)")
	}

	bufPool.buffers[b].Put(&buf)
	return nil
}


