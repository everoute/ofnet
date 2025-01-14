package cookie

import (
	"sync"
)

const (
	BitWidthReserved        = 32
	BitWidthRoundNum        = 4
	BitWidthFlowId          = 64 - BitWidthReserved - BitWidthRoundNum
	RoundNumMask     uint64 = 0x0000_0000_f000_0000
	FlowIdMask       uint64 = 0x0000_0000_0fff_ffff
)

type ID uint64

func (a *allocator) newId() ID {
	r := uint64(0)
	r |= a.roundNum << (64 - BitWidthReserved - BitWidthRoundNum)
	if a.bussinessBit > 0 {
		r |= a.bussinessNum << (64 - BitWidthReserved - BitWidthRoundNum - a.bussinessBit)
	}
	r |= uint64(a.flowID)

	return ID(r)
}

func (i ID) RawId() uint64 {
	return uint64(i)
}

func (i ID) Round() uint64 {
	return i.RawId() >> (64 - BitWidthReserved - BitWidthRoundNum)
}

type Allocator interface {
	RequestCookie() uint64
	SetFixedMask(uint64)
}

type allocator struct {
	roundNum     uint64
	flowID       uint64
	fixedMask    uint64
	bussinessNum uint64
	bussinessBit uint8
	flowIDLock   sync.RWMutex
}

// cookie will 'OR' fixed mask
func (a *allocator) SetFixedMask(mask uint64) {
	a.fixedMask = mask
}

func (a *allocator) RequestCookie() uint64 {
	a.flowIDLock.Lock()
	defer a.flowIDLock.Unlock()

	rawID := a.newId().RawId()
	a.flowID += 1
	return rawID | a.fixedMask
}

func NewAllocator(roundNum uint64) Allocator {
	a := &allocator{
		roundNum:   roundNum,
		flowID:     1,
		flowIDLock: sync.RWMutex{},
	}
	return a
}

func NewAllocatorWithBussinessBit(roundNum uint64, bussinessNum uint64, bussinessBit uint8) Allocator {
	if bussinessNum >= 1<<bussinessBit {
		return nil
	}
	a := &allocator{
		roundNum:     roundNum,
		flowID:       1,
		flowIDLock:   sync.RWMutex{},
		bussinessNum: bussinessNum,
		bussinessBit: bussinessBit,
	}

	return a
}

func RoundCookieWithMask(roundNum uint64) (uint64, uint64) {
	return roundNum << (64 - BitWidthReserved - BitWidthRoundNum), RoundNumMask
}
