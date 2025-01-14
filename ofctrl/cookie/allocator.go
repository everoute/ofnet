package cookie

import (
	"fmt"
	"sync"
)

const (
	BitWidthReserved        = 32
	BitWidthRoundNum        = 4
	BitWidthFlowId          = 64 - BitWidthReserved - BitWidthRoundNum
	RoundNumMask     uint64 = 0x0000_0000_f000_0000
	FlowIdMask       uint64 = 0x0000_0000_0fff_ffff
	InitFlowID       uint64 = 1
)

var FlowIDExhausted error = fmt.Errorf("flow id has exhausted")

type ID uint64

func newId(round uint64, flowId uint64) ID {
	r := uint64(0)
	r |= round << (64 - BitWidthReserved - BitWidthRoundNum)
	r |= uint64(flowId)

	return ID(r)
}

func (i ID) RawId() uint64 {
	return uint64(i)
}

func (i ID) Round() uint64 {
	return i.RawId() >> (64 - BitWidthReserved - BitWidthRoundNum)
}

type Allocator interface {
	RequestCookie() (uint64, error)
	SetFixedMask(uint64)
}

type AllocatorOption func(*allocator) error

type allocator struct {
	roundNum   uint64
	flowID     uint64
	fixedMask  uint64
	flowIDLock sync.RWMutex
	maxFlowID  uint64
}

// cookie will 'OR' fixed mask
func (a *allocator) SetFixedMask(mask uint64) {
	a.fixedMask = mask
}

func (a *allocator) RequestCookie() (uint64, error) {
	a.flowIDLock.Lock()
	defer a.flowIDLock.Unlock()

	if a.maxFlowID != 0 && a.flowID > a.maxFlowID {
		return 0, FlowIDExhausted
	}
	rawID := newId(a.roundNum, a.flowID).RawId()
	a.flowID += 1
	return rawID | a.fixedMask, nil
}

func (a *allocator) setFlowIDRange(start, end uint64) error {
	if start > end {
		return fmt.Errorf("param error, start %x can't bigger than end %x", start, end)
	}
	maxFlowIDOrigin := uint64(1<<BitWidthFlowId - 1)
	if start < InitFlowID {
		return fmt.Errorf("start %x can't small than minFlowID %x", start, InitFlowID)
	}
	if end > maxFlowIDOrigin {
		return fmt.Errorf("end %x can't biggger than maxFlowID %x", end, maxFlowIDOrigin)
	}
	a.flowID = start
	a.maxFlowID = end
	return nil
}

func (a *allocator) setDefaultFlowIDRange() {
	a.flowID = InitFlowID
	a.maxFlowID = uint64(1<<BitWidthFlowId - 1)
}

func SetFlowIDRange(start, end uint64) AllocatorOption {
	return func(a *allocator) error {
		return a.setFlowIDRange(start, end)
	}
}

func SetDefaultFlowIDRange() AllocatorOption {
	return func(a *allocator) error {
		a.setDefaultFlowIDRange()
		return nil
	}
}

func NewAllocator(roundNum uint64, options ...AllocatorOption) Allocator {
	a := &allocator{
		roundNum:   roundNum,
		flowID:     InitFlowID,
		flowIDLock: sync.RWMutex{},
	}
	for _, o := range options {
		if err := o(a); err != nil {
			return nil
		}
	}
	return a
}

func RoundCookieWithMask(roundNum uint64) (uint64, uint64) {
	return roundNum << (64 - BitWidthReserved - BitWidthRoundNum), RoundNumMask
}
