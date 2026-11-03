package ofctrl

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	openflow "github.com/contiv/libOpenflow/openflow15"
	log "github.com/sirupsen/logrus"
)

type MessageType int

// These values classify internal results, not OpenFlow wire message types.
const (
	UnknownResult MessageType = iota
	BundleControlResult
	BundleAddError
	BarrierReply
)

type MessageResult struct {
	succeed bool
	errType uint16
	errCode uint16
	xID     uint32
	msgType MessageType
}

type TransactionFlag uint16

const (
	Atomic  = TransactionFlag(openflow.OFPBCT_ATOMIC)
	Ordered = TransactionFlag(openflow.OFPBCT_ORDERED)
)

var bundleIDCounter uint32

// Transaction groups OpenFlow messages into one OpenFlow 1.5 bundle. Messages
// added between Begin and Install take effect together at commit, or are
// discarded with Abort.
//
// Transaction operations must be called serially. After Begin succeeds, the
// caller must end the transaction with Install or Abort. Each AddFlow call
// builds a message from the current Flow contents; transactions do not maintain
// the Flow object's isInstalled state.
type Transaction struct {
	ofSwitch *OFSwitch
	ID       uint32
	flag     TransactionFlag
	closed   bool // Accessed only by serial transaction operations, not the reply listener.
	begun    bool
	queueErr error

	replyCh   chan MessageResult
	controlCh chan MessageResult
	ctx       context.Context
	cancel    context.CancelFunc

	lock   sync.Mutex
	addErr error
}

// NewTransaction creates an atomic, ordered bundle by default. Optional flags
// override the default; multiple flags are combined with bitwise OR.
func (s *OFSwitch) NewTransaction(flags ...TransactionFlag) *Transaction {
	flag := Atomic | Ordered
	if len(flags) != 0 {
		flag = 0
		for _, value := range flags {
			flag |= value
		}
	}
	ctx, cancel := context.WithCancel(s.ctx)
	return &Transaction{
		ofSwitch:  s,
		ID:        atomic.AddUint32(&bundleIDCounter, 1),
		flag:      flag,
		replyCh:   make(chan MessageResult, 64),
		controlCh: make(chan MessageResult, 1),
		ctx:       ctx,
		cancel:    cancel,
	}
}

func (tx *Transaction) Begin() error {
	if tx.begun || tx.ctx.Err() != nil {
		return fmt.Errorf("transaction %d cannot begin again", tx.ID)
	}
	tx.ofSwitch.subscribeMessage(tx.ID, messageSubscription{
		replyCh: tx.replyCh,
		done:    tx.ctx.Done(),
	})
	go tx.listenReply()

	if err := tx.sendControl(openflow.OFPBCT_OPEN_REQUEST); err != nil {
		tx.finish()
		return err
	}
	tx.begun = true
	return nil
}

// AddFlow queues an FC_ADD message, regardless of flow.isInstalled; it never
// selects FC_MODIFY or updates the Flow object's installed state. Set NextElem
// before calling AddFlow; calling Flow.Next would install outside the bundle.
func (tx *Transaction) AddFlow(flow *Flow) error {
	if err := tx.checkFlow(flow); err != nil {
		tx.queueErr = err
		return err
	}
	flow.lock.Lock()
	defer flow.lock.Unlock()
	if flow.NextElem == nil {
		err := fmt.Errorf("flow %d has no next fgraph element", flow.FlowID)
		tx.queueErr = err
		return err
	}
	flowMod, err := flow.buildFlowMod()
	if err != nil {
		log.Errorf("failed to build flow %d for bundle %d: %v", flow.FlowID, tx.ID, err)
		tx.queueErr = err
		return err
	}
	flowMod.Command = openflow.FC_ADD
	return tx.addFlowMod(flowMod)
}

// DeleteFlow queues FC_DELETE by table and exact cookie, without checking or
// updating the Flow object's installed state.
func (tx *Transaction) DeleteFlow(flow *Flow) error {
	if err := tx.checkFlow(flow); err != nil {
		tx.queueErr = err
		return err
	}
	flow.lock.Lock()
	defer flow.lock.Unlock()
	return tx.deleteFlowByCookie(flow.Table.TableId, flow.FlowID, ^uint64(0))
}

// DeleteFlowByCookie queues deletion of matching cookies across all tables.
// A zero mask matches every cookie.
// It does not update any Flow object's installed state.
func (tx *Transaction) DeleteFlowByCookie(cookie, mask uint64) error {
	return tx.deleteFlowByCookie(openflow.OFPTT_ALL, cookie, mask)
}

// Install closes the bundle, synchronizes add results with a barrier, and
// commits it. Preparation or add failures cause the bundle to be discarded.
// Atomic guarantees for commit-time failures require the Atomic flag.
func (tx *Transaction) Install() error {
	if !tx.begun || tx.ctx.Err() != nil {
		return fmt.Errorf("transaction %d is not open", tx.ID)
	}
	defer tx.finish()

	err := tx.queueErr
	if err == nil {
		err = tx.complete()
	}
	if err != nil {
		log.Errorf("failed to prepare bundle %d for commit: %v", tx.ID, err)
		if abortErr := tx.Abort(); abortErr != nil {
			log.Errorf("failed to discard bundle %d after preparation failed: %v", tx.ID, abortErr)
		}
		return err
	}
	if err := tx.sendControl(openflow.OFPBCT_COMMIT_REQUEST); err != nil {
		log.Errorf("failed to commit bundle %d: %v", tx.ID, err)
		return err
	}
	log.Infof("successfully installed bundle %d on switch %v", tx.ID, tx.ofSwitch.DPID())
	return nil
}

// Abort discards the bundle on the switch, whether or not it is completed.
func (tx *Transaction) Abort() error {
	defer tx.finish()

	return tx.sendControl(openflow.OFPBCT_DISCARD_REQUEST)
}

func nextBundleXid() uint32 {
	// Share the library's allocator with ordinary OpenFlow messages instead of
	// allocating bundle xids from a separate, potentially overlapping counter.
	for {
		xid := openflow.NewOfp15Header().Xid
		if xid != 0 {
			return xid
		}
	}
}

func (tx *Transaction) deleteFlowByCookie(tableID uint8, cookie, mask uint64) error {
	flowMod := openflow.NewFlowMod()
	flowMod.Command = openflow.FC_DELETE
	flowMod.TableId = tableID
	flowMod.Cookie = cookie
	flowMod.CookieMask = mask
	flowMod.OutPort = openflow.P_ANY
	flowMod.OutGroup = openflow.OFPG_ANY
	return tx.addFlowMod(flowMod)
}

func (tx *Transaction) checkFlow(flow *Flow) error {
	if flow == nil || flow.Table == nil || flow.Table.Switch != tx.ofSwitch {
		return fmt.Errorf("flow does not belong to transaction %d switch", tx.ID)
	}
	return nil
}

func (tx *Transaction) addFlowMod(flowMod *openflow.FlowMod) error {
	if !tx.begun || tx.closed || tx.ctx.Err() != nil {
		return fmt.Errorf("transaction %d is not open", tx.ID)
	}
	if tx.queueErr != nil {
		return tx.queueErr
	}
	xid := nextBundleXid()
	flowMod.Xid = xid
	msg := openflow.NewBndleAdd(tx.ID, uint16(tx.flag))
	msg.Message = flowMod
	msg.Header.Xid = xid
	if err := tx.ofSwitch.Send(msg); err != nil {
		log.Errorf("failed to send flow mod in bundle %d: %v", tx.ID, err)
		tx.queueErr = err
		return err
	}
	return nil
}

// complete closes the bundle and waits until the switch has processed every
// message added so far. It returns an error if the switch rejected any of them.
func (tx *Transaction) complete() error {
	if tx.closed {
		return nil
	}
	if err := tx.sendControl(openflow.OFPBCT_CLOSE_REQUEST); err != nil {
		return err
	}
	if err := tx.sendBarrier(); err != nil {
		return err
	}
	tx.closed = true
	return tx.getAddErr()
}

func (tx *Transaction) sendControl(msgType uint16) error {
	xid := nextBundleXid()
	msg := openflow.NewBundleCtrl(tx.ID, msgType, uint16(tx.flag))
	msg.Header.Xid = xid
	if err := tx.ofSwitch.Send(msg); err != nil {
		return err
	}
	return tx.waitControlReply(xid)
}

// sendBarrier waits until the switch has processed all messages sent before
// it. Errors for earlier bundle messages are routed through replyCh ahead of
// the barrier reply, so they are recorded before the barrier returns.
func (tx *Transaction) sendBarrier() error {
	xid := nextBundleXid()
	msg := openflow.NewBarrierRequest()
	msg.Xid = xid
	tx.ofSwitch.subscribeBarrier(xid, messageSubscription{
		replyCh: tx.replyCh,
		done:    tx.ctx.Done(),
	})
	defer tx.ofSwitch.unsubscribeBarrier(xid)

	if err := tx.ofSwitch.Send(msg); err != nil {
		return err
	}
	return tx.waitControlReply(xid)
}

// waitControlReply waits for the reply to the request with the given xid.
// Replies to other requests, such as late replies to a request that already
// timed out, are discarded.
func (tx *Transaction) waitControlReply(xid uint32) error {
	timeout := time.After(messageTimeout)
	for {
		select {
		case reply := <-tx.controlCh:
			if reply.xID != xid {
				log.Warnf("bundle %d discards reply with xid %d while waiting for xid %d", tx.ID, reply.xID, xid)
				continue
			}
			if reply.succeed {
				return nil
			}
			return tx.bundleError(reply)
		case <-timeout:
			return fmt.Errorf("bundle %d reply is timeout", tx.ID)
		case <-tx.ctx.Done():
			return fmt.Errorf("bundle %d reply is canceled: %w", tx.ID, tx.ctx.Err())
		}
	}
}

// listenReply records bundle add failures as they arrive and hands control and
// barrier replies to the waiting sender. Replies are processed in the order the
// switch sent them, so a barrier reply is only forwarded after every earlier
// add failure has been recorded.
func (tx *Transaction) listenReply() {
	defer tx.finish()
	for {
		select {
		case reply := <-tx.replyCh:
			switch reply.msgType {
			case BundleControlResult, BarrierReply:
				select {
				case tx.controlCh <- reply:
				case <-tx.ctx.Done():
					return
				}
			case BundleAddError:
				err := tx.bundleError(reply)
				tx.lock.Lock()
				if tx.addErr == nil {
					tx.addErr = err
				}
				tx.lock.Unlock()
			}
		case <-tx.ctx.Done():
			return
		}
	}
}

func (tx *Transaction) getAddErr() error {
	tx.lock.Lock()
	defer tx.lock.Unlock()
	return tx.addErr
}

func (tx *Transaction) bundleError(reply MessageResult) error {
	err := openflow.ParseBundleError(reply.errCode)
	if err == nil {
		err = fmt.Errorf("unsupported bundle error with type %d and code %d", reply.errType, reply.errCode)
	}
	log.Errorf("bundle %d failed: type %d, code %d, err: %v", tx.ID, reply.errType, reply.errCode, err)
	return err
}

func (tx *Transaction) finish() {
	tx.cancel()
	tx.ofSwitch.unsubscribeMessage(tx.ID)
}
