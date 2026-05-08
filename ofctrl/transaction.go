package ofctrl

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	openflow "antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/util"
	log "github.com/sirupsen/logrus"
)

type TransactionFlag uint16

func (f TransactionFlag) getValue() uint16 {
	return uint16(f)
}

const (
	Atomic  = TransactionFlag(openflow.OFPBCT_ATOMIC)
	Ordered = TransactionFlag(openflow.OFPBCT_ORDERED)
)

var transactionUID uint32 = 1

type OpenFlowModMessage interface {
	resetXid(xid uint32) util.Message
	getXid() uint32
	GetMessage() util.Message
}

type Transaction struct {
	ofSwitch *OFSwitch
	ID       uint32
	flag     TransactionFlag
	closed   bool
	lock     sync.Mutex

	successAdd     map[uint32]bool
	controlReplyCh chan MessageResult
	controlIntCh   chan MessageResult
}

func (s *OFSwitch) NewTransaction(flag TransactionFlag) *Transaction {
	tx := &Transaction{
		ID:             atomic.AddUint32(&transactionUID, 1),
		flag:           flag,
		ofSwitch:       s,
		controlReplyCh: make(chan MessageResult, 10),
		controlIntCh:   make(chan MessageResult, 1),
	}
	return tx
}

func (tx *Transaction) getError(reply MessageResult) error {
	errType := reply.GetErrorType()
	errCode := reply.GetErrorCode()
	if (errType == openflow.ET_BUNDLE_FAILED || errType == openflow.ET_EXPERIMENTER) &&
		errCode >= openflow.BEC_UNKNOWN && errCode <= openflow.BEC_BUNDLE_IN_PROCESS {
		return openflow.ParseBundleError(reply.GetErrorCode())
	}
	return fmt.Errorf("unsupported bundle error with type %d and code %d", errType, errCode)
}

func (tx *Transaction) sendControlRequest(msg util.Message) error {
	if err := tx.ofSwitch.Send(msg); err != nil {
		return err
	}
	select {
	case reply := <-tx.controlIntCh:
		if reply.IsSucceed() {
			return nil
		}
		return tx.getError(reply)
	case <-time.After(messageTimeout):
		return fmt.Errorf("bundle reply is timeout")
	case <-tx.ofSwitch.ctx.Done():
		return fmt.Errorf("bundle reply is canceled because of disconnection from the Switch")
	}
}

func (tx *Transaction) newBundleControlMessage(msgType uint16) *openflow.BundleCtrl {
	message := openflow.NewBundleCtrl(tx.ID, msgType, tx.flag.getValue())
	log.Debugf("newBundleControlMessage XID: %x", message.Xid)
	return message
}

func (tx *Transaction) createBundleAddMessage(mod OpenFlowModMessage) (*openflow.BndleAdd, error) {
	message := openflow.NewBndleAdd(tx.ID, tx.flag.getValue())
	message.Message = mod.resetXid(message.Xid)
	log.Debugf("createBundleAddMessage XID: %x %x", message.Xid, mod.getXid())
	return message, nil
}

func (tx *Transaction) createBundleAddFlowMessage(flowMod *openflow.FlowMod) (*openflow.BndleAdd, error) {
	message := openflow.NewBndleAdd(tx.ID, tx.flag.getValue())
	flowMod.Xid = message.Xid
	message.Message = flowMod
	return message, nil
}

func (tx *Transaction) listenReply() {
	for reply := range tx.controlReplyCh {
		switch reply.msgType {
		case BundleControlMessage:
			select {
			case tx.controlIntCh <- reply:
			case <-time.After(messageTimeout):
				log.Warningln("BundleControlMessage reply message accept timeout")
			}
		case BundleAddMessage:
			if !reply.succeed {
				tx.lock.Lock()
				delete(tx.successAdd, reply.xID)
				tx.lock.Unlock()
			}
		}
	}
}

func (tx *Transaction) Begin() error {
	message := tx.newBundleControlMessage(openflow.OFPBCT_OPEN_REQUEST)
	tx.ofSwitch.subscribeMessage(tx.ID, tx.controlReplyCh)
	tx.successAdd = make(map[uint32]bool)
	go tx.listenReply()

	if err := tx.sendControlRequest(message); err != nil {
		tx.ofSwitch.unSubscribeMessage(tx.ID)
		close(tx.controlReplyCh)
		return err
	}
	return nil
}

func (tx *Transaction) AddFlow(flowMod *openflow.FlowMod) error {
	if tx.closed {
		return fmt.Errorf("transaction %d is complete", tx.ID)
	}
	if tx.successAdd == nil {
		return fmt.Errorf("transaction %d is not begun", tx.ID)
	}
	message, err := tx.createBundleAddFlowMessage(flowMod)
	if err != nil {
		return err
	}
	tx.lock.Lock()
	tx.successAdd[message.Xid] = true
	tx.lock.Unlock()
	return tx.ofSwitch.Send(message)
}

func (tx *Transaction) AddMessage(modMessage OpenFlowModMessage) error {
	if tx.closed {
		return fmt.Errorf("transaction %d is complete", tx.ID)
	}
	if tx.successAdd == nil {
		return fmt.Errorf("transaction %d is not begun", tx.ID)
	}
	message, err := tx.createBundleAddMessage(modMessage)
	if err != nil {
		return err
	}
	tx.lock.Lock()
	tx.successAdd[message.Xid] = true
	tx.lock.Unlock()
	log.Debugf("AddMessage: Xid: 0x%x", message.Xid)
	return tx.ofSwitch.Send(message)
}

func (tx *Transaction) Complete() (int, error) {
	if !tx.closed {
		msg := tx.newBundleControlMessage(openflow.OFPBCT_CLOSE_REQUEST)
		if err := tx.sendControlRequest(msg); err != nil {
			return 0, err
		}
		tx.closed = true
	}
	tx.lock.Lock()
	defer tx.lock.Unlock()
	return len(tx.successAdd), nil
}

func (tx *Transaction) Commit() error {
	if !tx.closed {
		return fmt.Errorf("transaction %d is not complete", tx.ID)
	}
	defer func() {
		tx.ofSwitch.unSubscribeMessage(tx.ID)
		close(tx.controlReplyCh)
	}()
	msg := tx.newBundleControlMessage(openflow.OFPBCT_COMMIT_REQUEST)
	return tx.sendControlRequest(msg)
}

func (tx *Transaction) Abort() error {
	if !tx.closed {
		return fmt.Errorf("transaction %d is not complete", tx.ID)
	}
	defer func() {
		tx.ofSwitch.unSubscribeMessage(tx.ID)
		close(tx.controlReplyCh)
	}()
	msg := tx.newBundleControlMessage(openflow.OFPBCT_DISCARD_REQUEST)
	return tx.sendControlRequest(msg)
}
