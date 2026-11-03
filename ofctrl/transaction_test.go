package ofctrl

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/contiv/libOpenflow/common"
	openflow "github.com/contiv/libOpenflow/openflow15"
	"github.com/contiv/libOpenflow/util"
)

// replaceFlowsInTransaction is a complete usage example, independent of testing
// APIs. Callers prepare the flows' match, actions and NextElem before calling it.
func replaceFlowsInTransaction(sw *OFSwitch, cookie, mask uint64, flows []*Flow) error {
	tx := sw.NewTransaction() // Atomic | Ordered by default.
	if err := tx.Begin(); err != nil {
		return err
	}
	if err := tx.DeleteFlowByCookie(cookie, mask); err != nil {
		return errors.Join(err, tx.Abort())
	}
	for _, flow := range flows {
		if err := tx.AddFlow(flow); err != nil {
			return errors.Join(err, tx.Abort())
		}
	}
	// Install handles CLOSE, Barrier, and COMMIT or DISCARD, including cleanup.
	return tx.Install()
}

// TestTransactionOVSUsage verifies the example against real OVS. Test setup,
// assertions and fallback cleanup stay here, not in the usage example above.
func TestTransactionOVSUsage(t *testing.T) {
	sw := ofActor.Switch
	output, err := sw.OutputPort(1)
	if err != nil {
		t.Fatalf("create output: %v", err)
	}

	// Prepare complete rules. Do not call Flow.Next: it sends outside the bundle.
	cookies := []uint64{0xc10001, 0xc10002, 0xc20001}
	flows := make([]*Flow, 0, len(cookies))
	for i, cookie := range cookies {
		flow, err := ofActor.inputTable.NewFlowWithFlowID(FlowMatch{
			Priority:  300,
			InputPort: uint32(31 + i),
		}, cookie)
		if err != nil {
			t.Fatalf("create flow with cookie %#x: %v", cookie, err)
		}
		flow.NextElem = output
		flows = append(flows, flow)
		// Fallback cleanup also runs if an assertion below fails. Flow.Delete
		// is not suitable here: bundle operations do not set isInstalled.
		t.Cleanup(func() {
			if err := DeleteFlow(flow.Table, flow.Match.Priority, flow.FlowID); err != nil {
				t.Errorf("cleanup flow with cookie %#x: %v", flow.FlowID, err)
			}
		})
	}

	if err := replaceFlowsInTransaction(sw, 0xc10000, 0xffff0000, flows[:2]); err != nil {
		t.Fatalf("install initial flows: %v", err)
	}

	dump, err := ofctlFlowDump("ovsbr11")
	if err != nil {
		t.Fatalf("dump flows after add: %v", err)
	}
	for i, cookie := range cookies {
		if got, want := ofctlFlowMatchCookieID(dump, cookie), i < 2; got != want {
			t.Errorf("initial cookie %#x present=%v, want %v", cookie, got, want)
		}
	}
	if !ofctlFlowMatch(dump, 0, "priority=300,in_port=31", "output:1") ||
		!ofctlFlowMatch(dump, 0, "priority=300,in_port=32", "output:1") {
		t.Error("initial flows have missing or incorrect match/actions")
	}
	// Replace both old flows in one transaction, using the same example function.
	if err := replaceFlowsInTransaction(sw, 0xc10000, 0xffff0000, flows[2:]); err != nil {
		t.Fatalf("replace flows: %v", err)
	}
	dump, err = ofctlFlowDump("ovsbr11")
	if err != nil {
		t.Fatalf("dump flows after delete: %v", err)
	}
	for i, cookie := range cookies {
		if got, want := ofctlFlowMatchCookieID(dump, cookie), i == 2; got != want {
			t.Errorf("replacement cookie %#x present=%v, want %v", cookie, got, want)
		}
	}
	if !ofctlFlowMatch(dump, 0, "priority=300,in_port=33", "output:1") {
		t.Error("replacement flow has missing or incorrect match/actions")
	}
	for _, flow := range flows {
		if flow.isInstalled {
			t.Error("bundle changed the Flow object's installed state")
		}
	}
}

// TestBundleRejectsWholeBundle checks that an ADD rejected by OVS prevents
// every other flow in that transaction from being committed.
func TestBundleRejectsWholeBundle(t *testing.T) {
	output, err := ofActor.Switch.OutputPort(1)
	if err != nil {
		t.Fatalf("create output: %v", err)
	}
	good, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  301,
		InputPort: 41,
	})
	if err != nil {
		t.Fatalf("create valid flow: %v", err)
	}
	good.NextElem = output
	t.Cleanup(func() {
		if err := DeleteFlow(good.Table, good.Match.Priority, good.FlowID); err != nil {
			t.Errorf("cleanup valid flow: %v", err)
		}
	})
	// Table 255 is invalid for FC_ADD.
	bad := &Flow{
		Table:    &Table{Switch: ofActor.Switch, TableId: 255},
		Match:    FlowMatch{Priority: 301, InputPort: 42},
		NextElem: output,
	}
	tx := beginOVSBundle(t)
	for _, flow := range []*Flow{good, bad} {
		if err := tx.AddFlow(flow); err != nil {
			t.Fatalf("queue flow: %v", err)
		}
	}
	if err := tx.Install(); err == nil {
		t.Fatal("Install succeeded, want rejection of the invalid flow")
	}
	dump, err := ofctlFlowDump("ovsbr11")
	if err != nil {
		t.Fatalf("dump rejected bundle flows: %v", err)
	}
	if ofctlFlowMatch(dump, 0, "priority=301,in_port=41", "output:1") {
		t.Error("valid flow was installed although its bundle was rejected")
	}
	if good.isInstalled || bad.isInstalled {
		t.Error("rejected transaction changed local installed state")
	}
}

func TestBundleMixedAddAndDelete(t *testing.T) {
	output, err := ofActor.Switch.OutputPort(1)
	if err != nil {
		t.Fatal(err)
	}
	cookies := []uint64{0xb10001, 0xb20001, 0xb20002, 0xb30001, 0xb40001}
	flows := make([]*Flow, 0, len(cookies))
	for i, cookie := range cookies {
		table := ofActor.inputTable
		if i == 2 {
			// Cookie deletion must cover matching flows in other tables too.
			table = ofActor.nextTable
		}
		flow, err := table.NewFlowWithFlowID(FlowMatch{
			Priority:  302,
			InputPort: uint32(61 + i),
		}, cookie)
		if err != nil {
			t.Fatal(err)
		}
		flow.NextElem = output
		flows = append(flows, flow)
		t.Cleanup(func() {
			if err := DeleteFlow(flow.Table, flow.Match.Priority, flow.FlowID); err != nil {
				t.Errorf("cleanup flow failed: %v", err)
			}
		})
	}
	initial := beginOVSBundle(t)
	for _, flow := range flows[:4] {
		if err := initial.AddFlow(flow); err != nil {
			t.Fatal(err)
		}
		if flow.isInstalled {
			t.Fatal("flow marked installed before Install")
		}
	}
	if err := initial.Install(); err != nil {
		t.Fatal(err)
	}

	// A failed bundle must preserve the existing flow in OVS.
	failed := beginOVSBundle(t)
	if err := failed.DeleteFlow(flows[0]); err != nil {
		t.Fatal(err)
	}
	bad := &Flow{
		Table:    &Table{Switch: ofActor.Switch, TableId: 255},
		Match:    FlowMatch{Priority: 302, InputPort: 66},
		NextElem: output,
	}
	if err := failed.AddFlow(bad); err != nil {
		t.Fatal(err)
	}
	if err := failed.Install(); err == nil {
		t.Fatal("invalid mixed bundle succeeded")
	}
	dump, err := ofctlFlowDump("ovsbr11")
	if err != nil {
		t.Fatal(err)
	}
	if !ofctlFlowMatchCookieID(dump, cookies[0]) {
		t.Fatal("failed bundle deleted the existing flow")
	}

	mixed := beginOVSBundle(t)
	if err := mixed.DeleteFlow(flows[0]); err != nil {
		t.Fatal(err)
	}
	if err := mixed.DeleteFlowByCookie(0xb20000, 0xffff0000); err != nil {
		t.Fatal(err)
	}
	if err := mixed.AddFlow(flows[4]); err != nil {
		t.Fatal(err)
	}
	if flows[0].isInstalled || flows[4].isInstalled {
		t.Fatal("queued operations changed local state before Install")
	}
	if err := mixed.Install(); err != nil {
		t.Fatal(err)
	}
	dump, err = ofctlFlowDump("ovsbr11")
	if err != nil {
		t.Fatal(err)
	}
	for i, cookie := range cookies {
		want := i >= 3
		if got := ofctlFlowMatchCookieID(dump, cookie); got != want {
			t.Errorf("cookie %#x present=%v, want %v", cookie, got, want)
		}
	}
	for _, flow := range flows {
		if flow.isInstalled {
			t.Fatal("bundle changed a Flow object's installed state")
		}
	}
}

type bundleRequest struct {
	kind uint8
	ctrl uint16
}

func TestNewTransactionFlags(t *testing.T) {
	sw := &OFSwitch{ctx: context.Background()}
	for _, tt := range []struct {
		name  string
		flags []TransactionFlag
		want  TransactionFlag
	}{
		{name: "default", want: Atomic | Ordered},
		{name: "atomic only", flags: []TransactionFlag{Atomic}, want: Atomic},
		{name: "combined", flags: []TransactionFlag{Atomic, Ordered}, want: Atomic | Ordered},
		{name: "no flags", flags: []TransactionFlag{0}, want: 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tx := sw.NewTransaction(tt.flags...)
			defer tx.finish()
			if tx.flag != tt.want {
				t.Errorf("flags=%d, want %d", tx.flag, tt.want)
			}
		})
	}
}

func beginOVSBundle(t *testing.T) *Transaction {
	t.Helper()
	tx := ofActor.Switch.NewTransaction(Atomic | Ordered)
	if err := tx.Begin(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if tx.ctx.Err() == nil {
			if err := tx.Abort(); err != nil {
				t.Errorf("Abort failed: %v", err)
			}
		}
	})
	return tx
}

func TestBundleAddFlowAlwaysUsesAdd(t *testing.T) {
	s := &OFSwitch{
		ctx: context.Background(),
		stream: &util.MessageStream{
			Outbound: make(chan util.Message, 1),
		},
	}
	tx := s.NewTransaction(Atomic)
	defer tx.finish()
	// Isolate message construction from the OPEN handshake.
	tx.begun = true
	flow := &Flow{
		Table:    &Table{Switch: s},
		NextElem: NewEmptyElem(),
	}
	for _, installed := range []bool{false, true} {
		flow.isInstalled = installed
		if err := tx.AddFlow(flow); err != nil {
			t.Fatal(err)
		}
		msg := (<-s.stream.Outbound).(*openflow.BndleAdd)
		mod := msg.Message.(*openflow.FlowMod)
		if mod.Command != openflow.FC_ADD {
			t.Fatalf("installed=%v: got command %d, want FC_ADD", installed, mod.Command)
		}
		if flow.isInstalled != installed {
			t.Fatal("AddFlow changed the Flow object's installed state")
		}
	}
}

func TestPublishResultStopsWhenTransactionEnds(t *testing.T) {
	for _, barrier := range []bool{false, true} {
		name := "bundle"
		if barrier {
			name = "barrier"
		}
		t.Run(name, func(t *testing.T) {
			s := &OFSwitch{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			subscription := messageSubscription{
				replyCh: make(chan MessageResult, 1),
				done:    ctx.Done(),
			}
			// Leave the subscription reachable to model a publisher that already
			// obtained it before the transaction unsubscribed.
			subscription.replyCh <- MessageResult{}
			if barrier {
				s.subscribeBarrier(1, subscription)
			} else {
				s.subscribeMessage(1, subscription)
			}
			finished := make(chan struct{})
			go func() {
				if barrier {
					s.publishBarrier(1, MessageResult{})
				} else {
					s.publishMessage(1, MessageResult{})
				}
				close(finished)
			}()
			// Closing the transaction must release a publisher even when its
			// destination channel has no space and no receiver.
			cancel()
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("publisher remained blocked after transaction ended")
			}
		})
	}
}

func TestTransactionDisconnectCleansSubscription(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &OFSwitch{ctx: ctx}
	tx := s.NewTransaction(Atomic)
	defer tx.finish()
	s.subscribeMessage(tx.ID, messageSubscription{
		replyCh: tx.replyCh,
		done:    tx.ctx.Done(),
	})
	finished := make(chan struct{})
	go func() {
		tx.listenReply()
		close(finished)
	}()
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("transaction listener did not exit after disconnect")
	}
	s.txLock.Lock()
	defer s.txLock.Unlock()
	if len(s.txChans) != 0 {
		t.Fatal("transaction subscription remains after disconnect")
	}
}

func TestTransactionContextLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &OFSwitch{ctx: ctx}
	first := s.NewTransaction(Atomic)
	defer first.finish()
	second := s.NewTransaction(Atomic)
	defer second.finish()

	first.finish()
	if first.ctx.Err() != context.Canceled {
		t.Fatal("finished transaction is not canceled")
	}
	if err := first.waitControlReply(1); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting on a finished transaction returned %v, want cancellation", err)
	}
	if ctx.Err() != nil || second.ctx.Err() != nil {
		t.Fatal("finishing one transaction canceled its switch or sibling")
	}
	cancel()
	if second.ctx.Err() != context.Canceled {
		t.Fatal("switch cancellation did not cancel its transaction")
	}
}

// newFakeBundleSwitch returns a switch whose outbound bundle messages are
// answered in place. failAddIndex selects the add message (1-based) that the
// fake switch rejects; zero means no add message fails.
func newFakeBundleSwitch(t *testing.T, failAddIndex int) (*OFSwitch, *[]bundleRequest) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	s := &OFSwitch{
		stream:  &util.MessageStream{Outbound: make(chan util.Message, 100)},
		ctx:     ctx,
		cancel:  cancel,
		txChans: make(map[uint32]messageSubscription),
	}

	var (
		lock     sync.Mutex
		requests []bundleRequest
		adds     int
	)
	go func() {
		for msg := range s.stream.Outbound {
			switch m := msg.(type) {
			case *openflow.BundleCtrl:
				lock.Lock()
				requests = append(requests, bundleRequest{kind: openflow.Type_BundleControl, ctrl: m.Type})
				lock.Unlock()

				reply := openflow.NewBundleCtrl(m.BundleId, m.Type+1, m.Flags)
				reply.Header.Xid = m.Header.Xid
				s.handleMessages(nil, reply)
			case *common.Header:
				if m.Type != openflow.Type_BarrierRequest {
					continue
				}
				lock.Lock()
				requests = append(requests, bundleRequest{kind: openflow.Type_BarrierRequest})
				lock.Unlock()

				reply := openflow.NewBarrierReply()
				reply.Xid = m.Xid
				s.handleMessages(nil, reply)
			case *openflow.BndleAdd:
				lock.Lock()
				requests = append(requests, bundleRequest{kind: openflow.Type_BundleAddMessage})
				adds++
				fail := adds == failAddIndex
				lock.Unlock()

				if fail {
					raw, err := m.MarshalBinary()
					if err != nil {
						t.Errorf("failed to marshal bundle add: %v", err)
						continue
					}
					errMsg := openflow.NewErrorMsg()
					errMsg.Xid = m.Header.Xid
					errMsg.Type = openflow.ET_BUNDLE_FAILED
					errMsg.Code = openflow.BEC_MSG_FAILD
					errMsg.Data = *util.NewBuffer(raw)
					s.handleMessages(nil, errMsg)
				}
			}
		}
	}()

	return s, &requests
}

func TestTransactionCommitAppliesAllFlows(t *testing.T) {
	s, requests := newFakeBundleSwitch(t, 0)

	tx := s.NewTransaction(Atomic)
	if err := tx.Begin(); err != nil {
		t.Fatalf("Begin failed: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := tx.addFlowMod(openflow.NewFlowMod()); err != nil {
			t.Fatalf("AddFlow failed: %v", err)
		}
	}
	if err := tx.Install(); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	want := []bundleRequest{
		{kind: openflow.Type_BundleControl, ctrl: openflow.OFPBCT_OPEN_REQUEST},
		{kind: openflow.Type_BundleAddMessage},
		{kind: openflow.Type_BundleAddMessage},
		{kind: openflow.Type_BundleControl, ctrl: openflow.OFPBCT_CLOSE_REQUEST},
		{kind: openflow.Type_BarrierRequest},
		{kind: openflow.Type_BundleControl, ctrl: openflow.OFPBCT_COMMIT_REQUEST},
	}
	if len(*requests) != len(want) {
		t.Fatalf("got %d requests %+v, want %d", len(*requests), *requests, len(want))
	}
	for i := range want {
		if (*requests)[i] != want[i] {
			t.Fatalf("request %d: got %+v, want %+v", i, (*requests)[i], want[i])
		}
	}
}

func TestTransactionAddFailureBlocksCommit(t *testing.T) {
	s, requests := newFakeBundleSwitch(t, 2)

	tx := s.NewTransaction(Atomic)
	if err := tx.Begin(); err != nil {
		t.Fatalf("Begin failed: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := tx.addFlowMod(openflow.NewFlowMod()); err != nil {
			t.Fatalf("AddFlow failed: %v", err)
		}
	}
	if err := tx.Install(); err == nil {
		t.Fatalf("Install succeeded, want error for failed bundle add")
	}

	for _, r := range *requests {
		if r.kind == openflow.Type_BundleControl && r.ctrl == openflow.OFPBCT_COMMIT_REQUEST {
			t.Fatalf("commit was sent after a failed bundle add: %+v", *requests)
		}
	}
	last := (*requests)[len(*requests)-1]
	if last.ctrl != openflow.OFPBCT_DISCARD_REQUEST {
		t.Fatalf("last request %+v, want discard", last)
	}
}

func TestWaitControlReplyDiscardsStaleReply(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &OFSwitch{ctx: ctx}
	tx := s.NewTransaction(Atomic)

	tx.controlCh = make(chan MessageResult, 2)
	tx.controlCh <- MessageResult{
		succeed: false,
		xID:     1,
		errCode: openflow.BEC_UNKNOWN,
		msgType: BundleControlResult,
	}
	tx.controlCh <- MessageResult{
		succeed: true,
		xID:     2,
		msgType: BundleControlResult,
	}

	if err := tx.waitControlReply(2); err != nil {
		t.Fatalf("waitControlReply(2) returned %v, want nil after discarding the stale reply", err)
	}
}

func TestBundleXidSharesOpenFlowAllocator(t *testing.T) {
	seen := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		for _, xid := range []uint32{openflow.NewFlowMod().Xid, nextBundleXid(), openflow.NewEchoRequest().Xid} {
			if xid == 0 || seen[xid] {
				t.Fatalf("unexpected zero or duplicate xid: %d", xid)
			}
			seen[xid] = true
		}
	}
}
