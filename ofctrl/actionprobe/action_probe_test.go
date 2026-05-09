package actionprobe_test

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	openflow "antrea.io/libOpenflow/openflow15"
	"github.com/contiv/ofnet/ofctrl"
)

type probeApp struct {
	swCh chan *ofctrl.OFSwitch
}

type staticAction struct {
	actionType string
	action     openflow.Action
}

func (a staticAction) GetActionType() string {
	return a.actionType
}

func (a staticAction) ToOfAction() (openflow.Action, error) {
	return a.action, nil
}

func (a *probeApp) PacketRcvd(sw *ofctrl.OFSwitch, pkt *ofctrl.PacketIn) {}

func (a *probeApp) SwitchConnected(sw *ofctrl.OFSwitch) {
	select {
	case a.swCh <- sw:
	default:
	}
}

func (a *probeApp) MultipartReply(sw *ofctrl.OFSwitch, rep *openflow.MultipartReply) {}

func (a *probeApp) SwitchDisconnected(sw *ofctrl.OFSwitch) {}

func runOVS(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("ovs-vsctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ovs-vsctl %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func runOfctl(t *testing.T, args ...string) string {
	t.Helper()
	cmdArgs := append([]string{"-O", "OpenFlow15"}, args...)
	cmd := exec.Command("ovs-ofctl", cmdArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ovs-ofctl %s failed: %v\n%s", strings.Join(cmdArgs, " "), err, out)
	}
	return string(out)
}

func TestOpenFlow15FieldActionEncoding(t *testing.T) {
	load, err := ofctrl.NewNXLoadAction("nxm_nx_reg4", 0x20, openflow.NewNXRange(0, 15))
	if err != nil {
		t.Fatalf("create load action: %v", err)
	}
	loadAction, err := load.ToOfAction()
	if err != nil {
		t.Fatalf("convert load action: %v", err)
	}
	if loadAction.Header().Type != openflow.ActionType_SetField {
		t.Fatalf("load action type = %d, want %d", loadAction.Header().Type, openflow.ActionType_SetField)
	}
	if _, err := loadAction.MarshalBinary(); err != nil {
		t.Fatalf("marshal load action: %v", err)
	}

	move, err := ofctrl.NewNXMoveAction(16, 0, 0, "nxm_nx_reg0", "nxm_nx_reg1", false)
	if err != nil {
		t.Fatalf("create move action: %v", err)
	}
	moveAction, err := move.ToOfAction()
	if err != nil {
		t.Fatalf("convert move action: %v", err)
	}
	if moveAction.Header().Type != openflow.ActionType_Copy_Field {
		t.Fatalf("move action type = %d, want %d", moveAction.Header().Type, openflow.ActionType_Copy_Field)
	}
	if _, err := moveAction.MarshalBinary(); err != nil {
		t.Fatalf("marshal move action: %v", err)
	}
}

func TestBundleActionCompatibilityWithOVS(t *testing.T) {
	if os.Getenv("OFNET_ACTION_PROBE") != "1" {
		t.Skip("set OFNET_ACTION_PROBE=1 to run the OVS bundle action compatibility probe")
	}

	const (
		brName = "ofnet-action-probe"
		port   = 16733
	)

	runOVS(t, "--if-exists", "del-br", brName)
	t.Cleanup(func() {
		_ = exec.Command("ovs-vsctl", "--if-exists", "del-br", brName).Run()
	})

	app := &probeApp{swCh: make(chan *ofctrl.OFSwitch, 1)}
	ctrl := ofctrl.NewController(app, ofctrl.DisableCleanGroup())
	go ctrl.Listen(fmt.Sprintf("127.0.0.1:%d", port))
	time.Sleep(200 * time.Millisecond)

	runOVS(t, "add-br", brName)
	runOVS(t, "set", "bridge", brName, "protocols=OpenFlow15")
	runOVS(t, "set", "bridge", brName, "fail_mode=secure")
	runOVS(t, "set-controller", brName, fmt.Sprintf("tcp:127.0.0.1:%d", port))

	var sw *ofctrl.OFSwitch
	select {
	case sw = <-app.swCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for OVS to connect")
	}

	table := sw.DefaultTable()
	nextTable, err := sw.NewTable(1)
	if err != nil {
		t.Fatalf("create next table: %v", err)
	}

	cases := []struct {
		name  string
		build func(*ofctrl.Flow) error
		next  ofctrl.FgraphElem
		match ofctrl.FlowMatch
	}{
		{
			name: "empty-apply-actions",
			build: func(f *ofctrl.Flow) error {
				return nil
			},
			next: ofctrl.NewEmptyElem(),
		},
		{
			name: "goto-table",
			build: func(f *ofctrl.Flow) error {
				return nil
			},
			next: nextTable,
		},
		{
			name: "load-reg4",
			build: func(f *ofctrl.Flow) error {
				return f.LoadField("nxm_nx_reg4", 0x20, openflow.NewNXRange(0, 15))
			},
			next: ofctrl.NewEmptyElem(),
		},
		{
			name: "load-pkt-mark",
			build: func(f *ofctrl.Flow) error {
				return f.LoadField("nxm_nx_pkt_mark", 0x1, openflow.NewNXRange(28, 28))
			},
			next: ofctrl.NewEmptyElem(),
		},
		{
			name: "load-in-port",
			build: func(f *ofctrl.Flow) error {
				return f.LoadField("nxm_of_in_port", 0xfffe, openflow.NewNXRange(0, 15))
			},
			next: ofctrl.NewEmptyElem(),
		},
		{
			name: "set-field-reg4",
			build: func(f *ofctrl.Flow) error {
				field := openflow.NewRegMatchField(4, 0x20, openflow.NewNXRange(0, 15))
				return f.AddAction(staticAction{
					actionType: ofctrl.ActTypeSetDstMac,
					action:     openflow.NewActionSetField(*field),
				})
			},
			next: ofctrl.NewEmptyElem(),
		},
		{
			name: "load-xxreg0",
			build: func(f *ofctrl.Flow) error {
				return f.LoadField("nxm_nx_xxreg0", 0x1, openflow.NewNXRange(60, 87))
			},
			next: ofctrl.NewEmptyElem(),
		},
		{
			name: "move-reg-to-reg",
			build: func(f *ofctrl.Flow) error {
				return f.MoveField(16, 0, 0, "nxm_nx_reg0", "nxm_nx_reg1", false)
			},
			next: ofctrl.NewEmptyElem(),
		},
		{
			name: "resubmit-table",
			build: func(f *ofctrl.Flow) error {
				tableID := uint8(1)
				return f.Resubmit(nil, &tableID)
			},
			next: ofctrl.NewEmptyElem(),
		},
		{
			name: "ct-zone-field",
			build: func(f *ofctrl.Flow) error {
				tableID := uint8(1)
				ct, err := ofctrl.NewConntrackActionWithZoneField(false, false, &tableID, "nxm_nx_reg0", openflow.NewNXRange(0, 15))
				if err != nil {
					return err
				}
				return f.SetConntrack(ct)
			},
			next: ofctrl.NewEmptyElem(),
			match: ofctrl.FlowMatch{
				Ethertype: 0x0800,
			},
		},
		{
			name: "ct-clear",
			build: func(f *ofctrl.Flow) error {
				return f.CTClear()
			},
			next: ofctrl.NewEmptyElem(),
		},
		{
			name: "set-eth-dst",
			build: func(f *ofctrl.Flow) error {
				return f.SetMacDa(net.HardwareAddr{0x00, 0x00, 0x5e, 0x00, 0x53, 0x01})
			},
			next: ofctrl.NewEmptyElem(),
		},
	}

	var failures []string
	for i, tt := range cases {
		runOfctl(t, "del-flows", brName)

		match := tt.match
		match.Priority = uint16(100 + i)
		flow, err := table.NewFlow(match)
		if err != nil {
			t.Fatalf("%s: create flow: %v", tt.name, err)
		}
		if err := tt.build(flow); err != nil {
			t.Fatalf("%s: build action: %v", tt.name, err)
		}
		flow.NextElem = tt.next

		flowMod, err := flow.BuildInstallFlowMod(true)
		if err != nil {
			t.Fatalf("%s: build FlowMod: %v", tt.name, err)
		}

		if err := sw.Send(flowMod); err != nil {
			t.Fatalf("%s: direct send FlowMod: %v", tt.name, err)
		}
		time.Sleep(300 * time.Millisecond)
		dump := runOfctl(t, "dump-flows", brName)
		directOK := strings.Contains(dump, fmt.Sprintf("cookie=0x%x", flowMod.Cookie))
		t.Logf("%s: direct FlowMod accepted=%t", tt.name, directOK)

		runOfctl(t, "del-flows", brName)

		tx := sw.NewTransaction(ofctrl.Atomic | ofctrl.Ordered)
		if err := tx.Begin(); err != nil {
			t.Fatalf("%s: begin bundle: %v", tt.name, err)
		}
		if err := tx.AddFlow(flowMod); err != nil {
			t.Fatalf("%s: add flow to bundle: %v", tt.name, err)
		}
		time.Sleep(300 * time.Millisecond)
		added, err := tx.Complete()
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: complete failed: %v", tt.name, err))
			continue
		}
		if added != 1 {
			failures = append(failures, fmt.Sprintf("%s: bundle added %d/1 messages", tt.name, added))
			_ = tx.Abort()
			continue
		}
		if err := tx.Commit(); err != nil {
			failures = append(failures, fmt.Sprintf("%s: commit failed: %v", tt.name, err))
			continue
		}
		t.Logf("%s: ok", tt.name)
	}

	if len(failures) > 0 {
		t.Fatalf("bundle action compatibility failures:\n%s", strings.Join(failures, "\n"))
	}
}
