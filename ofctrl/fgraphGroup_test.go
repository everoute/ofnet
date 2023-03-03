package ofctrl

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/contiv/libOpenflow/openflow13"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var notFoundGroup = errors.New("not found specified group")

func ofctrlGroupDump(brName string, groupId string) (string, error) {
	dumpGroups, err := runOfctlCmd("dump-groups", brName, groupId)
	if err != nil {
		return "", err
	}
	log.Infof("dumpGroup: %s", string(dumpGroups))
	groupInfo := strings.Split(strings.TrimRight(string(dumpGroups), "\n"), "\n")
	if len(groupInfo) <= 1 {
		return "", notFoundGroup
	}
	log.Infof("group: %s", groupInfo[1])
	return groupInfo[1], nil
}

func matchGroupType(group string, gType string) bool {
	typeStr := fmt.Sprintf("type=%s", gType)
	if strings.Contains(group, typeStr) {
		return true
	}
	return false
}

func matchGroupBucket(group string, bucketWeight uint16, bucketAct string) bool {
	wetStr := "weight:"
	if bucketWeight != 0 {
		wetStr = fmt.Sprintf("weight:%d", bucketWeight)
	}

	actStr := fmt.Sprintf("actions=%s", bucketAct)

	matchWet := strings.Contains(group, wetStr)
	matchAct := strings.Contains(group, actStr)

	if bucketWeight == 0 {
		return !matchWet && matchAct
	} else {
		return matchWet && matchAct
	}
}

func TestCreateDeleteGroup(t *testing.T) {
	sw := ofActor.Switch
	tests := []struct {
		name   string
		gpId   uint32
		gpType uint8
		exType string
	}{
		{
			name:   "group type all",
			gpId:   4,
			gpType: openflow13.OFPGT_ALL,
			exType: "all",
		}, {
			name:   "group type select",
			gpId:   6,
			gpType: openflow13.OFPGT_SELECT,
			exType: "select",
		}, {
			name:   "group type ff",
			gpId:   3,
			gpType: openflow13.OFPGT_FF,
			exType: "ff",
		},
	}

	for i, test := range tests {
		// test add empty group success
		gp, err := sw.NewGroup(test.gpId, test.gpType)
		if err != nil {
			t.Errorf("test: %s, op: add group, failed: %s", test.name, err)
		}
		err = gp.Install()
		if err != nil {
			t.Errorf("test: %s, op: add group, failed: %s", test.name, err)
		}
		dpGp, err := ofctrlGroupDump(ovsDriver.OvsBridgeName, fmt.Sprintf("%d", test.gpId))
		if err != nil {
			t.Errorf("test: %s, op: add group, failed: %s", test.name, err)
		}
		if !matchGroupType(dpGp, test.exType) {
			t.Errorf("test: %s, op: add group, failed: the groupType error", test.name)
		}

		// test add exist group failed
		if i == 0 {
			_, err = sw.NewGroup(test.gpId, openflow13.OFPGT_SELECT)
			if err == nil {
				t.Errorf("test: %s, op: add exist group, failed: add exist group should failed, but it success", test.name)
			}
		}

		// test delete group success, test func Group.Delete and DeleteGroup
		if i < len(tests)/2 {
			gp.Delete()
			if gp.isInstalled == true {
				t.Errorf("test: %s, op: delete group, failed: group.isInstalled is true, expect is false", test.name)
			}
		} else {
			_ = DeleteGroup(sw, test.gpId)
		}
		if sw.GetGroup(test.gpId) != nil {
			t.Errorf("test: %s, op: delete group, failed: switch groupDb cache hasn't delete the group", test.name)
		}
		dpGp, err = ofctrlGroupDump(ovsDriver.OvsBridgeName, fmt.Sprintf("%d", test.gpId))
		if !errors.Is(err, notFoundGroup) {
			t.Errorf("test: %s, op: delete group, failed: the err (%s) is not the same as (%s) ", test.name, err, notFoundGroup)
		}
	}
}

func TestAddResetBuckets(t *testing.T) {
	sw := ofActor.Switch
	var tableId uint8 = 190
	var gpId uint32 = 677
	gp, err := sw.NewGroup(gpId, openflow13.OFPGT_SELECT)
	assert.Nil(t, err)

	// doesn't send to dp
	bucket1 := NewBucket(100)
	loadAct1, _ := NewNXLoadAction("nxm_nx_reg2", 0x50, openflow13.NewNXRange(0, 15))
	bucket1.AddAction(loadAct1)
	bucket1.AddAction(NewResubmitAction(nil, &tableId))
	gp.AddBucket(bucket1)
	_, err = ofctrlGroupDump(ovsDriver.OvsBridgeName, fmt.Sprintf("%d", gpId))
	assert.EqualError(t, err, notFoundGroup.Error())

	// send to dp
	gp.Install()
	gpDump, err := ofctrlGroupDump(ovsDriver.OvsBridgeName, fmt.Sprintf("%d", gpId))
	assert.Nil(t, err)
	bucket1Act := fmt.Sprintf("load:0x50->NXM_NX_REG2[0..15],resubmit(,%d)", tableId)
	assert.True(t, matchGroupBucket(gpDump, 100, bucket1Act))

	// add bucket and send to dp
	bucket2 := NewBucket(35)
	loadAct2, _ := NewNXLoadAction("nxm_nx_reg1", 0xa00003b, openflow13.NewNXRange(0, 31))
	bucket2.AddAction(loadAct2)
	gp.AddBucket(bucket2)
	gpDump, err = ofctrlGroupDump(ovsDriver.OvsBridgeName, fmt.Sprintf("%d", gpId))
	assert.Nil(t, err)
	bucket2Act := fmt.Sprintf("load:0xa00003b->NXM_NX_REG1[]")
	assert.True(t, matchGroupBucket(gpDump, 35, bucket2Act))

	// test reset buckets
	bucket3 := NewBucket(50)
	bucket3.AddAction(NewSetDstIP(net.IPv4(192, 10, 10, 34)))
	mac, _ := net.ParseMAC("c2:c3:66:87:51:ce")
	bucket3.AddAction(NewSetDstMac(mac))
	gp.ResetBuckets([]*Bucket{bucket3})
	gpDump, err = ofctrlGroupDump(ovsDriver.OvsBridgeName, fmt.Sprintf("%d", gpId))
	assert.Nil(t, err)
	bucket3Act := fmt.Sprintf("set_field:c2:c3:66:87:51:ce->eth_dst,set_field:192.10.10.34->ip_dst")
	assert.True(t, matchGroupBucket(gpDump, 50, bucket3Act))
	assert.False(t, matchGroupBucket(gpDump, 35, bucket2Act))
	assert.False(t, matchGroupBucket(gpDump, 100, bucket1Act))
}
