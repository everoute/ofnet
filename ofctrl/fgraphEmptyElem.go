package ofctrl

import (
	"github.com/contiv/libOpenflow/openflow13"
)

type EmptyElem struct {
}

func (e *EmptyElem) Type() string {
	return "empty"
}

func (e *EmptyElem) GetFlowInstr() openflow13.Instruction {
	instr := openflow13.NewInstrApplyActions()
	return instr
}

func NewEmptyElem() *EmptyElem {
	return new(EmptyElem)
}
