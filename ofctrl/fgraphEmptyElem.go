package ofctrl

import (
	openflow "github.com/contiv/libOpenflow/openflow15"
)

type EmptyElem struct {
}

func (e *EmptyElem) Type() string {
	return "empty"
}

func (e *EmptyElem) GetFlowInstr() openflow.Instruction {
	instr := openflow.NewInstrApplyActions()
	return instr
}

func NewEmptyElem() *EmptyElem {
	return new(EmptyElem)
}
