package beater

import "strconv"

type FlowType uint8

const (
	NetFlowV1 FlowType = 1
	NetFlowV5 FlowType = 5
	NetFlowV6 FlowType = 6
	NetFlowV7 FlowType = 7
	NetFlowV9 FlowType = 9
	IPFIX     FlowType = 10
)

var flowTypeNames = map[FlowType]string{
	NetFlowV1: "NetFlow V1",
	NetFlowV5: "NetFlow V5",
	NetFlowV6: "NetFlow V6",
	NetFlowV7: "NetFlow V7",
	NetFlowV9: "NetFlow V9",
	IPFIX:     "IPFIX",
}

func (t FlowType) String() string {
	name, found := flowTypeNames[t]
	if found {
		return name
	}
	return "unknown (" + strconv.Itoa(int(t)) + ")"
}
