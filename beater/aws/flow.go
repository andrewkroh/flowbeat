package aws

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const notApplicable = "-"

type LogStatus uint8

const (
	OK LogStatus = iota + 1
	NoData
	SkipData
)

var logStatusNames = map[LogStatus]string{
	OK:       "OK",
	NoData:   "NODATA",
	SkipData: "SKIPDATA",
}

func (ls LogStatus) String() string {
	name, found := logStatusNames[ls]
	if found {
		return name
	}
	return "-"
}

type Action uint8

const (
	Accept Action = iota + 1
	Reject
)

var actionNames = map[Action]string{
	Accept: "ACCEPT",
	Reject: "REJECT",
}

func (a Action) String() string {
	name, found := actionNames[a]
	if found {
		return name
	}
	return "-"
}

// VPCFlowV2 represents an AWS VPC flow log (version 2).
//
// Format: <version> <account-id> <interface-id> <srcaddr> <dstaddr> <srcport>
// <dstport> <protocol> <packets> <bytes> <start> <end> <action> <log-status>
//
// If a field is not applicable for a specific record, the record displays a '-'
// symbol for that entry.
type VPCFlowV2 struct {
	AccountID   string
	InterfaceID string
	SrcAddr     net.IP
	DstAddr     net.IP
	SrcPort     uint16
	DstPort     uint16
	Protocol    uint8
	Packets     uint64
	Bytes       uint64
	Start       uint64
	End         uint64
	Action      Action
	LogStatus   LogStatus
}

const (
	idxAccountID = iota
	idxInterfaceID
	idxSrcAddr
	idxDstAddr
	idxSrcPort
	idxDstPort
	idxProtocol
	idxPackets
	idxBytes
	idxStart
	idxEnd
	idxAction
	idxLogStatus
	idxMax
)

func NewVPCFlowV2(s string) (*VPCFlowV2, error) {
	if len(s) <= 3 {
		return nil, errors.New("AWS VPC flow log string too short")
	}

	if s[0] != '2' {
		return nil, fmt.Errorf("wrong AWS VPC flow log version '%c'", s[0])
	}

	// Skip the version.
	fields := strings.Fields(s[2:])
	if len(fields) != idxMax {
		return nil, errors.New("invalid number of tokens in AWS VPC flow log")
	}

	// Use zero value to N/A fields.
	for i, v := range fields {
		if notApplicable == v {
			fields[i] = ""
		}
	}

	var err error
	var srcPort, dstPort, protocol, pkts, bytes, start, end uint64

	if fields[idxSrcPort] != "" {
		srcPort, err = strconv.ParseUint(fields[idxSrcPort], 10, 16)
		if err != nil {
			return nil, err
		}
	}

	if fields[idxDstPort] != "" {
		dstPort, err = strconv.ParseUint(fields[idxDstPort], 10, 16)
		if err != nil {
			return nil, err
		}
	}

	if fields[idxProtocol] != "" {
		protocol, err = strconv.ParseUint(fields[idxProtocol], 10, 8)
		if err != nil {
			return nil, err
		}
	}

	if fields[idxPackets] != "" {
		pkts, err = strconv.ParseUint(fields[idxPackets], 10, 64)
		if err != nil {
			return nil, err
		}
	}

	if fields[idxBytes] != "" {
		bytes, err = strconv.ParseUint(fields[idxBytes], 10, 64)
		if err != nil {
			return nil, err
		}
	}

	if fields[idxStart] != "" {
		start, err = strconv.ParseUint(fields[idxStart], 10, 64)
		if err != nil {
			return nil, err
		}
	}

	if fields[idxEnd] != "" {
		end, err = strconv.ParseUint(fields[idxEnd], 10, 64)
		if err != nil {
			return nil, err
		}
	}

	var action Action
	if len(fields[idxAction]) > 0 {
		switch fields[idxAction][0] {
		case 'A':
			action = Accept
		case 'R':
			action = Reject
		}
	}

	var status LogStatus
	if len(fields[idxLogStatus]) > 0 {
		switch fields[idxLogStatus][0] {
		case 'O':
			status = OK
		case 'N':
			status = NoData
		case 'S':
			status = SkipData
		}
	}

	return &VPCFlowV2{
		AccountID:   fields[idxAccountID],
		InterfaceID: fields[idxInterfaceID],
		SrcAddr:     net.ParseIP(fields[idxSrcAddr]),
		DstAddr:     net.ParseIP(fields[idxDstAddr]),
		SrcPort:     uint16(srcPort),
		DstPort:     uint16(dstPort),
		Protocol:    uint8(protocol),
		Packets:     pkts,
		Bytes:       bytes,
		Start:       start,
		End:         end,
		Action:      action,
		LogStatus:   status,
	}, nil
}
