package beater

import (
	"sort"
	"strings"
)

type TCPFlag uint32

const (
	NS  TCPFlag = 0x0100
	CWR TCPFlag = 0x0080
	ECE TCPFlag = 0x0040
	URG TCPFlag = 0x0020
	ACK TCPFlag = 0x0010
	PSH TCPFlag = 0x0008
	RST TCPFlag = 0x0004
	SYN TCPFlag = 0x0002
	FIN TCPFlag = 0x0001
)

var tcpFlagNames = map[TCPFlag]string{
	NS:  "NS",
	CWR: "CWR",
	ECE: "ECE",
	URG: "URG",
	ACK: "ACK",
	PSH: "PSH",
	RST: "RST",
	SYN: "SYN",
	FIN: "FIN",
}

func (f TCPFlag) String() string {
	return strings.Join(f.Strings(), "|")
}

var sortedTCPFlags []TCPFlag

func init() {
	sortedTCPFlags = make([]TCPFlag, 0, len(tcpFlagNames))
	for k := range tcpFlagNames {
		sortedTCPFlags = append(sortedTCPFlags, k)
	}
	sort.Slice(sortedTCPFlags, func(i, j int) bool {
		return sortedTCPFlags[i] < sortedTCPFlags[j]
	})
}

func (f TCPFlag) Strings() []string {
	var flags []string
	for _, flag := range sortedTCPFlags {
		if flag&f > 0 {
			flags = append(flags, tcpFlagNames[flag])
		}
	}
	return flags
}
