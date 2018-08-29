package beater

import "strconv"

// TODO: create table from https://www.iana.org/asdsignments/protocol-numbers/protocol-numbers.xhtml
// They have a CSV file available for conversion.

type IPProtocol uint8

const (
	ICMP     IPProtocol = 1
	TCP      IPProtocol = 6
	UDP      IPProtocol = 17
	IPv6ICMP IPProtocol = 58
)

var ipProtocolNames = map[IPProtocol]string{
	ICMP:     "ICMP",
	TCP:      "TCP",
	UDP:      "UDP",
	IPv6ICMP: "IPv6-ICMP",
}

func (p IPProtocol) String() string {
	name, found := ipProtocolNames[p]
	if found {
		return name
	}
	return "unknown (" + strconv.Itoa(int(p)) + ")"
}
