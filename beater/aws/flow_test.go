package aws

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

type FlowTest struct {
	Log  string
	Flow VPCFlowV2
}

var flowTests = []FlowTest{
	{
		"2 123456789010 eni-abc123de 172.31.16.139 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK",
		VPCFlowV2{
			AccountID:   "123456789010",
			InterfaceID: "eni-abc123de",
			SrcAddr:     net.ParseIP("172.31.16.139"),
			DstAddr:     net.ParseIP("172.31.16.21"),
			SrcPort:     20641,
			DstPort:     22,
			Protocol:    6,
			Packets:     20,
			Bytes:       4249,
			Start:       1418530010,
			End:         1418530070,
			Action:      Accept,
			LogStatus:   OK,
		},
	},
	{
		"2 123456789010 eni-abc123de 172.31.9.69 172.31.9.12 49761 3389 6 20 4249 1418530010 1418530070 REJECT OK",
		VPCFlowV2{
			AccountID:   "123456789010",
			InterfaceID: "eni-abc123de",
			SrcAddr:     net.ParseIP("172.31.9.69"),
			DstAddr:     net.ParseIP("172.31.9.12"),
			SrcPort:     49761,
			DstPort:     3389,
			Protocol:    6,
			Packets:     20,
			Bytes:       4249,
			Start:       1418530010,
			End:         1418530070,
			Action:      Reject,
			LogStatus:   OK,
		},
	},
	{
		"2 123456789010 eni-1a2b3c4d - - - - - - - 1431280876 1431280934 - NODATA",
		VPCFlowV2{
			AccountID:   "123456789010",
			InterfaceID: "eni-1a2b3c4d",
			Start:       1431280876,
			End:         1431280934,
			LogStatus:   NoData,
		},
	},
	{
		"2 123456789010 eni-4b118871 - - - - - - - 1431280876 1431280934 - SKIPDATA",
		VPCFlowV2{
			AccountID:   "123456789010",
			InterfaceID: "eni-4b118871",
			Start:       1431280876,
			End:         1431280934,
			LogStatus:   SkipData,
		},
	},
}

func TestNewVPCFlowV2(t *testing.T) {
	for i, test := range flowTests {
		f, err := NewVPCFlowV2(test.Log)
		if err != nil {
			t.Fatalf("error on test %d while parsing '%v': %v", i+1, test.Log, err)
		}

		assert.EqualValues(t, test.Flow, *f, "error on test %d while parsing '%v'", i+1, test.Log)
	}
}

func BenchmarkNewVPCFlowV2(b *testing.B) {
	log := flowTests[0].Log

	for i := 0; i < b.N; i++ {
		_, err := NewVPCFlowV2(log)
		if err != nil {
			b.Fatal(err)
		}
	}
}
