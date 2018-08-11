// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package beater

import (
	"net"
	"time"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
)

type FlowEvent struct {
	TimeReceived time.Time `ecs:"@timestamp"`
	TimeCreated  time.Time `ecs:"event.created"`
	SequenceNum  uint32
	Type         FlowType `ecs:"event.type"`

	// Flow exporter address.
	DeviceAddr net.IP `mapstr:"device.ip"`

	// Flow times.
	StartTime time.Time     `mapstr:"flow.start_time"`
	LastTime  time.Time     `mapstr:"flow.last_time"`
	Duration  time.Duration `mapstr:"flow.duration"`

	// Flow volume.
	Bytes   uint64 `mapstr:"flow.bytes"`
	Packets uint64 `mapstr:"flow.packets"`

	// Layer 3 info.
	SrcMAC net.HardwareAddr `mapstr:"source.mac"`
	DstMAC net.HardwareAddr `mapstr:"destination.mac"`

	// Layer 4 Info.

	// IP version. https://www.iana.org/assignments/version-numbers/version-numbers.xhtml
	IPVersion        uint8  `mapstr:"network.protocol,append"` // 4 = ipv4, 6=ipv6
	IPClassOfTraffic uint8  `mapstr:"network.tos"`             // TOS for IPv4, Traffic Class for IPv6.
	SrcIP            net.IP `mapstr:"source.ip"`
	DstIP            net.IP `mapstr:"destination.ip"`
	SrcPort          uint16
	DstPort          uint16

	// Layer 4 protocol (transport). Comes from the IPv4 and IPv6 headers.
	// Netflow fields: protocolIdentifier (IPv4) and nextHeaderIPv6.
	TransportProtocol IPProtocol `mapstr:"network.protocol,append"`

	FiveTupleHash string // Stable 5-tuple that's the same for both flow dirs.

	IngressVLAN uint16 `mapstr:"flow.vlan.ingress"`
	EgressVLAN  uint16 `mapstr:"flow.vlan.egress"`

	// Raw Netflow fields.
	Netflow map[string]interface{} `mapstr:"netflow,append"`
}

func (f *FlowEvent) toBeatEvent() beat.Event {
	b := beat.Event{
		Timestamp: f.TimeReceived,
		Fields: common.MapStr{
			"event": common.MapStr{
				"type":    f.Type.String(),
				"created": f.TimeCreated,
			},
			"device": common.MapStr{
				"ip": f.DeviceAddr,
			},
			"flow": common.MapStr{
				"sequence_num": f.SequenceNum,
				"start_time":   f.StartTime,
				"last_time":    f.LastTime,
				"duration":     f.Duration,
				"bytes":        f.Bytes,
				"packets":      f.Packets,
				"id":           f.FiveTupleHash,
			},
			"source": common.MapStr{
				"mac":  f.SrcMAC.String(),
				"ip":   f.SrcIP.String(),
				"port": f.SrcPort,
			},
			"destination": common.MapStr{
				"mac":  f.DstMAC.String(),
				"ip":   f.DstIP.String(),
				"port": f.DstPort,
			},
			"network": common.MapStr{
				"protocol": f.TransportProtocol.String(),
			},
			"netflow": f.Netflow,
		},
	}

	if f.IngressVLAN > 0 {
		b.PutValue("source.vlan", f.IngressVLAN)
	}
	if f.EgressVLAN > 0 {
		b.PutValue("destination.vlan", f.EgressVLAN)
	}
	return b
}
