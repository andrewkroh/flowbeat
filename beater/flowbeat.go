package beater

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/OneOfOne/xxhash"
	"github.com/pkg/errors"
	"github.com/tehmaze/netflow"
	"github.com/tehmaze/netflow/ipfix"
	"github.com/tehmaze/netflow/netflow1"
	"github.com/tehmaze/netflow/netflow5"
	"github.com/tehmaze/netflow/netflow6"
	"github.com/tehmaze/netflow/netflow7"
	"github.com/tehmaze/netflow/netflow9"
	"github.com/tehmaze/netflow/session"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
)

// Flowbeat configuration.
type Flowbeat struct {
	done   chan struct{}
	config Config
	client beat.Client
}

// New creates an instance of flowbeat.
func New(b *beat.Beat, cfg *common.Config) (beat.Beater, error) {
	c := defaultConfig
	if err := cfg.Unpack(&c); err != nil {
		return nil, errors.Wrap(err, "failed to unpack config")
	}

	bt := &Flowbeat{
		done:   make(chan struct{}),
		config: c,
	}
	return bt, nil
}

// Run starts flowbeat.
func (bt *Flowbeat) Run(b *beat.Beat) error {
	logp.Info("flowbeat is running! Hit CTRL-C to stop it.")

	var err error
	bt.client, err = b.Publisher.Connect()
	if err != nil {
		return err
	}

	if err = bt.listen(); err != nil {
		return err
	}
	return nil
}

// Stop stops flowbeat.
func (bt *Flowbeat) Stop() {
	bt.client.Close()
	close(bt.done)
}

func (bt *Flowbeat) listen() error {
	addr, err := net.ResolveUDPAddr("udp", bt.config.NetflowAddr)
	if err != nil {
		return err
	}

	server, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer server.Close()

	if err = server.SetReadBuffer(int(bt.config.NetflowReadBuffer)); err != nil {
		return err
	}

	go func() {
		select {
		case <-bt.done:
			server.Close()
		}
	}()

	// RFC 3954:
	// A 32-bit value that identifies the Exporter Observation Domain.
	// NetFlow Collectors SHOULD use the combination of the source IP
	// address and the Source ID field to separate different export
	// streams originating from the same Exporter.
	decoders := make(map[string]*netflow.Decoder)
	buf := make([]byte, 8192)
	log := logp.NewLogger("netflow")
	for {
		select {
		case <-bt.done:
			return nil
		default:
		}

		size, remote, err := server.ReadFromUDP(buf)
		if err != nil {
			log.Warnw("Error reading from socket", "error", err)
			continue
		}
		log.Debugf("received %d bytes from %s", size, remote)

		timestamp := time.Now()
		payloadCopy := make([]byte, size)
		copy(payloadCopy, buf)

		d, found := decoders[remote.String()]
		if !found {
			s := session.New()
			d = netflow.NewDecoder(s)
			decoders[remote.String()] = d
		}

		flows, err := decodePacket(timestamp, remote, payloadCopy, d)
		if err != nil {
			log.Errorw("Error while building flow records", "error", err)
			continue
		}
		publishFlows(flows, bt.client)
	}
}

func decodePacket(ts time.Time, src *net.UDPAddr, data []byte, dec *netflow.Decoder) ([]FlowEvent, error) {
	m, err := dec.Read(bytes.NewBuffer(data))
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode payload")
	}

	switch p := m.(type) {
	case *netflow1.Packet:
	case *netflow5.Packet:
	case *netflow6.Packet:
	case *netflow7.Packet:

	case *netflow9.Packet:
		flows, err := transformNetflowV9(ts, src, p)
		if err != nil {
			return nil, errors.Wrap(err, "errror while building flow records")
		}
		return flows, nil

	case *ipfix.Message:
		flows, err := transformIPFIX(ts, src, p)
		if err != nil {
			return nil, errors.Wrap(err, "errror while building ipfix flow records")
		}
		return flows, nil
	}

	return nil, nil
}

func publishFlows(flows []FlowEvent, c beat.Client) {
	events := make([]beat.Event, 0, len(flows))
	for _, flow := range flows {
		events = append(events, flow.toBeatEvent())
	}
	c.PublishAll(events)
}

func transformNetflowV9(ts time.Time, remoteAddr *net.UDPAddr, p *netflow9.Packet) ([]FlowEvent, error) {
	timeCreated := time.Unix(int64(p.Header.UnixSecs), 0).UTC()
	sysUpTime := time.Duration(p.Header.SysUpTime) * time.Millisecond

	var flows []FlowEvent
	for _, ds := range p.DataFlowSets {
		for _, r := range ds.Records {
			flow := FlowEvent{
				TimeCreated:  timeCreated,
				TimeReceived: ts,
				SequenceNum:  p.Header.SequenceNumber,
				Type:         NetFlowV9,
				DeviceAddr:   remoteAddr.IP,
				Netflow: common.MapStr{
					"template_id": r.TemplateID,
				},
			}

			transformNetflowV9Fields(&flow, sysUpTime, r.Fields)

			flows = append(flows, flow)
		}
	}

	return flows, nil
}

func transformNetflowV9Fields(flow *FlowEvent, sysUpTime time.Duration, fields netflow9.Fields) {
	var unknownTypes []uint16
	for _, f := range fields {
		if f.Translated == nil || f.Translated.Value == nil {
			unknownTypes = append(unknownTypes, f.Type)
			continue
		}

		var (
			name = f.Translated.Name
			v    = f.Translated.Value
		)

		// net.HardwareAddr does not marshal nicely.
		if mac, ok := v.(net.HardwareAddr); ok {
			flow.Netflow[name] = mac.String()
		} else {
			flow.Netflow[name] = v
		}

		var ok bool
		switch name {
		case "flowStartSysUpTime":
			var ms uint32
			ms, ok = v.(uint32)
			flow.StartTime = computeTime(flow.TimeCreated, sysUpTime,
				time.Duration(ms)*time.Millisecond)
		case "flowEndSysUpTime":
			var ms uint32
			ms, ok = v.(uint32)
			flow.LastTime = computeTime(flow.TimeCreated, sysUpTime,
				time.Duration(ms)*time.Millisecond)
		case "octetDeltaCount":
			flow.Bytes, ok = v.(uint64)
		case "packetDeltaCount":
			flow.Packets, ok = v.(uint64)
		case "sourceMacAddress", "postSourceMacAddress":
			flow.SrcMAC, ok = v.(net.HardwareAddr)
		case "flowDirection":
			var dir uint8
			dir, ok = v.(uint8)
			flow.Direction = (*FlowDirection)(&dir)
		case "destinationMacAddress", "postDestinationMacAddress":
			flow.DstMAC, ok = v.(net.HardwareAddr)
		case "ipVersion":
			flow.IPVersion, ok = v.(uint8)
		case "ipClassOfService":
			flow.IPClassOfTraffic, ok = v.(uint8)
		case "sourceIPv4Address", "sourceIPv6Address":
			flow.SrcIP, ok = v.(net.IP)
		case "destinationIPv4Address", "destinationIPv6Address":
			flow.DstIP, ok = v.(net.IP)
		case "sourceTransportPort":
			flow.SrcPort, ok = v.(uint16)
		case "destinationTransportPort":
			flow.DstPort, ok = v.(uint16)
		case "protocolIdentifier", "nextHeaderIPv6":
			var t uint8
			t, ok = v.(uint8)
			flow.TransportProtocol = IPProtocol(t)
		case "tcpControlBits":
			var t uint16
			t, ok = v.(uint16)
			flow.TCPFlags = TCPFlag(t)
		case "vlanId":
			flow.IngressVLAN, ok = v.(uint16)
		case "postVlanId":
			flow.EgressVLAN, ok = v.(uint16)
		default:
			ok = true
		}
		if !ok {
			logp.Warn("translation of %v failed, type is %T", name, v)
		}
	}

	// Compute flow duration.
	if dur := flow.LastTime.Sub(flow.StartTime); !flow.StartTime.IsZero() && dur > 0 {
		flow.Duration = dur
	}

	flow.FiveTuple = flowStableFiveTuple(flow.SrcIP, flow.DstIP, flow.SrcPort, flow.DstPort, flow.TransportProtocol)
	flow.FiveTupleHash = flowID(flow.SrcIP, flow.DstIP, flow.SrcPort, flow.DstPort, uint8(flow.TransportProtocol))
	flow.SrcLocality = getIPLocality(flow.SrcIP)
	flow.DstLocality = getIPLocality(flow.DstIP)
	flow.Locality = getIPLocality(flow.SrcIP, flow.DstIP)
}

func transformIPFIX(ts time.Time, remoteAddr *net.UDPAddr, p *ipfix.Message) ([]FlowEvent, error) {
	timeCreated := time.Unix(int64(p.Header.ExportTime), 0).UTC()

	var flows []FlowEvent
	for _, ds := range p.DataSets {
		for _, r := range ds.Records {
			flow := FlowEvent{
				TimeCreated:  timeCreated,
				TimeReceived: ts,
				SequenceNum:  p.Header.SequenceNumber,
				Type:         IPFIX,
				DeviceAddr:   remoteAddr.IP,
				Netflow: common.MapStr{
					"template_id": r.TemplateID,
				},
			}

			if p.Header.ObservationDomainID > 0 {
				flow.Netflow["observation_domain_id"] = p.Header.ObservationDomainID
			}

			transformIPFIXFields(&flow, r.Fields)

			flows = append(flows, flow)
		}
	}

	return flows, nil
}

func transformIPFIXFields(flow *FlowEvent, fields ipfix.Fields) {
	for _, f := range fields {
		if f.Translated == nil || f.Translated.Value == nil {
			continue
		}

		var (
			name = f.Translated.Name
			v    = f.Translated.Value
		)

		// net.HardwareAddr does not marshal nicely.
		if mac, ok := v.(net.HardwareAddr); ok {
			flow.Netflow[name] = mac.String()
		} else {
			flow.Netflow[name] = v
		}

		var ok bool
		switch name {
		//case "flowStartSysUpTime":
		//	var ms uint32
		//	ms, ok = v.(uint32)
		//	flow.StartTime = computeTime(flow.TimeCreated, sysUpTime,
		//		time.Duration(ms)*time.Millisecond)
		//case "flowEndSysUpTime":
		//	var ms uint32
		//	ms, ok = v.(uint32)
		//	flow.LastTime = computeTime(flow.TimeCreated, sysUpTime,
		//		time.Duration(ms)*time.Millisecond)
		case "octetDeltaCount":
			flow.Bytes, ok = v.(uint64)
		case "packetDeltaCount":
			flow.Packets, ok = v.(uint64)
		case "sourceMacAddress", "postSourceMacAddress":
			flow.SrcMAC, ok = v.(net.HardwareAddr)
		case "flowDirection":
			var dir uint8
			dir, ok = v.(uint8)
			flow.Direction = (*FlowDirection)(&dir)
		case "destinationMacAddress", "postDestinationMacAddress":
			flow.DstMAC, ok = v.(net.HardwareAddr)
		case "ipVersion":
			flow.IPVersion, ok = v.(uint8)
		case "ipClassOfService":
			flow.IPClassOfTraffic, ok = v.(uint8)
		case "sourceIPv4Address", "sourceIPv6Address":
			flow.SrcIP, ok = v.(net.IP)
		case "destinationIPv4Address", "destinationIPv6Address":
			flow.DstIP, ok = v.(net.IP)
		case "sourceTransportPort":
			flow.SrcPort, ok = v.(uint16)
		case "destinationTransportPort":
			flow.DstPort, ok = v.(uint16)
		case "protocolIdentifier", "nextHeaderIPv6":
			var t uint8
			t, ok = v.(uint8)
			flow.TransportProtocol = IPProtocol(t)
		case "tcpControlBits":
			var t uint16
			t, ok = v.(uint16)
			flow.TCPFlags = TCPFlag(t)
		case "vlanId":
			flow.IngressVLAN, ok = v.(uint16)
		case "postVlanId":
			flow.EgressVLAN, ok = v.(uint16)
		default:
			ok = true
		}
		if !ok {
			logp.Warn("translation of %v failed, type is %T", name, v)
		}
	}

	// Compute flow duration.
	if dur := flow.LastTime.Sub(flow.StartTime); !flow.StartTime.IsZero() && dur > 0 {
		flow.Duration = dur
	}

	flow.FiveTuple = flowStableFiveTuple(flow.SrcIP, flow.DstIP, flow.SrcPort, flow.DstPort, flow.TransportProtocol)
	flow.FiveTupleHash = flowID(flow.SrcIP, flow.DstIP, flow.SrcPort, flow.DstPort, uint8(flow.TransportProtocol))
	flow.SrcLocality = getIPLocality(flow.SrcIP)
	flow.DstLocality = getIPLocality(flow.DstIP)
	flow.Locality = getIPLocality(flow.SrcIP, flow.DstIP)
}

// computeTime computes a time value based on the differential between the
// system uptime and the uptime value at which the event occurred
// (start or last packet). That difference is then subtracted from current time
// to determine an absolute time.
func computeTime(referenceTime time.Time, referenceUptime, eventUptime time.Duration) time.Time {
	diff := referenceUptime - eventUptime
	if diff < 0 {
		return referenceTime
	}
	return referenceTime.Add(-1 * diff)
}

func flowID(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto uint8) string {
	h := xxhash.New64()

	// Both flows will have the same ID.
	if srcPort >= dstPort {
		h.Write(srcIP)
		binary.Write(h, binary.BigEndian, srcPort)
		h.Write(dstIP)
		binary.Write(h, binary.BigEndian, dstPort)
	} else {
		h.Write(dstIP)
		binary.Write(h, binary.BigEndian, dstPort)
		h.Write(srcIP)
		binary.Write(h, binary.BigEndian, srcPort)
	}
	binary.Write(h, binary.BigEndian, proto)

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func flowStableFiveTuple(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto IPProtocol) string {
	if srcPort < dstPort {
		// Swap src and dst.
		ip, port := srcIP, srcPort
		srcIP, srcPort = dstIP, dstPort
		dstIP, dstPort = ip, port
	}

	// Write the address with the highest port first so that we get a stable
	// value for both sides of the flow.
	var b strings.Builder
	b.WriteString(srcIP.String())
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(int(srcPort)))

	b.WriteString(" - ")

	b.WriteString(dstIP.String())
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(int(dstPort)))

	b.WriteByte(' ')
	b.WriteString(proto.String())
	return b.String()
}

var (
	// RFC 1918
	privateIPv4 = []net.IPNet{
		{IP: net.IPv4(10, 0, 0, 0), Mask: net.IPv4Mask(255, 0, 0, 0)},
		{IP: net.IPv4(172, 16, 0, 0), Mask: net.IPv4Mask(255, 240, 0, 0)},
		{IP: net.IPv4(192, 168, 0, 0), Mask: net.IPv4Mask(255, 255, 0, 0)},
	}

	// RFC 4193
	privateIPv6 = net.IPNet{
		IP:   net.IP{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		Mask: net.IPMask{0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
)

func isPrivateNetwork(ip net.IP) bool {
	for _, net := range privateIPv4 {
		if net.Contains(ip) {
			return true
		}
	}

	return privateIPv6.Contains(ip)
}

func isLocalOrPrivate(ip net.IP) bool {
	return isPrivateNetwork(ip) ||
		ip.IsLoopback() ||
		ip.IsUnspecified() ||
		ip.Equal(net.IPv4bcast) ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast()
}

func getIPLocality(ip ...net.IP) Locality {
	for _, addr := range ip {
		if !isLocalOrPrivate(addr) {
			return LocalityPublic
		}
	}
	return LocalityPrivate
}
