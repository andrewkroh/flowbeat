package beater

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/assert"
	"github.com/tehmaze/netflow"
	"github.com/tehmaze/netflow/session"
	"gopkg.in/yaml.v2"

	"github.com/elastic/beats/libbeat/beat"
)

var (
	update = flag.Bool("update", false, "update golden data")

	sanitizer = strings.NewReplacer("-", "--", ":", "-", "/", "-", "+", "-", " ", "-", ",", "")

	timeReceived, _ = time.Parse(time.RFC3339Nano, "2018-08-26T20:30:41.013545202Z")
)

const (
	pcapDir     = "../testdata/pcap"
	datDir      = "../testdata/dat"
	goldenDir   = "../testdata/golden"
	datSourceIP = "192.0.2.1"
)

// DatTests specifies the .dat files associated with test cases.
type DatTests struct {
	Tests map[string][]string `yaml:"tests"`
}

// TestResult specifies the format of the result data that is written in a
// golden files.
type TestResult struct {
	Name   string       `json:"test_name"`
	Error  string       `json:"error,omitempty"`
	Events []beat.Event `json:"events,omitempty"`
}

func TestPCAPFiles(t *testing.T) {
	pcaps, err := filepath.Glob(filepath.Join(pcapDir, "*.pcap"))
	if err != nil {
		t.Fatal(err)
	}

	for _, file := range pcaps {
		testName := strings.TrimSuffix(filepath.Base(file), ".pcap")

		t.Run(testName, func(t *testing.T) {
			goldenName := filepath.Join(goldenDir, testName+".pcap.golden.json")
			result := getFlowsFromPCAP(t, testName, file)

			if *update {
				data, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					t.Fatal(err)
				}

				if err = os.MkdirAll(goldenDir, 0755); err != nil {
					t.Fatal(err)
				}

				err = ioutil.WriteFile(goldenName, data, 0644)
				if err != nil {
					t.Fatal(err)
				}

				return
			}

			goldenData := readGoldenFile(t, goldenName)
			assert.EqualValues(t, goldenData, normalize(t, result))
		})
	}
}

func TestDatFiles(t *testing.T) {
	tests := readDatTests(t)

	for name, files := range tests.Tests {
		t.Run(name, func(t *testing.T) {
			goldenName := filepath.Join(goldenDir, sanitizer.Replace(name)+".golden.json")
			result := getFlowsFromDat(t, name, files...)

			if *update {
				data, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					t.Fatal(err)
				}

				if err = os.MkdirAll(goldenDir, 0755); err != nil {
					t.Fatal(err)
				}

				err = ioutil.WriteFile(goldenName, data, 0644)
				if err != nil {
					t.Fatal(err)
				}

				return
			}

			goldenData := readGoldenFile(t, goldenName)
			assert.EqualValues(t, goldenData, normalize(t, result))
		})
	}
}

func readDatTests(t testing.TB) *DatTests {
	data, err := ioutil.ReadFile("../testdata/dat_tests.yaml")
	if err != nil {
		t.Fatal(err)
	}

	var tests DatTests
	if err := yaml.Unmarshal(data, &tests); err != nil {
		t.Fatal(err)
	}

	return &tests
}

func getFlowsFromDat(t testing.TB, name string, datFiles ...string) TestResult {
	t.Helper()

	sess := session.New()
	decoder := netflow.NewDecoder(sess)
	var flows []FlowEvent

	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP(datSourceIP),
		Port: 4444,
	}

	for _, f := range datFiles {
		dat, err := ioutil.ReadFile(filepath.Join(datDir, f))
		if err != nil {
			t.Fatal(err)
		}

		events, err := decodePacket(time.Now(), remoteAddr, dat, decoder)
		if err != nil {
			t.Logf("test %v: decode error: %v", name, err)
			return TestResult{Name: name, Error: err.Error(), Events: flowsToEvents(flows)}
		}
		flows = append(flows, events...)
	}

	return TestResult{Name: name, Events: flowsToEvents(flows)}
}

func getFlowsFromPCAP(t testing.TB, name, pcapFile string) TestResult {
	t.Helper()

	r, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	sess := session.New()
	decoder := netflow.NewDecoder(sess)
	packetSource := gopacket.NewPacketSource(r, r.LinkType())
	var flows []FlowEvent

	// Process packets in PCAP and get flow records.
	for packet := range packetSource.Packets() {
		remoteAddr := &net.UDPAddr{
			IP:   net.ParseIP(packet.NetworkLayer().NetworkFlow().Src().String()),
			Port: int(binary.BigEndian.Uint16(packet.TransportLayer().TransportFlow().Src().Raw())),
		}
		payloadData := packet.TransportLayer().LayerPayload()

		events, err := decodePacket(time.Now(), remoteAddr, payloadData, decoder)
		if err != nil {
			return TestResult{Name: name, Error: err.Error(), Events: flowsToEvents(flows)}
		}
		flows = append(flows, events...)
	}

	return TestResult{Name: name, Events: flowsToEvents(flows)}
}

func flowsToEvents(flows []FlowEvent) []beat.Event {
	var events []beat.Event
	for _, f := range flows {
		// Overwrite time received so the results are reproducible.
		f.TimeReceived = timeReceived
		events = append(events, f.toBeatEvent())
	}
	return events
}

func normalize(t testing.TB, result TestResult) TestResult {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	var tr TestResult
	if err = json.Unmarshal(data, &tr); err != nil {
		t.Fatal(err)
	}
	return tr
}

func readGoldenFile(t testing.TB, file string) TestResult {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}

	var tr TestResult
	if err = json.Unmarshal(data, &tr); err != nil {
		t.Fatal(err)
	}
	return tr
}
