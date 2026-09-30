package stack_test

import (
	"bytes"
	"io"
	"log"
	"net"
	"sync"
	"testing"

	"github.com/asideofcode/mytcp/internal/arp"
	"github.com/asideofcode/mytcp/internal/eth"
	"github.com/asideofcode/mytcp/internal/icmp"
	"github.com/asideofcode/mytcp/internal/ip4"
	"github.com/asideofcode/mytcp/internal/stack"
	"github.com/asideofcode/mytcp/internal/tcp"
)

type memIF struct {
	mu   sync.Mutex
	rx   [][]byte
	tx   [][]byte
	name string
}

func (m *memIF) Name() string { return m.name }

func (m *memIF) Read(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.rx) == 0 {
		return 0, io.EOF
	}
	b := m.rx[0]
	m.rx = m.rx[1:]
	return copy(p, b), nil
}

func (m *memIF) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tx = append(m.tx, append([]byte(nil), p...))
	return len(p), nil
}

func (m *memIF) lastTX() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.tx) == 0 {
		return nil
	}
	return m.tx[len(m.tx)-1]
}

func testStack(t *testing.T) (*stack.Stack, *memIF) {
	t.Helper()
	nif := &memIF{name: "test0"}
	st := stack.New(nif, stack.Config{
		MAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		IP:        net.IPv4(10, 0, 0, 2),
		ListenTCP: 7,
		Dump:      false,
		Logger:    log.New(io.Discard, "", 0),
	})
	return st, nif
}

func TestARPReply(t *testing.T) {
	st, nif := testStack(t)
	req := arp.Packet{
		Op:  arp.OpRequest,
		SHA: net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		SPA: net.IPv4(10, 0, 0, 1),
		THA: net.HardwareAddr{0, 0, 0, 0, 0, 0},
		TPA: net.IPv4(10, 0, 0, 2),
	}
	frame := eth.Frame{
		Dst:     net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		Src:     req.SHA,
		Type:    eth.TypeARP,
		Payload: req.Marshal(),
	}
	if err := st.HandleFrame(frame.Marshal()); err != nil {
		t.Fatal(err)
	}
	raw := nif.lastTX()
	if raw == nil {
		t.Fatal("no TX")
	}
	out, err := eth.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != eth.TypeARP {
		t.Fatalf("type=%s", eth.TypeName(out.Type))
	}
	rep, err := arp.Parse(out.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Op != arp.OpReply || !rep.SPA.Equal(net.IPv4(10, 0, 0, 2)) {
		t.Fatalf("bad reply %+v", rep)
	}
}

func TestICMPEcho(t *testing.T) {
	st, nif := testStack(t)
	echo := icmp.Echo{Type: icmp.TypeEcho, ID: 1, Seq: 1, Payload: []byte("hi")}
	ipPkt := ip4.Packet{
		TTL: 64, Proto: ip4.ProtoICMP,
		Src: net.IPv4(10, 0, 0, 1), Dst: net.IPv4(10, 0, 0, 2),
		Payload: echo.Marshal(),
	}
	frame := eth.Frame{
		Dst:  net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		Src:  net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		Type: eth.TypeIPv4, Payload: ipPkt.Marshal(),
	}
	if err := st.HandleFrame(frame.Marshal()); err != nil {
		t.Fatal(err)
	}
	raw := nif.lastTX()
	out, err := eth.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := ip4.Parse(out.Payload)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := icmp.ParseEcho(ip.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Type != icmp.TypeEchoReply || !bytes.Equal(rep.Payload, []byte("hi")) {
		t.Fatalf("bad icmp %+v", rep)
	}
}

func TestTCPHandshakeAndEcho(t *testing.T) {
	st, nif := testStack(t)
	peerMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	peerIP := net.IPv4(10, 0, 0, 1)
	ourIP := net.IPv4(10, 0, 0, 2)

	sendTCP := func(seg tcp.Segment) {
		t.Helper()
		ipPkt := ip4.Packet{
			TTL: 64, Proto: ip4.ProtoTCP,
			Src: peerIP, Dst: ourIP,
			Payload: seg.Marshal(peerIP, ourIP),
		}
		frame := eth.Frame{
			Dst: net.HardwareAddr{0x02, 0, 0, 0, 0, 2}, Src: peerMAC,
			Type: eth.TypeIPv4, Payload: ipPkt.Marshal(),
		}
		if err := st.HandleFrame(frame.Marshal()); err != nil {
			t.Fatal(err)
		}
	}
	readTCP := func() tcp.Segment {
		t.Helper()
		raw := nif.lastTX()
		if raw == nil {
			t.Fatal("no TX")
		}
		f, err := eth.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		ip, err := ip4.Parse(f.Payload)
		if err != nil {
			t.Fatal(err)
		}
		seg, err := tcp.Parse(ip.Payload)
		if err != nil {
			t.Fatal(err)
		}
		return seg
	}

	// SYN
	sendTCP(tcp.Segment{
		SrcPort: 40000, DstPort: 7, Seq: 500, Flags: tcp.FlagSYN, Window: 65535,
	})
	synAck := readTCP()
	if !synAck.Has(tcp.FlagSYN) || !synAck.Has(tcp.FlagACK) || synAck.Ack != 501 {
		t.Fatalf("SYN-ACK %+v flags=%s", synAck, tcp.FlagsString(synAck.Flags))
	}

	// ACK handshake
	sendTCP(tcp.Segment{
		SrcPort: 40000, DstPort: 7, Seq: 501, Ack: synAck.Seq + 1,
		Flags: tcp.FlagACK, Window: 65535,
	})

	// Data
	nif.tx = nil
	payload := []byte("hello")
	sendTCP(tcp.Segment{
		SrcPort: 40000, DstPort: 7, Seq: 501, Ack: synAck.Seq + 1,
		Flags: tcp.FlagACK | tcp.FlagPSH, Window: 65535, Payload: payload,
	})
	echo := readTCP()
	if !bytes.Equal(echo.Payload, payload) {
		t.Fatalf("echo %q", echo.Payload)
	}
	if echo.Ack != 501+uint32(len(payload)) {
		t.Fatalf("ack=%d", echo.Ack)
	}
}

// Ping replies (reader goroutine) and TCP sends (tick and TLS goroutines)
// share the IPv4 ID counter. Run with -race; every packet must get its own ID.
func TestConcurrentSendsGetDistinctIPIDs(t *testing.T) {
	st, nif := testStack(t)
	echo := icmp.Echo{Type: icmp.TypeEcho, ID: 1, Seq: 1, Payload: []byte("hi")}
	ping := eth.Frame{
		Dst:  net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		Src:  net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		Type: eth.TypeIPv4,
		Payload: (&ip4.Packet{
			TTL: 64, Proto: ip4.ProtoICMP,
			Src: net.IPv4(10, 0, 0, 1), Dst: net.IPv4(10, 0, 0, 2),
			Payload: echo.Marshal(),
		}).Marshal(),
	}.Marshal()

	const perWorker, workers = 200, 4
	var wg sync.WaitGroup
	wg.Add(workers)
	go func() {
		defer wg.Done()
		for i := 0; i < perWorker; i++ {
			if err := st.HandleFrame(ping); err != nil {
				t.Error(err)
			}
		}
	}()
	for w := 1; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				seg := tcp.Segment{SrcPort: 7, DstPort: 5000, Flags: tcp.FlagACK}
				if err := st.SendTCP(net.HardwareAddr{0x02, 0, 0, 0, 0, 1}, net.IPv4(10, 0, 0, 1), seg); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()

	seen := map[uint16]bool{}
	for _, raw := range nif.tx {
		f, _ := eth.Parse(raw)
		p, err := ip4.Parse(f.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if seen[p.ID] {
			t.Fatalf("IPv4 ID %d used twice", p.ID)
		}
		seen[p.ID] = true
	}
	if len(seen) != perWorker*workers {
		t.Fatalf("got %d packets, want %d", len(seen), perWorker*workers)
	}
}
