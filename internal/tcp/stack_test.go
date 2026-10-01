package tcp

import (
	"io"
	"log"
	"net"
	"testing"
	"time"
)

type fakeEmit struct {
	n    int
	last Segment
}

func (f *fakeEmit) SendTCP(dstMAC net.HardwareAddr, dstIP net.IP, seg Segment) error {
	f.n++
	f.last = seg
	return nil
}

func TestRetransmitTick(t *testing.T) {
	em := &fakeEmit{}
	s := NewStack(net.IPv4(10, 0, 0, 2), em, log.New(io.Discard, "", 0))
	s.rto = 50 * time.Millisecond
	now := time.Unix(0, 0)
	s.now = func() time.Time { return now }

	s.Listen(7)
	peerMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	if err := s.Handle(peerMAC, net.IPv4(10, 0, 0, 1), Segment{
		SrcPort: 40000, DstPort: 7, Seq: 1, Flags: FlagSYN, Window: 1000,
	}); err != nil {
		t.Fatal(err)
	}
	if em.n != 1 {
		t.Fatalf("expected SYN-ACK send, got %d", em.n)
	}

	now = now.Add(60 * time.Millisecond)
	s.Tick()
	if em.n != 2 {
		t.Fatalf("expected retransmit, got %d sends", em.n)
	}
}
