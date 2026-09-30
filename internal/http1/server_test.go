package http1_test

import (
	"io"
	"log"
	"strings"
	"testing"

	"github.com/asideofcode/mytcp/internal/http1"
	"github.com/asideofcode/mytcp/internal/tcp"
)

func TestGET(t *testing.T) {
	s := http1.New(log.New(io.Discard, "", 0))
	key := tcp.ConnKey{RemoteIP: "10.0.0.1", RemotePort: 1, LocalPort: 80}

	reply, done := s.OnData(key, []byte("GET / HTTP/1.0\r\nHost: x\r\n\r\n"))
	if !done {
		t.Fatal("expected closeAfter")
	}
	if !strings.Contains(string(reply), "HTTP/1.0 200") {
		t.Fatalf("status: %q", reply)
	}
	if !strings.Contains(string(reply), "mytcp") {
		t.Fatalf("body: %q", reply)
	}
	if !strings.Contains(string(reply), "Connection: close") {
		t.Fatal("missing Connection: close")
	}
}

func TestPartialThenComplete(t *testing.T) {
	s := http1.New(log.New(io.Discard, "", 0))
	key := tcp.ConnKey{RemoteIP: "10.0.0.1", RemotePort: 2, LocalPort: 80}

	reply, done := s.OnData(key, []byte("GET / HTTP/1.1\r\n"))
	if reply != nil || done {
		t.Fatalf("incomplete should wait, got %q done=%v", reply, done)
	}
	reply, done = s.OnData(key, []byte("Host: x\r\n\r\n"))
	if !done || !strings.HasPrefix(string(reply), "HTTP/1.0 200") {
		t.Fatalf("got %q done=%v", reply, done)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	s := http1.New(log.New(io.Discard, "", 0))
	key := tcp.ConnKey{RemoteIP: "10.0.0.1", RemotePort: 3, LocalPort: 80}
	reply, done := s.OnData(key, []byte("POST / HTTP/1.0\r\n\r\n"))
	if !done || !strings.Contains(string(reply), "405") {
		t.Fatalf("got %q", reply)
	}
}
