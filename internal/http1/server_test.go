package http1_test

import (
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

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

// pipePair is a bidirectional in-memory net.Conn pair for ServeConn tests.
type pipePair struct {
	net.Conn
	local, remote net.Addr
}

func (p pipePair) LocalAddr() net.Addr  { return p.local }
func (p pipePair) RemoteAddr() net.Addr { return p.remote }

func TestServeConn(t *testing.T) {
	s := http1.New(log.New(io.Discard, "", 0))
	c1, c2 := net.Pipe()
	server := pipePair{
		Conn:   c1,
		local:  &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 80},
		remote: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 50000},
	}
	client := c2

	go s.ServeConn(server)

	if _, err := client.Write([]byte("GET / HTTP/1.0\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	got := string(buf[:n])
	if !strings.Contains(got, "HTTP/1.0 200") || !strings.Contains(got, "mytcp") {
		t.Fatalf("response: %q", got)
	}
	client.Close()
}

func TestStdlibHandler(t *testing.T) {
	s := http1.New(log.New(io.Discard, "", 0))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := &http.Server{Handler: s.Handler()}
	srv.SetKeepAlivesEnabled(false)
	go srv.Serve(ln)

	resp, err := http.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "mytcp") {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
}
