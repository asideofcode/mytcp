// Package http1 is a tiny HTTP/1.x server sitting on our userspace TCP.
//
// Mental model: TCP delivers a byte stream; HTTP is just parsing that stream
// for a request ending in \r\n\r\n, then writing a response and closing.
//
// It plugs into the stack as a tcp.App: TCP hands it in-order payload bytes
// per connection, and it hands back response bytes plus "close after this".
// It deliberately leaves out keep-alive, request bodies, chunked encoding,
// header parsing beyond the request line, and routing: every path gets the
// same page.
package http1

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/asideofcode/mytcp/internal/tcp"
)

// maxBuf caps how many bytes we buffer per connection while waiting for
// the end of the headers. Without a cap, a client that never sends
// \r\n\r\n could make us buffer forever.
const maxBuf = 64 << 10

// Server implements tcp.App. It keeps one partial-request buffer per
// connection, because a request may arrive spread over several TCP segments.
//
// The same Server is also driven by the HTTPS wrappers from one goroutine
// per connection, so mu guards buf.
type Server struct {
	mu   sync.Mutex
	buf  map[tcp.ConnKey][]byte // bytes received so far, per connection, until headers are complete
	log  *log.Logger
	Body string // response body; default greeting if empty
}

// New returns a Server that logs to logger, or to the standard logger
// if logger is nil.
func New(logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	return &Server{
		buf: make(map[tcp.ConnKey][]byte),
		log: logger,
	}
}

// OnData is called with each chunk of in-order bytes TCP receives on the
// connection identified by key. It returns the response to send, if a full
// request has arrived, and whether TCP should close the connection after it.
//
// TCP is a byte stream, not a message stream. One request can arrive in
// several segments, and segment boundaries mean nothing to HTTP. So bytes
// are appended to a per-connection buffer until the blank line that ends
// the header section (\r\n\r\n, RFC 9112 Section 2.1) shows up.
func (s *Server) OnData(key tcp.ConnKey, data []byte) (reply []byte, closeAfter bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	buf := append(s.buf[key], data...)
	if len(buf) > maxBuf {
		s.log.Printf("http: %v request too large — 413", key)
		delete(s.buf, key)
		return s.response(413, "text/plain", "request too large\n"), true
	}
	s.buf[key] = buf

	headerEnd := bytes.Index(buf, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		// Incomplete request; TCP already ACKs — wait for more.
		return nil, false
	}

	// Headers are complete. The buffer is dropped here, so any bytes after
	// the blank line (a body, or a second pipelined request) are discarded.
	// That is safe only because every response closes the connection.
	head := string(buf[:headerEnd])
	delete(s.buf, key)

	// The first line is the request line: "METHOD target HTTP/x.y"
	// (RFC 9112 Section 3). Only the method and target are used; the
	// version and all header fields are ignored.
	line, _, _ := strings.Cut(head, "\r\n")
	parts := strings.Fields(line)
	if len(parts) < 2 {
		s.log.Printf("http: %v bad request-line %q", key, line)
		return s.response(400, "text/plain", "bad request\n"), true
	}
	method, path := parts[0], parts[1]
	s.log.Printf("http: %v %s %s", key, method, path)

	// Only GET and HEAD are supported, and the path does not matter.
	switch method {
	case "GET", "HEAD":
		body := s.body()
		// HEAD gets the same headers as GET, including the Content-Length
		// GET would have had, but no body (RFC 9110 Section 9.3.2).
		if method == "HEAD" {
			return s.responseHead(200, "text/html; charset=utf-8", len(body)), true
		}
		return s.response(200, "text/html; charset=utf-8", body), true
	default:
		return s.response(405, "text/plain", "method not allowed\n"), true
	}
}

// OnClose is called by TCP when the connection is gone. It forgets any
// half-received request so the buffer map does not leak.
func (s *Server) OnClose(key tcp.ConnKey) {
	s.mu.Lock()
	delete(s.buf, key)
	s.mu.Unlock()
}

// body returns the page served for every GET: Body if set, otherwise a
// small built-in HTML greeting.
func (s *Server) body() string {
	if s.Body != "" {
		return s.Body
	}
	return `<!doctype html>
<html><head><title>mytcp</title></head>
<body>
<h1>mytcp</h1>
<p>HTTP/1 over userspace TCP on TAP.</p>
</body></html>
`
}

// response builds a complete HTTP response: status line, headers, the
// blank line that ends the headers, then the body.
//
// The headers are the minimum a client needs. Content-Type says how to
// display the body. Content-Length says where the body ends, so the client
// does not have to guess. Connection: close says this server does not keep
// connections alive: it sends one response and then closes TCP
// (RFC 9112 Section 9.6). The status line says HTTP/1.0, whose default is
// already one request per connection.
func (s *Server) response(code int, ctype, body string) []byte {
	reason := statusText(code)
	return []byte(fmt.Sprintf(
		"HTTP/1.0 %d %s\r\n"+
			"Content-Type: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"%s",
		code, reason, ctype, len(body), body,
	))
}

// responseHead builds the same headers as response for a body of bodyLen
// bytes, but without the body itself. It is used for HEAD requests.
func (s *Server) responseHead(code int, ctype string, bodyLen int) []byte {
	reason := statusText(code)
	return []byte(fmt.Sprintf(
		"HTTP/1.0 %d %s\r\n"+
			"Content-Type: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		code, reason, ctype, bodyLen,
	))
}

// statusText returns the reason phrase for the few status codes this
// server sends. Clients are expected to act on the number and ignore the
// phrase; it is there for humans reading the raw bytes.
func statusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 400:
		return "Bad Request"
	case 405:
		return "Method Not Allowed"
	case 413:
		return "Payload Too Large"
	default:
		return "Error"
	}
}
