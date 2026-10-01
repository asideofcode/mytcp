package tcp

import (
	"net"
	"sync"
)

// Compile-time checks: StreamConn is a net.Conn, Listener is a net.Listener.
// That is the contract Go's stdlib (net/http, crypto/tls) expects of a
// transport, so anything that works on a kernel socket works on ours.
var (
	_ net.Conn     = (*StreamConn)(nil)
	_ net.Listener = (*Listener)(nil)
)

// Listener is a net.Listener backed by this userspace TCP stack. It is the
// pull side of the Acceptor push: each ESTABLISHED connection is handed to
// OnAccept, which parks it on a channel until Accept takes it.
type Listener struct {
	stack *Stack
	port  uint16
	addr  net.Addr

	ch   chan *StreamConn
	done chan struct{}
	once sync.Once
}

// NewListener opens port for incoming connections and returns a Listener
// that Accept will block on. It sets the stack's Acceptor, so App.OnData
// is no longer called for data on this stack; use NopApp when constructing
// the stack. Call it before traffic arrives.
func (s *Stack) NewListener(port uint16) *Listener {
	ln := &Listener{
		stack: s,
		port:  port,
		addr:  &net.TCPAddr{IP: append(net.IP(nil), s.ourIP...), Port: int(port)},
		ch:    make(chan *StreamConn),
		done:  make(chan struct{}),
	}
	s.SetAcceptor(ln)
	s.Listen(port)
	return ln
}

// OnAccept implements Acceptor. The stack already calls it on a new
// goroutine, so blocking on the channel does not stall other traffic.
func (l *Listener) OnAccept(c *StreamConn) {
	select {
	case l.ch <- c:
	case <-l.done:
		_ = c.Close()
	}
}

// Accept waits for the next ESTABLISHED connection and returns it as a
// net.Conn (*StreamConn). It returns net.ErrClosed after Close.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops accepting. In-flight Accept calls return net.ErrClosed.
// Connections already handed out are not closed.
func (l *Listener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

// Addr returns the local IP and listen port as a *net.TCPAddr.
func (l *Listener) Addr() net.Addr { return l.addr }
