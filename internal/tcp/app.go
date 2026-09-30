package tcp

// ConnKey identifies a connection for the application layer. It is the
// exported mirror of the internal fourTuple: remote IP and port plus our
// local port. Apps use it to keep per-connection state, such as a
// partially received HTTP request.
type ConnKey struct {
	RemoteIP   string
	RemotePort uint16
	LocalPort  uint16
}

// App is the byte-stream consumer above TCP (echo, HTTP, …).
// OnData is invoked for each in-order payload. Return bytes to send
// (may be nil) and whether to FIN after that send (active close).
//
// OnData is called with the stack lock held, once per received segment,
// so it must be quick. A segment boundary is not a message boundary:
// one request may arrive split over several calls, and the app has to
// buffer until it has a complete message. OnClose is called once when
// the connection is removed, whether by a normal close or a RST.
//
// For stream-oriented apps (TLS), call Stack.SetAcceptor instead; App is
// then unused for data (NopApp is fine), though OnClose is still called.
type App interface {
	OnData(key ConnKey, data []byte) (reply []byte, closeAfter bool)
	OnClose(key ConnKey)
}

// Acceptor is notified once when a connection reaches ESTABLISHED.
// OnAccept must not block the TCP input path for long — typically
// `go serve(conn)`. The conn implements net.Conn over this stack.
//
// Stack.Handle already calls OnAccept on a new goroutine, outside the
// stack lock, so blocking inside OnAccept does not stall other traffic.
type Acceptor interface {
	OnAccept(conn *StreamConn)
}

// NopApp ignores payloads (used with Acceptor-based apps).
type NopApp struct{}

// OnData acknowledges the data but sends nothing back.
func (NopApp) OnData(ConnKey, []byte) ([]byte, bool) { return nil, false }

// OnClose does nothing.
func (NopApp) OnClose(ConnKey) {}

// EchoApp sends every received payload straight back and never closes
// the connection itself. It is the default App when NewStack is given
// nil, and is handy for testing with netcat.
type EchoApp struct{}

// OnData returns a copy of data as the reply, so the segment kept in the
// retransmission queue owns its bytes.
func (EchoApp) OnData(_ ConnKey, data []byte) ([]byte, bool) {
	return append([]byte(nil), data...), false
}

// OnClose does nothing; EchoApp keeps no per-connection state.
func (EchoApp) OnClose(ConnKey) {}

// key converts the internal connection identifier to the exported ConnKey.
func (t fourTuple) key() ConnKey {
	return ConnKey{RemoteIP: t.remoteIP, RemotePort: t.remotePort, LocalPort: t.localPort}
}
