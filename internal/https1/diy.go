package https1

import (
	"log"
	"net"

	"github.com/asideofcode/mytcp/internal/http1"
	"github.com/asideofcode/mytcp/internal/mintls"
	"github.com/asideofcode/mytcp/internal/tcp"
)

// DIYServer is HTTPS using our own TLS 1.2 stack (mintls), not crypto/tls.
//
// The plumbing is the same as Server: a goroutine per connection, a
// StreamConn underneath, http1 on top. What changes is the middle layer.
// mintls speaks only TLS 1.2 with one cipher suite
// (ECDHE_ECDSA_WITH_AES_128_GCM_SHA256), so clients have to be told to
// cap at TLS 1.2 (curl --tls-max 1.2).
type DIYServer struct {
	cfg  *mintls.Config
	http *http1.Server
	log  *log.Logger
}

// NewDIY builds a mintls-backed HTTPS acceptor with an ephemeral self-signed cert.
func NewDIY(ip net.IP, logger *log.Logger) (*DIYServer, error) {
	if logger == nil {
		logger = log.Default()
	}
	// mintls makes its own certificate and ECDSA key, so this variant does
	// not depend on crypto/tls anywhere.
	der, key, err := mintls.SelfSigned(ip.To4(), []string{"localhost", "mytcp.local"})
	if err != nil {
		return nil, err
	}
	return &DIYServer{
		cfg: &mintls.Config{Certificates: []mintls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
		}}},
		http: http1.New(logger),
		log:  logger,
	}, nil
}

// OnAccept is called by the TCP layer once per new ESTABLISHED connection.
// It must not block the TCP input path, so the real work runs in its own
// goroutine.
func (s *DIYServer) OnAccept(conn *tcp.StreamConn) {
	go s.serve(conn)
}

// serve runs one HTTPS connection from handshake to close, using mintls.
// The loop closely mirrors Server.serve; only the TLS type differs.
func (s *DIYServer) serve(raw *tcp.StreamConn) {
	defer raw.Close()

	// mintls needs an explicit Handshake before Read or Write. crypto/tls
	// would run it on first use; mintls has no such shortcut.
	tlsConn := mintls.Server(raw, s.cfg)
	if err := tlsConn.Handshake(s.cfg); err != nil {
		s.log.Printf("https-diy: handshake %v: %v", raw.RemoteAddr(), err)
		return
	}
	s.log.Printf("https-diy: handshake ok %v (mintls TLS 1.2 ECDHE_ECDSA_AES_128_GCM)", raw.RemoteAddr())
	// mintls Close closes the TCP stream (sending our FIN). It does not
	// send a TLS close_notify alert first.
	defer tlsConn.Close()

	// Rebuild the ConnKey that http1.Server uses to track this
	// connection's partial request.
	key := tcp.ConnKey{RemoteIP: raw.RemoteAddr().String(), LocalPort: 443}
	if ta, ok := raw.RemoteAddr().(*net.TCPAddr); ok {
		key.RemoteIP = ta.IP.String()
		key.RemotePort = uint16(ta.Port)
		if la, ok := raw.LocalAddr().(*net.TCPAddr); ok {
			key.LocalPort = uint16(la.Port)
		}
	}
	// TCP only calls OnClose on its callback App (NopApp here), so this
	// loop must drop http1's half-read request itself on every exit.
	defer s.http.OnClose(key)

	// Read returns decrypted application data from one or more TLS
	// records. http1 buffers until it has full headers, then answers
	// and asks to close.
	buf := make([]byte, 4096)
	for {
		n, err := tlsConn.Read(buf)
		if n > 0 {
			reply, closeAfter := s.http.OnData(key, buf[:n])
			if len(reply) > 0 {
				// Write encrypts the reply into TLS records of up to
				// 4096 plaintext bytes each.
				if _, werr := tlsConn.Write(reply); werr != nil {
					s.log.Printf("https-diy: write %v: %v", key, werr)
					return
				}
			}
			if closeAfter {
				return
			}
		}
		// mintls reports io.EOF when the client sends any alert, which
		// includes close_notify.
		if err != nil {
			return
		}
	}
}
