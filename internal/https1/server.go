// Package https1 serves HTTP/1 over crypto/tls on our userspace TCP streams.
//
// We do not implement TLS — Go's crypto/tls does. This package only bridges
// tcp.StreamConn → tls.Server → the existing http1 app.
//
// TLS needs a blocking, net.Conn-style byte stream, not the per-segment
// callbacks a tcp.App gets. So these servers are tcp.Acceptors instead: TCP
// hands over a *tcp.StreamConn once the handshake reaches ESTABLISHED. That
// StreamConn is a net.Conn whose Read blocks on a buffer the TCP input path
// fills, and whose Write turns bytes into TCP segments. Each connection gets
// its own goroutine running a plain read-decrypt, answer, encrypt-write loop:
//
//	TCP segments ⇄ tcp.StreamConn (net.Conn) ⇄ TLS (crypto/tls or mintls) ⇄ http1.Server.OnData
//
// Server uses crypto/tls (TLS 1.2 or 1.3). DIYServer in diy.go uses our own
// mintls (TLS 1.2, one cipher suite). Both serve the same http1 page.
// Certificates are generated at startup and self-signed, so clients must
// skip verification (curl -k).
package https1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/asideofcode/mytcp/internal/http1"
	"github.com/asideofcode/mytcp/internal/tcp"
)

// Server implements tcp.Acceptor using Go's crypto/tls. It decrypts each
// connection and feeds the plaintext to an http1.Server.
type Server struct {
	cfg  *tls.Config
	http *http1.Server
	log  *log.Logger
}

// New builds a TLS acceptor with an ephemeral self-signed cert for ip.
func New(ip net.IP, logger *log.Logger) (*Server, error) {
	if logger == nil {
		logger = log.Default()
	}
	cert, err := selfSigned(ip)
	if err != nil {
		return nil, err
	}
	// MinVersion refuses the deprecated TLS 1.0 and 1.1. crypto/tls picks
	// the highest version both sides support, so modern clients get 1.3.
	return &Server{
		cfg: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		http: http1.New(logger),
		log:  logger,
	}, nil
}

// OnAccept is called by the TCP layer once per new ESTABLISHED connection.
// It must not block the TCP input path, so the real work runs in its own
// goroutine.
func (s *Server) OnAccept(conn *tcp.StreamConn) {
	go s.serve(conn)
}

// serve runs one HTTPS connection from TLS handshake to close.
func (s *Server) serve(raw *tcp.StreamConn) {
	defer raw.Close()

	// tls.Server only needs a net.Conn. It has no idea the bytes travel
	// over a TCP written in userspace.
	tlsConn := tls.Server(raw, s.cfg)
	// Deferred calls run last-in first-out, so the TLS conn closes first:
	// after a completed handshake it sends a close_notify alert, then it
	// closes the TCP stream, which sends our FIN.
	defer tlsConn.Close()

	// The handshake is several round trips of TLS records over the same
	// StreamConn: hello messages, certificate, key exchange, Finished.
	if err := tlsConn.Handshake(); err != nil {
		s.log.Printf("https: handshake %v: %v", raw.RemoteAddr(), err)
		return
	}
	s.log.Printf("https: handshake ok %v %s", raw.RemoteAddr(), tls.VersionName(tlsConn.ConnectionState().Version))

	// http1.Server keys its per-connection buffer by ConnKey, the same
	// identity the plain TCP path would use, so rebuild it from the
	// connection's addresses.
	key := tcp.ConnKey{
		RemoteIP:   raw.RemoteAddr().String(),
		RemotePort: 0,
		LocalPort:  443,
	}
	if ta, ok := raw.RemoteAddr().(*net.TCPAddr); ok {
		key.RemoteIP = ta.IP.String()
		key.RemotePort = uint16(ta.Port)
		key.LocalPort = uint16(raw.LocalAddr().(*net.TCPAddr).Port)
	}
	// TCP only calls OnClose on its callback App (NopApp here), so this
	// loop must drop http1's half-read request itself on every exit.
	defer s.http.OnClose(key)

	// Each Read returns decrypted application data. As with plain TCP,
	// a chunk may hold part of a request, so http1 keeps buffering until
	// it sees the end of the headers. Once it answers, it asks to close.
	buf := make([]byte, 4096)
	for {
		n, err := tlsConn.Read(buf)
		if n > 0 {
			reply, closeAfter := s.http.OnData(key, buf[:n])
			if len(reply) > 0 {
				// Write encrypts the reply into TLS records, which
				// StreamConn then splits into TCP segments.
				if _, werr := tlsConn.Write(reply); werr != nil {
					s.log.Printf("https: write %v: %v", key, werr)
					return
				}
			}
			if closeAfter {
				return
			}
		}
		// Any error ends the connection: io.EOF after the client's
		// close_notify, or an error if TCP went away or a record was bad.
		if err != nil {
			return
		}
	}
}

// selfSigned creates a fresh ECDSA P-256 key and a certificate for ip
// signed by that same key. Nothing trusts it, which is fine for a demo:
// the connection is still encrypted, just not authenticated.
func selfSigned(ip net.IP) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	// Serial numbers should be unique per issuer; a random one is the
	// usual approach for throwaway certificates.
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, err
	}
	// NotBefore is backdated an hour so small clock differences between us
	// and the client do not make the certificate "not yet valid". Clients
	// match the name they connected to against IPAddresses and DNSNames,
	// so those list our IP and the host names the demo might use.
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{ip.To4()},
		DNSNames:     []string{"localhost", "mytcp.local"},
	}
	if ip4 := ip.To4(); ip4 != nil {
		tmpl.IPAddresses = []net.IP{ip4}
	}
	// Passing tmpl as both the certificate and its parent is what makes
	// it self-signed: subject and issuer are the same.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	// tls.X509KeyPair takes PEM text, so encode the DER bytes as PEM and
	// let it parse them back into a tls.Certificate.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
