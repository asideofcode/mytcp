// Command mytcp runs the userspace network stack on a Linux TAP device.
//
// The kernel sees the TAP as a normal network card with its own address
// (-host). Every frame the kernel sends to it lands in this process as raw
// bytes, and mytcp answers as if it were a separate machine at -ip / -mac:
// ARP, ping, and one TCP application chosen with -app. Opening a TAP needs
// Linux and CAP_NET_ADMIN (root, or a privileged container).
//
// Typical invocations:
//
//	mytcp                               # HTTP on 10.0.0.2:80 (our http1 on net.Listener)
//	mytcp -app http-go                  # same Listener, Go's net/http.Server
//	mytcp -app echo                     # TCP echo on port 7
//	mytcp -app https                    # HTTPS on :443 via crypto/tls
//	mytcp -app https-go                 # same, but tls.NewListener + net/http.Server
//	mytcp -app https-diy                # HTTPS on :443 via our own mintls (TLS 1.2)
//	mytcp -dump-only                    # decode and capture frames, never reply
//	mytcp -i tap1 -ip 10.0.1.2 -host 10.0.1.1/24 -tcp 8080
//	mytcp -dump=false -pcap captures/run1
//
// Then, from another shell on the same machine: curl http://10.0.0.2/
// or ping 10.0.0.2.
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/asideofcode/mytcp/internal/capture"
	"github.com/asideofcode/mytcp/internal/dump"
	"github.com/asideofcode/mytcp/internal/http1"
	"github.com/asideofcode/mytcp/internal/https1"
	"github.com/asideofcode/mytcp/internal/stack"
	"github.com/asideofcode/mytcp/internal/tap"
)

// main parses flags, picks the TCP application, opens the TAP, wires the
// stack together, and then runs until Ctrl-C or a read error.
func main() {
	// The first four flags are identity: which TAP to use, the address we
	// pretend to be, the address the kernel gets on its side of the
	// virtual cable, and our MAC. The two IPs share a subnet so the kernel
	// sends straight to us over the TAP. The default MAC starts with 02,
	// the "locally administered" bit, so it cannot clash with a real
	// vendor MAC. The rest choose the app and port, how much to print,
	// and where to record frames.
	var (
		ifName   = flag.String("i", "tap0", "TAP interface name (created if missing)")
		ipStr    = flag.String("ip", "10.0.0.2", "IPv4 address we claim (userspace)")
		hostCIDR = flag.String("host", "10.0.0.1/24", "kernel-side address on the TAP (empty = skip)")
		macStr   = flag.String("mac", "02:00:00:00:00:02", "MAC address we claim")
		tcpPort  = flag.Uint("tcp", 0, "TCP listen port (0 = default: 80 http, 443 https, 7 echo)")
		appName  = flag.String("app", "http", "TCP app: http | http-go | https | https-go | https-diy | echo")
		doDump   = flag.Bool("dump", true, "layered onion decode of RX/TX frames")
		dumpOnly = flag.Bool("dump-only", false, "Stage 0: decode frames only, no replies")
		pcapPath = flag.String("pcap", "captures/latest", "capture stem (.jsonl + .pcap); empty disables")
	)
	flag.Parse()

	mac, err := net.ParseMAC(*macStr)
	if err != nil {
		log.Fatalf("mac: %v", err)
	}
	// The stack speaks IPv4 only, so reject IPv6 addresses up front.
	ip := net.ParseIP(*ipStr)
	if ip == nil || ip.To4() == nil {
		log.Fatalf("ip: need IPv4 address, got %q", *ipStr)
	}

	// Pick what runs on top of TCP. Every app is the same shape: a
	// function that takes a net.Listener and serves connections from it,
	// exactly as it would on a kernel socket. Each has a default port.
	var (
		serve   func(net.Listener) error
		port    = uint16(*tcpPort)
		defPort uint16
		appDesc string
	)
	switch *appName {
	case "echo":
		serve, defPort, appDesc = serveEcho, 7, "TCP echo"
	case "http":
		serve, defPort, appDesc = http1.New(log.Default()).Serve, 80, "HTTP/1 (our server on net.Listener)"
	case "http-go":
		// Go's own HTTP server, given our Listener instead of net.Listen's.
		srv := &http.Server{Handler: http1.New(log.Default()).Handler()}
		srv.SetKeepAlivesEnabled(false)
		serve, defPort, appDesc = srv.Serve, 80, "HTTP/1 (net/http.Server on net.Listener)"
	case "https":
		hs, err := https1.New(ip.To4(), log.Default())
		if err != nil {
			log.Fatalf("https: %v", err)
		}
		serve, defPort, appDesc = hs.Serve, 443, "HTTPS (crypto/tls + HTTP/1)"
	case "https-go":
		// All stdlib above our TCP: tls.NewListener wraps our Listener, and
		// http.Server serves the TLS conns it returns.
		hs, err := https1.New(ip.To4(), log.Default())
		if err != nil {
			log.Fatalf("https-go: %v", err)
		}
		srv := &http.Server{Handler: http1.New(log.Default()).Handler()}
		srv.SetKeepAlivesEnabled(false)
		serve = func(ln net.Listener) error { return srv.Serve(tls.NewListener(ln, hs.TLSConfig())) }
		defPort, appDesc = 443, "HTTPS (tls.NewListener + net/http.Server)"
	case "https-diy":
		hs, err := https1.NewDIY(ip.To4(), log.Default())
		if err != nil {
			log.Fatalf("https-diy: %v", err)
		}
		serve, defPort, appDesc = hs.Serve, 443, "HTTPS (mintls TLS 1.2 DIY + HTTP/1)"
	default:
		log.Fatalf("unknown -app %q (want http|http-go|https|https-go|https-diy|echo)", *appName)
	}
	if port == 0 {
		port = defPort
	}

	// Open the TAP. From here on, every Read is one Ethernet frame the
	// kernel sent toward our side of the virtual cable.
	dev, err := tap.Open(*ifName)
	if err != nil {
		log.Fatal(err)
	}
	defer dev.Close()

	// Bring the interface up and give the kernel side its address, so the
	// kernel knows that -ip is reachable through this TAP.
	if err := tap.ConfigureHostSide(dev.Name(), *hostCIDR); err != nil {
		log.Fatalf("configure %s: %v", dev.Name(), err)
	}

	// Optional capture: every RX and TX frame is written to <stem>.jsonl
	// (for the browser viewer in web/) and <stem>.pcap (for Wireshark).
	var rec *capture.Recorder
	if *pcapPath != "" {
		rec, err = capture.Open(*pcapPath)
		if err != nil {
			log.Fatalf("capture: %v", err)
		}
		defer rec.Close()
		abs, _ := filepath.Abs(rec.Path())
		log.Printf("capturing → %s.jsonl + .pcap  (open web/index.html to inspect)", abs)
	}

	// Startup banner, including a ready-to-paste command to try the
	// chosen app from another shell.
	log.Printf("TAP %s open — we are %s / %s (host %s)", dev.Name(), mac, ip.To4(), *hostCIDR)
	if *dumpOnly {
		log.Printf("dump-only mode: no protocol replies")
	} else {
		log.Printf("protocols: ARP, ICMP echo, %s :%d", appDesc, port)
	}
	switch *appName {
	case "http", "http-go":
		log.Printf("from another shell: curl http://%s/   or   printf 'GET / HTTP/1.0\\r\\n\\r\\n' | nc %s %d",
			ip.To4(), ip.To4(), port)
	case "https", "https-go", "https-diy":
		// -k because the certificate is self-signed. The TLS 1.2 cap is
		// required for mintls, which speaks nothing newer.
		log.Printf("from another shell: curl -k --tlsv1.2 --tls-max 1.2 https://%s/", ip.To4())
	default:
		log.Printf("from another shell: ping %s   or   nc %s %d", ip.To4(), ip.To4(), port)
	}

	st := stack.New(dev, stack.Config{
		MAC:     mac,
		IP:      ip.To4(),
		Dump:    *doDump,
		DumpOut: os.Stdout,
		Capture: rec,
		Logger:  log.Default(),
	})

	// The same call a kernel program makes with net.Listen, but on our TCP.
	ln := st.TCP().Listen(port)
	go func() {
		if err := serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("%s: %v", *appName, err)
		}
	}()

	// Ctrl-C (SIGINT) or SIGTERM ends the program cleanly so the deferred
	// Close calls run and the capture files are complete.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// Timer goroutine: TCP must resend segments that were never ACKed,
	// and that needs a clock. Every 100 ms the stack checks for segments
	// whose retransmit timeout has passed.
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	go func() {
		for range tick.C {
			if !*dumpOnly {
				st.Tick()
			}
		}
	}()

	// Reader goroutine: the receive loop. It is the only caller of
	// HandleFrame, so incoming frames are processed one at a time, in
	// order. 2048 bytes holds any standard Ethernet frame (up to 1514
	// bytes without the checksum, which the TAP does not deliver).
	buf := make([]byte, 2048)
	errCh := make(chan error, 1)
	go func() {
		for {
			n, err := dev.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			// Copy the frame out of the shared read buffer, so nothing
			// downstream holds a slice the next Read will overwrite.
			frame := append([]byte(nil), buf[:n]...)
			// Dump-only mode: watch and record, but never hand frames to
			// the stack. With no ARP replies, the host cannot even find
			// us, so all you see are its questions.
			if *dumpOnly {
				if *doDump {
					dump.Frame(os.Stdout, "<<< RX", frame)
				}
				if rec != nil {
					_ = rec.Write(capture.RX, frame)
				}
				continue
			}
			// A bad frame is logged and skipped; it must not stop the loop.
			if err := st.HandleFrame(frame); err != nil {
				log.Printf("handle: %v", err)
			}
		}
	}()

	// The main goroutine just waits for a signal or a fatal read error.
	// log.Fatalf exits immediately, without running deferred calls.
	select {
	case <-stop:
		log.Printf("shutting down")
	case err := <-errCh:
		log.Fatalf("read: %v", err)
	}
}

// serveEcho writes every byte it reads straight back, one goroutine per
// connection, until the client closes. Try it with nc.
func serveEcho(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}()
	}
}
