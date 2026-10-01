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
//	mytcp -app https-diy                # HTTPS on :443 via our own mintls (TLS 1.2)
//	mytcp -dump-only                    # decode and capture frames, never reply
//	mytcp -i tap1 -ip 10.0.1.2 -host 10.0.1.1/24 -tcp 8080
//	mytcp -dump=false -pcap captures/run1
//
// Then, from another shell on the same machine: curl http://10.0.0.2/
// or ping 10.0.0.2.
package main

import (
	"flag"
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
	"github.com/asideofcode/mytcp/internal/tcp"
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
		appName  = flag.String("app", "http", "TCP app: http | http-go | https | https-diy | echo")
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

	// Pick what runs on top of TCP. There are three plug-in styles:
	//   - app (tcp.App) gets each chunk of received bytes as a callback
	//     and returns bytes to send. Echo works this way.
	//   - listener (net.Listener from tcp.NewListener): Accept returns a
	//     net.Conn per connection. Plain HTTP and Go's net/http use this.
	//   - acceptor (tcp.Acceptor) gets a whole connection as a net.Conn
	//     immediately. TLS needs that; the HTTPS apps then set app to a no-op.
	// Each app also has a well-known default port.
	var (
		app        tcp.App
		acceptor   tcp.Acceptor
		httpSrv    *http1.Server // set for -app http / http-go; started after the stack
		useStdHTTP bool
		port       = uint16(*tcpPort)
		appDesc    string
	)
	switch *appName {
	case "echo":
		app = tcp.EchoApp{}
		if port == 0 {
			port = 7
		}
		appDesc = "TCP echo"
	case "http":
		// Hand-rolled HTTP on a net.Listener. ListenTCP stays 0 here; the
		// Listener opens the port after the stack is built.
		httpSrv = http1.New(log.Default())
		app = tcp.NopApp{}
		if port == 0 {
			port = 80
		}
		appDesc = "HTTP/1 (our server on net.Listener)"
	case "http-go":
		// Same Listener, but net/http.Server.Serve drives it.
		httpSrv = http1.New(log.Default())
		useStdHTTP = true
		app = tcp.NopApp{}
		if port == 0 {
			port = 80
		}
		appDesc = "HTTP/1 (net/http.Server on net.Listener)"
	case "https":
		hs, err := https1.New(ip.To4(), log.Default())
		if err != nil {
			log.Fatalf("https: %v", err)
		}
		acceptor = hs
		app = tcp.NopApp{}
		if port == 0 {
			port = 443
		}
		appDesc = "HTTPS (crypto/tls + HTTP/1)"
	case "https-diy":
		hs, err := https1.NewDIY(ip.To4(), log.Default())
		if err != nil {
			log.Fatalf("https-diy: %v", err)
		}
		acceptor = hs
		app = tcp.NopApp{}
		if port == 0 {
			port = 443
		}
		appDesc = "HTTPS (mintls TLS 1.2 DIY + HTTP/1)"
	default:
		log.Fatalf("unknown -app %q (want http|http-go|https|https-diy|echo)", *appName)
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
	case "https", "https-diy":
		// -k because the certificate is self-signed. The TLS 1.2 cap is
		// required for mintls, which speaks nothing newer.
		log.Printf("from another shell: curl -k --tlsv1.2 --tls-max 1.2 https://%s/", ip.To4())
	default:
		log.Printf("from another shell: ping %s   or   nc %s %d", ip.To4(), ip.To4(), port)
	}

	// Plain HTTP opens its own Listener after New, so leave ListenTCP at 0
	// for those apps. Echo and HTTPS still register the port here.
	listenPort := port
	if httpSrv != nil {
		listenPort = 0
	}
	st := stack.New(dev, stack.Config{
		MAC:       mac,
		IP:        ip.To4(),
		ListenTCP: listenPort,
		App:       app,
		Acceptor:  acceptor,
		Dump:      *doDump,
		DumpOut:   os.Stdout,
		Capture:   rec,
		Logger:    log.Default(),
	})

	// Same Listener, two servers: ours, or Go's. Either way curl sees HTTP.
	if httpSrv != nil {
		ln := st.TCP().NewListener(port)
		if useStdHTTP {
			srv := &http.Server{
				Handler:           httpSrv.Handler(),
				ReadHeaderTimeout: 0,
			}
			srv.SetKeepAlivesEnabled(false)
			go func() {
				if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed && err != net.ErrClosed {
					log.Printf("http-go: %v", err)
				}
			}()
		} else {
			go func() {
				if err := httpSrv.Serve(ln); err != nil && err != net.ErrClosed {
					log.Printf("http: %v", err)
				}
			}()
		}
	}
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
