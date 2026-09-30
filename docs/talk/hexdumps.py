#!/usr/bin/env python3
"""Render the annotated `hexdump -C` slides into index.html.

The frames below were captured in the lab with:

    /tmp/mytcp -i tap0 -app http      -pcap captures/talk-http       # + ping, curl
    /tmp/mytcp -i tap0 -app https-diy -pcap captures/talk-https-diy  # + curl -k

and read back with:

    jq -r 'select(.n==7).data' captures/talk-http.jsonl | xxd -r -p | hexdump -C

captures/ is gitignored, so the bytes are copied here. Each slide lives
between <!-- hexdump:NAME --> markers; rerun this script after editing.
"""

import html
import pathlib
import re

FRAMES = {
    "arp-req": "ffffffffffffeeeaf30f573208060001080006040001eeeaf30f57320a0000010000000000000a000002",
    "arp-rep": "eeeaf30f5732020000000002080600010800060400020200000000020a000002eeeaf30f57320a000001",
    "ping": "020000000002eeeaf30f5732080045000054c6d3400040015fd30a0000010a000002080040fe000700018039bc6a00000000b982020000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
    "syn": "020000000002eeeaf30f573208004500003c56ea40004006cfcf0a0000010a000002c68a005013e85a6600000000a002faf02f000000020405b40402080aa1a8333b0000000001030307",
    "synack": "eeeaf30f573202000000000208004500002800020000400666cc0a0000020a0000010050c68a000003e813e85a675012ffff62be0000",
    "ack": "020000000002eeeaf30f573208004500002856eb40004006cfe20a0000010a000002c68a005013e85a67000003e95010faf067ce0000",
    "http-get": "020000000002eeeaf30f573208004500007056ec40004006cf990a0000010a000002c68a005013e85a67000003e95018faf091b10000474554202f20485454502f312e310d0a486f73743a2031302e302e302e320d0a557365722d4167656e743a206375726c2f372e38382e310d0a4163636570743a202a2f2a0d0a0d0a",
    "tls-get": "020000000002aa0baa94e9f308004500008d13f34000400612760a0000010a000002ce9e01bb6f3a1b39000006545018f95ac9130000170303006091a20ad98a04d79f3810fffeb5c37707da7769853ca0878e2c7ce85456b3a1800bb3b9990898a44841014f6ed81ed1929b37442d7af68a886645c208886b41604027021aa37352918a843c50cd887e9aad265f2a1ce5abd38a80393471bf80c9",
}

def shade(fields):
    """Colour = layer, shade = field: consecutive fields of one layer alternate
    between a bright banded shade (1) and a darker plain one (2)."""
    seen, out = {}, []
    for start, end, layer, *rest in fields:
        if layer == "f0":
            out.append((start, end, layer, *rest))
            continue
        n = seen.get(layer, 0)
        seen[layer] = n + 1
        out.append((start, end, f"{layer}{n % 2 + 1}", *rest))
    return out


def dump(data: bytes, spans, skip=0, cls="hexdump") -> str:
    """hexdump -C [-s skip], with each field's bytes wrapped in one coloured span."""
    colour, field = [None] * len(data), [None] * len(data)
    for n, (start, end, c) in enumerate(spans):
        for i in range(start, min(end, len(data))):
            colour[i], field[i] = c, n

    def runs(idx, cell, sep):
        """Group bytes into one span per field so the band doesn't break between bytes."""
        out, prev = [], None
        for k, i in enumerate(idx):
            s = sep(k)
            if field[i] is not None and field[i] == prev:
                out[-1][1] += s + cell(i)
            else:
                out.append([i, cell(i), s])
            prev = field[i]
        return "".join(
            s + (f'<span class="{colour[i]}">{t}</span>' if colour[i] else t) for i, t, s in out
        )

    lines = []
    for off in range(skip, len(data), 16):
        idx = range(off, min(off + 16, len(data)))
        hex_sep = lambda k: "  " if k == 8 else (" " if k else "")
        width = sum(len(hex_sep(k)) + 2 for k in range(len(idx)))
        hex_part = runs(idx, lambda i: f"{data[i]:02x}", hex_sep)
        ascii_part = runs(
            idx,
            lambda i: html.escape(chr(data[i]) if 0x20 <= data[i] <= 0x7E else ".", quote=False),
            lambda k: "",
        )
        lines.append(f"{off:08x}  {hex_part}{' ' * (48 - width)}  |{ascii_part}|")
    lines.append(f"{len(data):08x}")
    return f'<pre class="{cls}"><code class="nohighlight" data-noescape>' + "\n".join(lines) + "</code></pre>"


def chip(c):
    return f'<span class="chip {c}"></span>' if c else ""


def span_range(start, end):
    return f"{start}" if end - start == 1 else f"{start}–{end - 1}"


def spans(fields):
    return [(f[0], f[1], f[2]) for f in fields]


def table(head, fields):
    """fields: (start, end, colour, name, value...) — one row per field."""
    th = "".join(f"<th>{h}</th>" for h in ["", "Bytes"] + head)
    rows = []
    for start, end, c, *cells in fields:
        tds = "".join(f"<td>{x}</td>" for x in [chip(c), span_range(start, end)] + cells)
        rows.append(f"            <tr>{tds}</tr>")
    return (
        '        <table class="compact hexlegend">\n'
        f"          <thead><tr>{th}</tr></thead>\n"
        "          <tbody>\n" + "\n".join(rows) + "\n          </tbody>\n        </table>"
    )


def note(text):
    return f'        <p class="soft hexnote">{text}</p>'


def label(text):
    return f'        <p class="hexlabel">{text}</p>'


def b(name):
    return bytes.fromhex(FRAMES[name])


def section(sid, title, path, *parts):
    inner = "\n".join(parts)
    return (
        f'      <section id="{sid}">\n'
        f"        <h2>{title}</h2>\n"
        f'        <p class="code-path">{path}</p>\n'
        f"{inner}\n"
        "      </section>"
    )


C = lambda s: f"<code>{s}</code>"
# a link back to the slide that introduces this layer; browser Back returns
J = lambda text, sid: f'<a class="jump" href="#/{sid}">{text}</a>'

# (start, end, layer, name, values…): layer is eth/arp/ip/icmp/tcp/http/tls,
# or f0 for grey = "explained on another slide"
ETH_READ = shade([
    (0, 6, "eth", J(f"Destination MAC ({C('Dst')})", "struct-eth"), "ff:ff:ff:ff:ff:ff = broadcast: everyone on the link"),
    (6, 12, "eth", J(f"Source MAC ({C('Src')})", "struct-eth"), "ee:ea:f3:0f:57:32 = the kernel’s side of tap0"),
    (12, 14, "eth", J(f"EtherType ({C('Type')})", "struct-eth"), f"08 06 = 0x0806 = ARP, so {C('arp.Parse')} gets the rest"),
    (14, 42, "f0", J(f"Payload ({C('Payload')})", "hex-arp-header"), "28 bytes: the ARP message, unpacked in the ARP section"),
])

ARP = shade([
    (0, 14, "f0", J("Ethernet header", "hex-eth"),
     "to ff:ff:ff:ff:ff:ff (everyone), from ee:ea:f3:0f:57:32",
     "to ee:ea:f3:0f:57:32 (only the asker), from 02:00:00:00:00:02"),
    (14, 16, "arp", "Hardware type", "00 01 = Ethernet", "same"),
    (16, 18, "arp", "Protocol type", "08 00 = IPv4", "same"),
    (18, 19, "arp", "Hardware address length", "06 = a MAC is 6 bytes", "same"),
    (19, 20, "arp", "Protocol address length", "04 = an IPv4 address is 4 bytes", "same"),
    (20, 22, "arp", J(f"Operation ({C('Op')})", "struct-arp"), "00 01 = request", "00 02 = reply"),
    (22, 28, "arp", J(f"Sender MAC ({C('SHA')})", "struct-arp"), "ee:ea:f3:0f:57:32", "<strong>02:00:00:00:00:02</strong> ← the answer"),
    (28, 32, "arp", J(f"Sender IP ({C('SPA')})", "struct-arp"), "0a 00 00 01 = 10.0.0.1", "0a 00 00 02 = 10.0.0.2"),
    (32, 38, "arp", J(f"Target MAC ({C('THA')})", "struct-arp"), "00:00:00:00:00:00 = unknown (the question)", "ee:ea:f3:0f:57:32"),
    (38, 42, "arp", J(f"Target IP ({C('TPA')})", "struct-arp"), "0a 00 00 02 = 10.0.0.2", "0a 00 00 01 = 10.0.0.1"),
])

IPV4 = shade([
    (14, 15, "ip", "Version + header length", "45: 4 = IPv4, 5 × 4 = 20-byte header"),
    (15, 16, "ip", "Traffic class (DSCP/ECN)", "00 = ordinary traffic"),
    (16, 18, "ip", "Total length", "00 54 = 84 bytes: this header plus the ICMP message"),
    (18, 20, "ip", "Identification", "c6 d3: only used if the packet gets split up"),
    (20, 22, "ip", "Flags + fragment offset", "40 00 = “don’t fragment”, and this isn’t a fragment"),
    (22, 23, "ip", "Time to live", "40 = 64 hops before a router throws it away"),
    (23, 24, "ip", f"Protocol ({C('Proto')})", f"01 = ICMP, so {C('icmp.ParseEcho')} gets the payload"),
    (24, 26, "ip", "Header checksum", "5f d3: covers these 20 bytes only"),
    (26, 30, "ip", f"Source IP ({C('Src')})", "0a 00 00 01 = 10.0.0.1"),
    (30, 34, "ip", f"Destination IP ({C('Dst')})", "0a 00 00 02 = 10.0.0.2"),
])

ICMP = shade([
    (34, 35, "icmp", f"Type ({C('Type')})", "08 = echo request (a reply is 00)"),
    (35, 36, "icmp", "Code", "00: echo has no sub-types"),
    (36, 38, "icmp", "Checksum", "40 fe: covers the whole ICMP message"),
    (38, 40, "icmp", f"Identifier ({C('ID')})", "00 07: which ping process sent it"),
    (40, 42, "icmp", f"Sequence number ({C('Seq')})", "00 01 = the first ping"),
    (42, 58, "icmp", "Data: send time", "80 39 bc 6a … read <strong>little-endian</strong> = 1790720384 s + 164537 µs = 22:19:44.164537 UTC"),
    (58, 98, "icmp", "Data: filler", "10 11 12 … 37: a counting pattern up to 56 bytes of data"),
])

T = lambda text: J(text, "struct-tcp")
TCP_SYN = shade([
    (0, 34, "f0", J("Ethernet + IPv4 headers", "hex-ipv4"), "as in the ping · IPv4 protocol 06 = TCP"),
    (34, 36, "tcp", T(f"Source port ({C('SrcPort')})"), "c6 8a = 50826: a random free port the client’s kernel picked"),
    (36, 38, "tcp", T(f"Destination port ({C('DstPort')})"), "00 50 = 80: the port our stack is listening on"),
    (38, 42, "tcp", T(f"Sequence number ({C('Seq')})"), "13 e8 5a 66 = 333994598: the client’s starting number, chosen to be hard to guess"),
    (42, 46, "tcp", T(f"Acknowledgment ({C('Ack')})"), "00 00 00 00: nothing to acknowledge yet"),
    (46, 47, "tcp", "Header length", "a0: top 4 bits, a = 10 × 4 = 40 bytes (20 fixed + 20 of options)"),
    (47, 48, "tcp", T(f"Flags ({C('Flags')})"), "02 = SYN: “let’s talk; my bytes will be numbered from here”"),
    (48, 50, "tcp", T(f"Window ({C('Window')})"), "fa f0 = 64240 bytes the client can take before we must wait"),
    (50, 52, "tcp", "Checksum", "2f 00: covers the TCP header and data, plus both IPs"),
    (52, 54, "tcp", "Urgent pointer", "00 00: unused (almost nobody uses it)"),
    (54, 74, "f0", J("Options", "hex-tcp-options"), "20 bytes, on the next slide · no payload: the application has not spoken yet"),
])

TCP_OPTS = shade([
    (0, 54, "f0", J("Ethernet, IPv4, TCP header", "hex-tcp"), "the previous slide"),
    (54, 58, "tcp", "Max segment size (MSS)", "02 04 05 b4: kind 2, length 4, 1460 = “send me at most 1460 bytes per segment”"),
    (58, 60, "tcp", "SACK permitted", "04 02: “I can say exactly which pieces I’m missing”"),
    (60, 70, "tcp", "Timestamps", "08 0a + curl’s clock a1 a8 33 3b + 00 00 00 00 (no echo yet): helps measure round trips"),
    (70, 71, "tcp", "No-op", "01: padding, so the next option lines up on 4 bytes"),
    (71, 74, "tcp", "Window scale", "03 03 07: “multiply my window by 2<sup>7</sup> = 128”, for windows over 64 KB"),
])

# Whole frame, not just seq/ack/flags. Byte 46 is the header length; leaving
# it out put a grey byte between the acknowledgment and the flags.
HANDSHAKE = shade([
    (0, 14, "eth"),
    (14, 34, "ip"),
    (34, 38, "tcp"),   # ports
    (38, 42, "tcp"),   # sequence number
    (42, 46, "tcp"),   # acknowledgment
    (46, 48, "tcp"),   # header length + flags
    (48, 54, "tcp"),   # window, checksum, urgent pointer
    (54, 74, "tcp"),   # options; only the SYN has any
])


def band(spans, start):
    return next(c for s, _, c in spans if s == start)
TCP_GET = shade([
    (0, 14, "eth", J("Ethernet header", "hex-eth"), "type 08 00 = IPv4"),
    (14, 34, "ip", J("IPv4 header", "hex-ipv4"), "same fields as the ping · length 00 70 = 112 · protocol 06 = TCP"),
    (34, 38, "tcp", T(f"Ports ({C('SrcPort')} → {C('DstPort')})"), f"c6 8a → 00 50 = 50826 → 80, {J('same as the SYN', 'hex-tcp')}"),
    (38, 42, "tcp", T(f"Sequence number ({C('Seq')})"), "13 e8 5a 67 = the SYN’s start + 1: the first byte of this payload"),
    (42, 46, "tcp", T(f"Acknowledgment ({C('Ack')})"), "00 00 03 e9 = 1001: “got everything before 1001” (we started at 1000)"),
    (46, 48, "tcp", T(f"Header length + flags ({C('Flags')})"), "50 18: 5 × 4 = 20-byte header · 0x18 = PSH + ACK"),
    (48, 50, "tcp", T(f"Window ({C('Window')})"), "fa f0 = 64240 more bytes curl can take"),
    (50, 52, "tcp", "Checksum", "91 b1: covers TCP header, payload and both IPs"),
    (52, 54, "tcp", "Urgent pointer", "00 00: unused"),
    (54, 126, "http", J(f"Payload ({C('Payload')})", "http-parse"), f"72 bytes of HTTP: {C('GET / HTTP/1.1')}, Host, User-Agent, Accept, blank line"),
])

# The first segment that carries application bytes. TCP does not interpret them.
TCP_DATA = shade([
    (0, 14, "eth", J("Ethernet header", "hex-eth"), "same link as the handshake"),
    (14, 34, "ip", J("IPv4 header", "hex-ipv4"), "protocol 06 = TCP · 112 bytes in total"),
    (34, 54, "tcp", J("TCP header", "hex-handshake"), "20 bytes, no options · 50 18 = PSH + ACK · seq is the client’s start + 1 · ack 1001"),
    (54, 126, "app", "Payload", "72 bytes the application sent. TCP numbers them and delivers them in order. It does not read them."),
])

LAYERS_PLAIN = shade([(0, 14, "eth"), (14, 34, "ip"), (34, 54, "tcp"), (54, 126, "http")])
LAYERS_TLS = shade([(0, 14, "eth"), (14, 34, "ip"), (34, 54, "tcp"),
                    (54, 59, "tls"), (59, 67, "tls"), (67, 139, "tls"), (139, 155, "tls")])

READ_CMD = (
    "# mytcp logs every frame to captures/<name>.jsonl (and a .pcap for Wireshark)\n"
    "# pick frame 0, turn its hex back into bytes, and dump them\n"
    "jq -r 'select(.n==0).data' captures/talk-http.jsonl | xxd -r -p | hexdump -C"
)

SLIDES = {}

SLIDES["read"] = (
    "Parsing means reading bytes at fixed offsets",
    section(
        "hex-eth",
        "An Ethernet frame, as real bytes",
        "captures/talk-http.jsonl · frame 0 (an ARP request)",
        '        <pre><code class="language-bash" data-trim>' + html.escape(READ_CMD, quote=False) + "</code></pre>",
        "        " + dump(b("arp-req"), spans(ETH_READ)),
        table(["Field", "Value"], ETH_READ),
        note("Each line: where it starts in hex (00000010 = byte 16), 16 bytes in hex, "
             "then the same bytes as text (<code>.</code> = not printable)."),
        note("Numbers longer than a byte are <strong>big-endian</strong>, biggest byte first "
             "(“network byte order”): 08 06 is 0x0806. Go reads them with "
             "<code>binary.BigEndian.Uint16</code>."),
    ),
)

SLIDES["arp"] = (
    "Answering “who has 10.0.0.2?”",
    section(
        "hex-arp-header",
        "A real ARP request and reply: the header",
        "captures/talk-http.jsonl · the first two frames of the capture",
        label("<strong>Frame 0</strong> · kernel → everyone · the question: “who has 10.0.0.2?”"),
        "        " + dump(b("arp-req"), spans(ARP[:6])),
        label("<strong>Frame 1</strong> · mytcp → kernel · our answer: “10.0.0.2 is at 02:00:00:00:00:02”"),
        "        " + dump(b("arp-rep"), spans(ARP[:6])),
        table(["Field", "Request (frame 0)", "Reply (frame 1)"], ARP[:6]),
        note("One packet format for both directions: these six fields match byte for byte, except the operation."),
    )
    + "\n\n"
    + section(
        "hex-arp-addr",
        "A real ARP request and reply: the addresses",
        "captures/talk-http.jsonl · the first two frames of the capture",
        label("<strong>Frame 0</strong> · kernel → everyone · the question: “who has 10.0.0.2?”"),
        "        " + dump(b("arp-req"), spans(ARP[6:])),
        label("<strong>Frame 1</strong> · mytcp → kernel · our answer: “10.0.0.2 is at 02:00:00:00:00:02”"),
        "        " + dump(b("arp-rep"), spans(ARP[6:])),
        table(["Field", "Request (frame 0)", "Reply (frame 1)"], ARP[6:]),
        note("The reply swaps sender and target, and fills in the one thing the request didn’t know: our MAC."),
    ),
)

SLIDES["ping"] = (
    "Answering a ping",
    section(
        "hex-ipv4",
        "A real ping: the IPv4 header",
        "captures/talk-http.jsonl · frame 2 (from <code>ping -c 1 10.0.0.2</code>)",
        "        " + dump(b("ping"), spans(IPV4)),
        table(["Field", "Value"], IPV4),
        note(f"Grey: the {J('Ethernet header', 'hex-eth')} (bytes 0–13, type 08 00 = IPv4) "
             f"and the {J('ICMP message', 'hex-icmp')} (bytes 34–97, next slide)."),
    )
    + "\n\n"
    + section(
        "hex-icmp",
        "A real ping: the ICMP message",
        "captures/talk-http.jsonl · frame 2, bytes 34–97",
        "        " + dump(b("ping"), spans(ICMP)),
        table(["Field", "Value"], ICMP),
        note("Headers are big-endian, but ping writes its send time in the CPU’s own order (little-endian on x86 and ARM), "
             "because only ping reads it back. Read big-endian, those 8 bytes would be 9.2 × 10<sup>18</sup> seconds."),
    ),
)

SLIDES["tcp"] = (
    "A TCP segment, as a Go struct",
    section(
        "hex-tcp",
        "A real TCP segment: opening a connection",
        "captures/talk-http.jsonl · frame 4 · client → mytcp",
        "        " + dump(b("syn"), spans(TCP_SYN)),
        table(["Field", "Value"], TCP_SYN),
        note("No application data. A SYN only opens the connection; bytes for an app come later, after both sides agree."),
    )
    + "\n\n"
    + section(
        "hex-tcp-options",
        "The SYN’s options, and why we ignore them",
        "captures/talk-http.jsonl · frame 4, bytes 54–73",
        "        " + dump(b("syn"), spans(TCP_OPTS)),
        table(["Option", "Bytes on the wire"], TCP_OPTS),
        note("Options are offers. Our SYN+ACK sends none back, so the kernel on curl’s side turns off SACK, timestamps and "
             "window scaling, and falls back to the default 536-byte segments. Everything still works, just less efficiently."),
    )
    + "\n\n"
    + section(
        "hex-handshake",
        "The three-way handshake, in bytes",
        "captures/talk-http.jsonl · frames 4, 5 and 6",
        label("<strong>Frame 4</strong> · curl → mytcp · SYN"),
        "        " + dump(b("syn"), HANDSHAKE, cls="hexdump tight stack3"),
        label("<strong>Frame 5</strong> · mytcp → curl · SYN+ACK"),
        "        " + dump(b("synack"), HANDSHAKE, cls="hexdump tight stack3"),
        label("<strong>Frame 6</strong> · curl → mytcp · ACK"),
        "        " + dump(b("ack"), HANDSHAKE, cls="hexdump tight stack3"),
        '        <p class="hexkey">'
        + chip(band(HANDSHAKE, 0)) + J("Ethernet", "hex-eth") + " "
        + chip(band(HANDSHAKE, 14)) + J("IPv4", "hex-ipv4") + " "
        + chip(band(HANDSHAKE, 34)) + "TCP ports "
        + chip(band(HANDSHAKE, 38)) + "Seq "
        + chip(band(HANDSHAKE, 42)) + "Ack "
        + chip(band(HANDSHAKE, 46)) + "header length + flags "
        + chip(band(HANDSHAKE, 48)) + "window, checksum, urgent "
        + chip(band(HANDSHAKE, 54)) + "options (SYN only)</p>",
        '        <table class="compact hexlegend">\n'
        "          <thead><tr><th>Frame</th><th>Direction</th>"
        f"<th>{chip(band(HANDSHAKE, 46))}Length + flags (bytes 46–47)</th>"
        f"<th>{chip(band(HANDSHAKE, 38))}Seq (bytes 38–41)</th>"
        f"<th>{chip(band(HANDSHAKE, 42))}Ack (bytes 42–45)</th></tr></thead>\n"
        "          <tbody>\n"
        "            <tr><td>4</td><td>curl → mytcp</td><td>a0 02 · SYN, 40-byte header</td><td>13 e8 5a 66 = 333994598 (curl’s start)</td><td>0</td></tr>\n"
        "            <tr><td>5</td><td>mytcp → curl</td><td>50 12 · SYN+ACK, 20-byte header</td><td>00 00 03 e8 = 1000 (ours; fixed so captures read easily)</td><td>333994599 = theirs + 1</td></tr>\n"
        "            <tr><td>6</td><td>curl → mytcp</td><td>50 10 · ACK, 20-byte header</td><td>333994599</td><td>00 00 03 e9 = 1001 = ours + 1</td></tr>\n"
        "          </tbody>\n        </table>",
    )
    + "\n\n"
    + section(
        "hex-tcp-data",
        "The first segment that carries data",
        "captures/talk-http.jsonl · frame 7 · same connection, next segment from the client",
        "        " + dump(b("http-get"), spans(TCP_DATA)),
        table(["Field", "Value"], TCP_DATA),
        note("The letters in the margin are the application’s. TCP does not know what they mean."),
    ),
)

SLIDES["http"] = (
    "HTTP: finding where a request ends",
    section(
        "hex-http",
        "One HTTP request, every layer at once",
        "captures/talk-http.jsonl · frame 7 of the same connection, after the handshake",
        "        " + dump(b("http-get"), spans(TCP_GET)),
        table(["Field", "Value"], TCP_GET),
        note(f"Same {J('three-way handshake', 'hex-handshake')} as before. The TCP header is now 20 bytes (no options); the new part is the payload."),
    ),
)

P, S = LAYERS_PLAIN, LAYERS_TLS
SLIDES["tls"] = (
    "Encrypting a record with AES-GCM",
    section(
        "hex-tls",
        "The same GET, plain and encrypted",
        "curl http://10.0.0.2/ · captures/talk-http.jsonl frame 7",
        "        " + dump(b("http-get"), P, cls="hexdump tight"),
        '        <p class="code-path">curl -k https://10.0.0.2/ through mintls · captures/talk-https-diy.jsonl frame 31</p>',
        "        " + dump(b("tls-get"), S, cls="hexdump tight"),
        '        <p class="hexkey">'
        + chip(P[0][2]) + J("Ethernet", "hex-eth") + " "
        + chip(P[1][2]) + J("IPv4", "hex-ipv4") + " "
        + chip(P[2][2]) + J("TCP", "hex-tcp") + " "
        + chip(P[3][2]) + J("HTTP", "hex-http") + " (72) "
        + chip(S[3][2]) + J("TLS header", "tls-record") + ": 17 = app data, 03 03 = TLS 1.2, 00 60 = 96 "
        + chip(S[4][2]) + J("nonce", "tls-seal") + " (8) "
        + chip(S[5][2]) + J("ciphertext", "tls-seal") + " (72) "
        + chip(S[6][2]) + J("tag", "tls-seal") + " (16)</p>",
        note("Bytes 0–53 have the same layout; only lengths, IDs, ports, sequence numbers, checksums and tap0’s MAC differ. "
             "96 = 8 + 72 + 16: the ciphertext is as long as the plain GET, so encryption hides the content, not the size."),
    ),
)


def main():
    path = pathlib.Path(__file__).with_name("index.html")
    s = path.read_text()
    for name, (anchor, body) in SLIDES.items():
        block = f"      <!-- hexdump:{name} -->\n{body}\n      <!-- /hexdump:{name} -->"
        pat = re.compile(rf"      <!-- hexdump:{name} -->.*?<!-- /hexdump:{name} -->", re.S)
        if pat.search(s):
            s = pat.sub(lambda _: block, s)
            continue
        h2 = s.index(f"<h2>{anchor}</h2>")
        end = s.index("</section>", h2) + len("</section>")
        s = s[:end] + "\n\n" + block + s[end:]
    path.write_text(s)


if __name__ == "__main__":
    main()
