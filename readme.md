# PCAP Parser — Classic `.pcap` File Reader in C

A minimal and educational PCAP parser written in C.
It can read classic libpcap (`.pcap`) files, correctly handle endianness, extract packet metadata, and expose raw frame bytes for higher-level protocol decoding.

This project is suitable for:

* Students learning network forensics
* Developers building IDS/IPS features
* Hobbyists studying low-level packet formats
* Anyone wanting a dependency-free reference parser

---

## Features

* Reads classic PCAP (global header + packet records)
* Handles magic numbers and endianness detection
* Iterates through packets safely
* Extracts timestamps, captured length, original length
* Provides raw frame bytes for protocol analysis
* Pure ANSI C implementation, portable across systems
* No external dependencies required

---

## Repository Structure

```
pcap-parser/
├── lib/
│   └── pcap-master.h
├── examples/
│   └── http.cap
├── main.c
├── README.md
└── LICENSE
```

---

## Short Technical Overview

A classic `.pcap` file is composed of:

1. Global Header (24 bytes)
2. Repeating packet blocks consisting of:

   * Packet Header (16 bytes)
   * Packet Data (`incl_len` bytes)

The parser processes each element according to the libpcap file format specification.

---

## Building

Requires GCC or Clang.

Compile the parser:

```bash
gcc -o pcap_reader main.c
```

Run it with a PCAP file:

```bash
./pcap_reader examples/http.cap
```

---

## Example Output

```
PCAP Global Header:
  Version:     2.4
  Thiszone:    0
  Sigfigs:     0
  Snaplen:     65535
  Network DLT: 1

Packet #1:
  Timestamp:   1694143831.120304
  Captured:    74 bytes
  Original:    74 bytes
  First bytes: ff ff ff ff ...

Packet #2:
  ...
```

---

## Roadmap

### v1.0 – Core Parser (Completed)

* Global header parsing
* Packet header parsing
* Endianness detection
* Safe packet iteration

### v1.1 – Protocol Layer Decoders

* Ethernet header decoding
* IPv4 and IPv6 parsing
* UDP/TCP header extraction
* 5-tuple output (src/dst IP, ports, protocol)

### v1.2 – Library API

* Convert executable into a small reusable library
* Add `pcap_open`, `pcap_next`, `pcap_close`
* Document parsing API with examples

### v2.0 – Advanced Features

* TCP stream reassembly
* Export packets to JSON
* SQLite backend for indexing
* Wireshark-style hexdump viewer

---

## Contributing

Contributions and pull requests are welcome.
Bug reports, feature proposals, and improvements help the project grow.

---

## License

Released under the MIT License.
