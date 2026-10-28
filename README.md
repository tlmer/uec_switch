# uec_switch

UEC 1.1 switch model and UET endpoint model. The switch is a SystemC
packet-level model (forwarding, QoS, ECN, trim, CSIG/UFH, PFC/CBFC, INC/PCM,
pcap, console); the UET endpoint model implements the UEC wire format,
PDS/SES transport, MR, retransmission, congestion control, and TSS. Every
switch port is a plain byte-stream signal boundary, so a customer DUT attaches
without a Linux OS or a simulator.

## Contents

```
include/                 public headers
lib/libuec_model.a       static model library
smoke/                   green and red self-tests
example/                 minimal endpoint example
console/                 standalone interactive console
config/                  YAML profiles
tools/                   pcap check/diff and coverage helpers
USER_GUIDE.md            API, config, console, testcases, limits
PORT_SIGNAL_CONTRACT.md  per-port byte-stream contract for DUT attach
NOT_SUPPORTED.md         scope, boundaries, and checklist mapping
```

## Features

- Switch fabric: 2..64 ports, L2 learning/aging, VLAN/QinQ, IPv4/IPv6,
  ECMP + flowlet, multicast snooping, UFH_32/16, compact/wide CSIG transit.
- QoS: 3 traffic classes, strict priority + WRR, shared buffer, ECN marking,
  packet trimming (IPv4/IPv6 length/checksum, Ethernet FCS), PFC, CBFC
  (32 VCs, cross-device CF/CC), egress shaper, per-port counters and latency.
- Packet capture and replay: pcap load/save; deterministic duplicate/drop
  injection for red tests.
- INC SEP (reduce/barrier, integer and floating-point types) and PCM
  primitives/control table.
- UET endpoint model: Ethernet/IPv4/UDP wire format, PDS/SES, CRC32C,
  WRITE/READ/SEND/ATOMIC, SMALL/MEDIUM/STD headers, SOM/EOM reassembly,
  jumbo frames, MR authorization, multi-PDC, RUD/ROD, ACK/ACK_CC + SACK,
  RTO/NACK retransmit, READ chunking, error matrix, MR lifecycle/pooling,
  INC over SEND, NSCC-style congestion control, TSS (AES-256-GCM, DIRECT and
  cluster/server KDF, TSC replay window, key rotation, endpoint wiring).
- Port signal boundary: `PortBeat`/`PortSource`/`PortSink`/`PortBeatQueue` for
  attaching a customer DUT without an OS.

## Scope

The model stops at the switch port byte stream. PHY/PCS/FEC/serdes/optics,
the control plane and register bus, a Linux driver, and host WQ/CQ rings are
outside this model. TSS is a functional subset and is not crypto-audited.
See `NOT_SUPPORTED.md` for the full boundary and the customer checklist
mapping.

## Quick check

```sh
cd smoke && make && make red
./tb_uec_smoke                              # UEC_SMOKE PASS
./tb_uec_tss_smoke                          # UEC_TSS_SMOKE PASS
LD_LIBRARY_PATH=$SYSTEMC_HOME/lib-linux64 ./tb_uec_switch_smoke
./tb_uec_tss_red                            # UEC_TSS_RED FAIL (expected)
cd ../example && make && ./uec_example      # UEC_EXAMPLE PASS
cd ../console && make
printf 'info\nstats 0\nrun 1000\nquit\n' | \
  LD_LIBRARY_PATH=$SYSTEMC_HOME/lib-linux64 ./uec_console ../config/default.yaml
```

Requirements: C++14 compiler; SystemC 2.3.4 for the switch core and console;
OpenSSL `libcrypto` for TSS; pthread. Set `SYSTEMC_HOME` to the SystemC
installation prefix (default `/opt/tools/systemc2.34` in the Makefiles).
