# UEC switch model -- user guide

Version 1.0 (2026-10-28). This guide covers the delivered headers, library,
smoke tests, example, console, configuration, and the integration boundary.

## 1. What is in the box

| Path | Contents |
|---|---|
| `include/` | Public headers (switch, ports, pcap, config, UET endpoint, MR, pool, CC, TSS, INC, PCM, CBFC, PFC) |
| `lib/libuec_model.a` | Prebuilt static library: switch core (`uec_switch.o`) and TSS path (`uec_uet_tss_path.o`) |
| `smoke/` | Green self-tests and one red test |
| `example/` | Two-endpoint WRITE/READ example |
| `console/` | Interactive console (SystemC) |
| `config/` | YAML profiles (`default.yaml`, `s2_alt.yaml`) |
| `tools/` | pcap check/diff and coverage helpers |

The model is source-compatible with C++14. The switch core and console use
SystemC 2.3.4. TSS uses OpenSSL `libcrypto` (AES-256-GCM and HKDF-SHA256).
The UET endpoint headers alone need neither SystemC nor OpenSSL unless TSS is
enabled.

## 2. Build and run

```sh
export SYSTEMC_HOME=/opt/tools/systemc2.34     # your SystemC prefix

cd smoke
make                                            # three green tests + red target
./tb_uec_smoke                                  # UEC_SMOKE PASS cases=4
./tb_uec_tss_smoke                              # UEC_TSS_SMOKE PASS cases=4
LD_LIBRARY_PATH=$SYSTEMC_HOME/lib-linux64 ./tb_uec_switch_smoke
make red && ./tb_uec_tss_red                    # UEC_TSS_RED FAIL (expected)

cd ../example && make && ./uec_example          # UEC_EXAMPLE PASS bytes=64

cd ../console && make
printf 'info\nstats 0\nrun 1000\nquit\n' | \
  LD_LIBRARY_PATH=$SYSTEMC_HOME/lib-linux64 ./uec_console ../config/default.yaml
```

The red binary is expected to fail: it proves the GCM tag check is active in
the green build. The release gate runs the same commands after stripping
comments and removing internal identifiers.

## 3. Switch API (`include/uec_switch.h`)

`UecSwitch` is a SystemC module with one input and one output `sc_fifo<UecFrame>`
per port:

```cpp
UecSwitch sw("sw", 4);
sw.rx[0]->write(frame);              // inject at ingress 0
UecFrame out;
if (sw.tx[1]->nb_read(out)) { ... }  // read egress 1
sc_start(10, SC_NS);                 // advance the model
```

Tables and policy are configured through C++ calls, not a control protocol:
`add_l2`, `add_l3_ipv4`, `add_l3_ipv6`, `add_vlan`, `add_mcast`, `add_ecmp`,
`set_qos`, `set_features`, `set_features_ex`, `set_ids`, `set_port_rate`,
`set_egress_shaper`, `set_pfc_thresholds`, `set_cbfc_credits`,
`set_cbfc_vc_mode`, `set_cbfc_remote_cf`, `set_inject`.
Per-port counters (`UecPortStats`) include packets/bytes, drops, shaper defer,
latency min/avg/max, and forwarding/flood/drop counts.

`UecFrame` carries the L2 preamble fields, parsed L3/L4 fields, CSIG/UFH
fields, the payload, and the egress FCS.

## 4. UET endpoint API (`include/uec_uet_endpoint.h`)

`Endpoint` is an OS-independent packet-level UET endpoint. Frames are
exchanged through `std::function<void(const std::vector<uint8_t>&)>`:

```cpp
EndpointConfig ca = ...;             // MAC/IP/PDC/job/keys
Endpoint host(ca), target(cb);
host.set_tx([&](const auto& f) { target.on_frame(f); });
target.set_tx([&](const auto& f) { host.on_frame(f); });

host.send_write(0x1000, data);       // WRITE
Completion c;
host.poll(c);                        // completion / READ data
host.send_read(0x1000, len);
host.send_send(data);
host.send_atomic(off, op, dt, operand, fetch);
```

Supported request types: WRITE, SYNC_WRITE, READ, SEND, ATOMIC, FETCH_ATOMIC
(with CSWAP family). Request header forms: SMALL/MEDIUM/STD. WRITE/SEND
support SOM/EOM multi-packet messages; READ responses support chunking and
reassembly. Transport features: RUD/ROD, cumulative ACK, ACK_CC with 64-bit
SACK, RTO and NACK retransmission, duplicate suppression, 32-bit PSN wrap,
multi-PDC receive state, and an error-code matrix.

Target-side features: MR table (mkey and JobID modes, permissions, PID/RI,
SEND match bits), buffer pools, SOM+HD completion data, INC-over-SEND, and a
functional congestion-control runtime (cwnd gate, CE/RTO, PCM control table).

## 5. TSS

`TssEngine` (header) implements the UET security envelope: 12/16-byte TSS
header, AES-256-GCM, TSC replay window, previous/current key rotation, and
DIRECT plus cluster/server HKDF-SHA256 key derivation. The endpoint wiring is
provided by `uec_uet_tss_path.h`: an endpoint with `tss_enable` seals
data-bearing packets at egress and verifies them before decoding at ingress.
The implementation is in the library (`uec_uet_tss_path.o`); register it once
with `uet_tss_path_register()` before constructing TSS endpoints.
TSS configuration fields: `tss_enable`, `tss_sdi`, `tss_ssi`, `tss_use_ssi`,
`tss_kdf` (0 DIRECT, 1 cluster, 2 server), `tss_key[32]`.
This is a functional subset, not a crypto-audited implementation; key
management is configuration-injected and there is no management plane.

## 6. Port signal contract

`include/uec_port_if.h` defines the DUT-facing boundary: one byte per beat with
`sof`/`eof`, a `ready` backpressure input, and bounded queues. A customer DUT
implements `PortSource` (frames it produces) and `PortSink` (frames it accepts).
`send_frame`/`recv_frame` convert between whole frames and beats. The model
does not define a control protocol, register bus, or PHY below this boundary.
See `PORT_SIGNAL_CONTRACT.md` for the full contract.

## 7. Configuration (`config/*.yaml`)

The YAML subset is parsed by `include/uec_config.h`. Keys used by the shipped
profiles:

- `ports.count`, `ports.rates`, `ports.mtu_bytes`, `ports.min_frame_bytes`
- `tc.count`, `tc.names`, `tc.dscp_to_tc.*`
- `scheduler.high`, `scheduler.med_low`, `scheduler.med_weight`,
  `scheduler.low_weight`
- `buffer.cell_bytes`, `buffer.pool_bytes`, `buffer.per_port_headroom_bytes`,
  `buffer.thresholds_frac.*`
- `ecn.enabled`, `ecn.mark_on_dequeue`
- `trim.enabled`, `trim.min_trim_size_bytes`, `trim.update_ip_len_checksum`,
  `trim.update_fcs`, `trim.dscp_trimmed`, `trim.dscp_trimmed_last_hop`
- `features.*` (l2, l3_ipv4, l3_ipv6, vlan, ecmp, multicast, ufh, csig,
  cbfc, pfc, inc_sep)
- `cbfc.num_vc`, `cbfc.window`; `pfc.xoff`, `pfc.xon`, `pfc.quanta`
- `console.*`

`uec_cfg::load_config()` and `uec_cfg::apply_config()` apply a profile at
runtime without recompiling.

## 8. Console

`uec_console [config.yaml]` reads commands from stdin and prints `CONSOLE_*`
lines for scripting:

```
info | probe <port> | stats [port] | queue <port> [tc] | trim <port>
pcap load <file> [port] | pcap save <file> [port]
run <ns> | quit
```

`run` advances SystemC time. `pcap load` injects frames at an ingress port;
`pcap save` drains an egress port. The console requires SystemC and the
static library.

## 9. Tests and coverage

The green smoke tests cover the endpoint transport (WRITE/READ/SEND/RTO), TSS
endpoint wiring (seal/open, tamper, replay, fresh TSC on retry), and switch
forwarding/flood/TC classification. The red test covers the GCM tag check.
The pcap helpers in `tools/` check frame fields and byte-diff two captures.
The model's internal development suite (not shipped) additionally covers
ECN/trim/PFC/CBFC/CSIG/UFH/INC/PCM/CC/MR/pool/PDC/error-matrix/multi-hop
cases; the public smoke set is a representative subset.

Known gaps in the public surface: there is no ioctl ABI, no DTS loader, and no
`MODEL_TRACE` environment switch. Configuration is the C++ API plus YAML, and
the console prints the observable state. These are documented in
`NOT_SUPPORTED.md` rather than silently omitted.

## 10. Limitations

See `NOT_SUPPORTED.md`. In short: no PHY/PCS/FEC/serdes/optics, no control
plane/register bus, no Linux driver or WQ/CQ rings, no line-rate/resource/
timing claims, no CtlOS/LLR modeling, no TSS management plane, and TSS/PCM/CC
are functional subsets. The model is a packet-level functional model.
