# Scope, limitations, and checklist mapping

This model is a functional, packet-level UEC 1.1 model. It is not a PHY, a
control plane, a Linux driver, or a line-rate/resource estimate. The tables
below record what is supported, what is deliberately out of scope, and how the
customer checklist maps onto the delivered surface.

## 1. Out of scope

| Item | Reason |
|---|---|
| PHY / PCS / FEC / serdes / optics | Owned by the DUT or a MAC/PCS IP; no clock-domain or line-coding model |
| Control plane: register blocks, management bus, configuration protocol, ctrl frame semantics | Configuration is the C++ API plus YAML; the control plane belongs to the DUT or a control block |
| Linux driver, OS services, sysfs/proc | The model is OS-independent; no kernel interfaces |
| Host WQ/CQ rings, doorbells, owner bits, enable flags | Host control semantics; the RTL host path covers them |
| AXI4 / PCIe / DMA host interfaces | The model boundary is the switch port byte stream and the UET endpoint frame API |
| Line rate, latency guarantees, timing closure, area, resources | Functional model; statistics are model-level |
| CtlOS and LLR | Not modeled (the model is not a PHY/LLR implementation) |
| TSS management plane, key database, certificate handling | Keys are configuration-injected; TSS is a functional subset and is not crypto-audited |
| PCM runtime at the endpoint | PCM primitives and a control table are present; the runtime is engine-level |
| WQ/CQ in the endpoint model | Deliberately left to the RTL/control side |
| Multi-queue switch control | The switch exposes ports and C++ configuration, not queue-management rings |

## 2. Functional subsets

- **TSS**: DIRECT, cluster, and server KDF; AES-256-GCM; 48-bit TSC with a
  64-entry replay window; previous/current key rotation; endpoint seal/open.
  Not a compliance-certified or crypto-audited implementation.
- **Congestion control**: NSCC-style cwnd gate, additive increase, CE/RTO
  multiplicative decrease, PCM control table. Functional subset.
- **INC**: reduce/barrier, integer and floating-point types, group tables,
  multi-switch gateway; engine-level SEP.
- **PCM**: signal accumulation, atomic batches, EV table, ACK hooks, control
  table; functional primitives.
- **Switch**: 2..64 ports, 3 traffic classes, 32 CBFC VCs, 8 MB shared buffer
  profile; packet-level behavior, not hardware throughput.

## 3. Customer checklist mapping (20 items)

| # | Requirement | Status | Notes |
|---|---|---|---|
| 1 | AXI4 master/slave TLM interface | N/A | The switch boundary is a per-port byte stream; the UET endpoint API is frame-based. No AXI interface is needed. |
| 2 | AXI ID/outstanding configurable per DUT | N/A | No AXI. Equivalent configurables: port count, rates, TC/queue limits, CBFC credits, buffer size. |
| 3 | Single/multi-bit interrupt selected by DT | N/A | No interrupt controller or DT in the model; the console reports state and counters. |
| 4 | Bandwidth / latency / throughput statistics | Yes | Per-port packet/byte/drop/shaper counters and latency min/avg/max in `UecPortStats`; console `stats`. |
| 6 | ioctl callable from a UVM environment | Partial | The model exposes a C++ API and a console. There is no ioctl ABI in this release; a thin wrapper can be added without changing the model. |
| 7 | Independent build, no dependencies | Partial | Endpoint headers are dependency-free C++14. The switch core and console need SystemC; TSS needs OpenSSL `libcrypto`; pthread is a system library. No OS or simulator is required. |
| 8 | Host/root only; IP vendor/product coverage | N/A | This is a switch/endpoint model, not a Linux host-driver IP; there is no host-device mode split or vendor HAL table. |
| 9 | User guide | Yes | `USER_GUIDE.md` (English). |
| 10 | Console | Yes | `console/uec_console` with info/probe/stats/queue/trim/pcap/run/quit. |
| 11 | Same function/experience as Linux OS | N/A | No Linux driver; the model is OS-independent by design. Management visibility is the console and C++ API. |
| 12 | Linux proxy; test a DUT without an OS | Partial | The UET endpoint model is OS-independent and the switch exposes a DUT port boundary; it is not a Linux proxy. |
| 13 | RTL bridge / `.veo` templates | N/A | No AXI, so no AXI DPI bridge. The DUT hookup is the port signal contract in `PORT_SIGNAL_CONTRACT.md`. |
| 14 | Core files released as a binary library | Yes | `lib/libuec_model.a` plus public headers; model `.cpp` files are not shipped. |
| 15 | Linux driver prints reproduced | N/A | There is no Linux driver. The console prints `CONSOLE_*` state/counters; smoke tests print explicit PASS/FAIL lines. No `MODEL_TRACE` switch in this release. |
| 16 | Pure English, no Chinese comments | Yes | Release gate strips comments and scans for CJK in text and binaries. |
| 17 | DTS template and loader | N/A | No Linux/DT. Configuration uses the YAML profiles in `config/` and `uec_config.h`. |
| 18 | Linux utilities (lspci/setpci analogues) | N/A | Not applicable to a switch model; the console is the management surface. |
| 19 | Remove vendor-characteristic words from the database | Yes | Release gate scans for vendor names and internal identifiers. |
| 20 | Pack RTL-facing signals instead of expanding them | N/A | No RTL port bundle is shipped. The delivered boundary is the byte-stream port contract; a customer DUT owns its own PHY/RAM interfaces. |

## 4. Unified test practice (T1-T10)

| Item | Status | Notes |
|---|---|---|
| T1 DTS template + loader | N/A | YAML profiles + runtime loader instead |
| T2 Standard testcase set + ioctl channel | Partial | Smoke tests are the public testcase set; there is no ioctl/testcase registry in this release |
| T3 `MODEL_TRACE` environment switch | Partial | Console/state output and smoke PASS/FAIL lines; no environment trace switch |
| T4 Coverage output (tested / not tested) | Partial | The public smoke set is representative; the internal development suite is larger and not shipped |
| T5 `all` runs every test | Yes | `cd smoke && make test`, or `make && make red` |
| T6 Repeatable runs | Yes | All smoke binaries are stateless and rerunnable |
| T7 User-defined test blobs | N/A | No private blob format; custom stimulus can drive the port signals or endpoint API |
| T8 Console by category | Yes | info/probe/stats/queue/trim/pcap/run/quit |
| T9 Linux utilities available | N/A | No Linux user-space tools for a switch model |
| T10 Shader generation | N/A | No GPU/shader |
