# Switch model port signal contract

The external boundary of the model is a **per-port byte stream**. The control
plane and PHY/PCS/FEC are not modeled. A customer DUT attaches at these
signals; a future UEC control block attaches at the same signals.

## 1. Signals

One transmit and one receive group per port (`include/uec_port_if.h`):

| Signal | Direction | Meaning |
|---|---|---|
| `valid` | source -> sink | `data` is valid this beat (`PortSource::pop()` returned true) |
| `data[7:0]` | source -> sink | one byte |
| `sof` | source -> sink | this beat is the first byte of a frame |
| `eof` | source -> sink | this beat is the last byte (a single-byte frame sets both) |
| `ready` | sink -> source | the sink can accept this beat (`PortSink::ready()`); when low, the source must hold the data |

- Model -> DUT: the DUT implements `PortSink`.
- DUT -> model: the DUT implements `PortSource`.
- Reference implementation: `PortBeatQueue` (bounded, `drops()` is explicit;
  it never silently loses a beat) and `send_frame()`/`recv_frame()` for
  frame <-> beat conversion.

The boundary is a byte stream rather than a whole-frame API on purpose:
backpressure is the easiest thing for a DUT to get wrong, so `valid`/`ready`
timing, FIFO depth, and frame delimiters stay visible and testable.

## 2. Inside the boundary (model responsibility)

- L2/L3 lookup and forwarding, VLAN/QinQ, multicast, ECMP, TTL, UFH, CSIG,
  trim, ECN, PFC/CBFC engines, INC/PCM engines, statistics, and rate shaping.
- Internally the switch carries whole frames in `UecSwitch::rx[port]` and
  `tx[port]` (`sc_fifo<UecFrame>`). The external adapter maps them to the
  beats above. Both are the same boundary; externally only the signals matter.

## 3. Outside the boundary (not modeled)

| Not modeled | Reason |
|---|---|
| Control plane (register blocks, management bus, configuration protocol, ctrl frame semantics) | Configuration is the C++ API; the control plane belongs to the customer DUT or a control block |
| PHY / PCS / FEC / serdes / optics | Owned by the DUT or a MAC/PCS IP; the model does not abstract clock domains or line coding |
| Timing / area / resources | The model is functional and is not an implementation estimate |
| Host-side WQ/CQ rings, doorbells, owner bits, enable flags | Host control semantics; the boundary is at port frames. The RTL host path covers them, so the model does not build a second copy |

PFC/CBFC control frames and PDS ACK/NACK are part of the **data-plane
protocol** (they change forwarding and drop behavior) and are modeled. They
are not "control plane" in the sense above.

The endpoint model (`Endpoint`) is a data-plane endpoint (PSN, retransmit, MR,
SES, INC), not a host driver; queue semantics stay on the RTL/control side.

## 4. Attaching a DUT

```cpp
#include "uec_port_if.h"
using namespace uec_port;

class MyDutIngress : public PortSink {   // model egress -> DUT
 public:
  bool ready() const override;            // your FIFO has room
  void push(const PortBeat& b) override;  // one byte, sof/eof already set
};

class MyDutEgress : public PortSource {   // DUT -> model ingress
 public:
  bool pop(PortBeat& b) override;         // fill b and return true when available
};
```

The attach points are the per-port `rx`/`tx` of the switch model; port numbers
`0..N-1` are set by `UecSwitch(name, N)`. Backpressure is `ready()`;
`send_frame()` waits for a ready sink with a bounded spin and returns false on
timeout instead of dropping a beat.

## 5. Verified behavior

Real UET frames (`uec_uet::Packet::encode()` output) round-trip through the
DUT attach point byte-for-byte, with the CRC and payload unchanged. The
internal test suite covers this path; the public smoke set covers the port
adapter types and frame/beat conversion.
