
#include "uec_uet_endpoint.h"

#include <cstdio>
#include <vector>

using namespace uec_uet;

static EndpointConfig make_cfg(bool host) {
  EndpointConfig c;
  if (host) {
    c.mac = {{0x02, 0, 0, 0, 0, 0x0a}};
    c.ip = 0x0a000001;
    c.peer_mac = {{0x02, 0, 0, 0, 0, 0x0b}};
    c.peer_ip = 0x0a000002;
    c.local_pdc = 0x10;
    c.remote_pdc = 0x20;
  } else {
    c.mac = {{0x02, 0, 0, 0, 0, 0x0b}};
    c.ip = 0x0a000002;
    c.peer_mac = {{0x02, 0, 0, 0, 0, 0x0a}};
    c.peer_ip = 0x0a000001;
    c.local_pdc = 0x20;
    c.remote_pdc = 0x10;
  }
  c.job_id = host ? 0x111111 : 0x222222;
  c.rto_ns = 200000;
  return c;
}

int main() {
  Endpoint host(make_cfg(true)), target(make_cfg(false));
  host.set_tx([&target](const std::vector<uint8_t>& f) { target.on_frame(f); });
  target.set_tx([&host](const std::vector<uint8_t>& f) { host.on_frame(f); });

  std::vector<uint8_t> data(64);
  for (size_t i = 0; i < data.size(); i++) data[i] = (uint8_t)(i * 7 + 1);

  if (!host.send_write(0x1000, data)) return 1;
  Completion c;
  if (!host.poll(c) || c.rc != RC_OK) return 1;
  std::vector<uint8_t> got;
  if (!target.get_mem(0x1000, data.size(), got) || got != data) return 1;

  if (!host.send_read(0x1000, 64)) return 1;
  if (!host.poll(c) || c.rc != RC_OK || c.data != data) return 1;

  std::printf("UEC_EXAMPLE PASS bytes=%zu\n", data.size());
  return 0;
}
