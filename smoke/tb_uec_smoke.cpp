
#include "uec_uet_endpoint.h"

#include <cstdio>
#include <vector>

using namespace uec_uet;

static int errors;
static void check(bool ok, const char* what) {
  if (!ok) {
    errors++;
    std::printf("UEC_SMOKE_FAIL %s\n", what);
  }
}

static std::vector<uint8_t> pattern(size_t n, uint8_t seed) {
  std::vector<uint8_t> v(n);
  for (size_t i = 0; i < n; i++)
    v[i] = (uint8_t)(seed ^ (uint8_t)((i * 13u) & 0xffu));
  return v;
}

static EndpointConfig cfg_a() {
  EndpointConfig c;
  c.mac = {{0x02, 0, 0, 0, 0, 0x0a}};
  c.ip = 0x0a000001;
  c.peer_mac = {{0x02, 0, 0, 0, 0, 0x0b}};
  c.peer_ip = 0x0a000002;
  c.local_pdc = 0x10;
  c.remote_pdc = 0x20;
  c.job_id = 0x111111;
  c.rto_ns = 200000;
  return c;
}

static EndpointConfig cfg_b() {
  EndpointConfig c;
  c.mac = {{0x02, 0, 0, 0, 0, 0x0b}};
  c.ip = 0x0a000002;
  c.peer_mac = {{0x02, 0, 0, 0, 0, 0x0a}};
  c.peer_ip = 0x0a000001;
  c.local_pdc = 0x20;
  c.remote_pdc = 0x10;
  c.job_id = 0x222222;
  c.rto_ns = 200000;
  return c;
}

static void wire_pair(Endpoint& a, Endpoint& b) {
  a.set_tx([&b](const std::vector<uint8_t>& f) { b.on_frame(f); });
  b.set_tx([&a](const std::vector<uint8_t>& f) { a.on_frame(f); });
}

int main() {
  errors = 0;
  {
    Endpoint a(cfg_a()), b(cfg_b());
    wire_pair(a, b);
    const std::vector<uint8_t> data = pattern(256, 0xa5);
    check(a.send_write(0x1000, data), "write accepted");
    Completion c;
    check(a.poll(c) && c.rc == RC_OK && !c.read, "write completion");
    std::vector<uint8_t> got;
    check(b.get_mem(0x1000, data.size(), got) && got == data,
          "write data landed");

    const std::vector<uint8_t> mem = pattern(300, 0x77);
    b.set_mem(0x2000, mem);
    check(a.send_read(0x2000, (uint32_t)mem.size()), "read accepted");
    check(a.poll(c) && c.rc == RC_OK && c.read && c.data == mem,
          "read completion data");
  }
  {
    Endpoint a(cfg_a()), b(cfg_b());
    wire_pair(a, b);
    const std::vector<uint8_t> msg = pattern(64, 0x3c);
    check(a.send_send(msg), "send accepted");
    Completion c;
    check(a.poll(c) && c.rc == RC_OK, "send completion");
    std::vector<uint8_t> mailbox;
    check(b.get_message(1, mailbox) && mailbox == msg, "send delivered");
  }
  {
    Endpoint a(cfg_a()), b(cfg_b());
    wire_pair(a, b);
    a.drop_next_tx();
    const std::vector<uint8_t> data = pattern(128, 0x5a);
    check(a.send_write(0x3000, data), "retx write accepted");
    Completion none;
    check(!a.poll(none), "no completion before RTO");
    a.tick(200001);
    Completion c;
    check(a.poll(c) && c.rc == RC_OK, "completion after RTO");
    std::vector<uint8_t> got;
    check(b.get_mem(0x3000, data.size(), got) && got == data,
          "retx data landed");
  }

  if (errors == 0) {
    std::printf("UEC_SMOKE PASS cases=4\n");
    return 0;
  }
  std::printf("UEC_SMOKE FAIL errors=%d\n", errors);
  return 1;
}
