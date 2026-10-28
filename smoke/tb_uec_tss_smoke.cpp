

#include "uec_uet_endpoint.h"
#include "uec_uet_tss_path.h"

#include <cstdio>
#include <vector>

using namespace uec_uet;

static int errors;
static void check(bool ok, const char* what) {
  if (!ok) {
    errors++;
    std::printf("UEC_TSS_SMOKE_FAIL %s\n", what);
  }
}

static std::vector<uint8_t> pattern(size_t n, uint8_t seed) {
  std::vector<uint8_t> v(n);
  for (size_t i = 0; i < n; i++)
    v[i] = (uint8_t)(seed ^ (uint8_t)((i * 29u) & 0xffu));
  return v;
}

static EndpointConfig cfg(bool host) {
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
  c.tss_enable = true;
  c.tss_sdi = 1;
  c.tss_ssi = 0x1234;
  c.tss_use_ssi = true;
  for (int i = 0; i < 32; i++) c.tss_key[i] = (uint8_t)(0x31 + i * 7);
  return c;
}

int main() {
  errors = 0;
  uet_tss_path_register();

  {
    Endpoint a(cfg(true)), b(cfg(false));
    a.set_tx([&b](const std::vector<uint8_t>& f) { b.on_frame(f); });
    b.set_tx([&a](const std::vector<uint8_t>& f) { a.on_frame(f); });
    check(a.tss_active() && b.tss_active(), "tss path active");

    const std::vector<uint8_t> data = pattern(256, 0xa5);
    check(a.send_write(0x1000, data), "sealed write accepted");
    Completion c;
    check(a.poll(c) && c.rc == RC_OK, "sealed write completion");
    std::vector<uint8_t> got;
    check(b.get_mem(0x1000, data.size(), got) && got == data,
          "sealed write landed");
    check(a.stats().tss_sealed == 1 && b.stats().tss_opened == 1,
          "tss counters");

    const std::vector<uint8_t> mem = pattern(300, 0x77);
    b.set_mem(0x2000, mem);
    check(a.send_read(0x2000, (uint32_t)mem.size()), "sealed read accepted");
    check(a.poll(c) && c.rc == RC_OK && c.data == mem, "sealed read data");
    check(a.stats().tss_opened == 1 && b.stats().tss_sealed == 1,
          "response sealed/opened");
  }

  {
    Endpoint a(cfg(true)), b(cfg(false));
    std::vector<std::vector<uint8_t>> frames;
    a.set_tx([&frames](const std::vector<uint8_t>& f) { frames.push_back(f); });
    b.set_tx([](const std::vector<uint8_t>&) {});
    check(a.send_write(0x3000, pattern(96, 0x5a)), "tamper write accepted");
    check(frames.size() == 1 && frames[0].size() > 42 + 21,
          "one sealed frame captured");
    if (!frames.empty() && frames[0].size() > 42 + 21) {
      std::vector<uint8_t> bad = frames[0];
      bad[42 + 20] ^= 0x80;
      b.on_frame(bad);
    }
#ifndef UET_TSS_RED_NOTAG
    check(b.stats().tss_auth_fail == 1, "tamper rejected");
    check(b.stats().write_rx == 0, "tamper not delivered");
#else
    check(b.stats().tss_auth_fail == 0, "red: tag not verified");
    check(b.stats().tss_opened >= 1, "red: tampered frame opened");
#endif
  }

  {
    Endpoint a(cfg(true)), b(cfg(false));
    std::vector<std::vector<uint8_t>> frames;
    a.set_tx([&frames](const std::vector<uint8_t>& f) { frames.push_back(f); });
    b.set_tx([](const std::vector<uint8_t>&) {});
    check(a.send_write(0x3100, pattern(64, 0x11)), "replay write accepted");
    check(frames.size() == 1, "replay frame captured");
    if (!frames.empty()) {
      b.on_frame(frames[0]);
      b.on_frame(frames[0]);
    }
    check(b.stats().write_rx == 1, "only first frame delivered");
    check(b.stats().tss_replay == 1, "replay rejected");
  }

  {
    Endpoint a(cfg(true)), b(cfg(false));
    int b_tx = 0;
    a.set_tx([&b](const std::vector<uint8_t>& f) { b.on_frame(f); });
    b.set_tx([&a, &b_tx](const std::vector<uint8_t>& f) {
      if (b_tx++ == 0) return;
      a.on_frame(f);
    });
    check(a.send_write(0x4000, pattern(128, 0xc3)), "retx write accepted");
    Completion none;
    check(!a.poll(none), "no completion while the ACK is lost");
    a.tick(200001);
    Completion c;
    check(a.poll(c) && c.rc == RC_OK, "completion after RTO");
    check(a.stats().tss_sealed == 2 && b.stats().tss_opened == 2,
          "retry uses a fresh TSC");
  }

#ifdef UET_TSS_RED_NOTAG
  std::printf("UEC_TSS_SMOKE RED_PASS errors=%d\n", errors);
  return 0;
#else
  if (errors == 0) {
    std::printf("UEC_TSS_SMOKE PASS cases=4\n");
    return 0;
  }
  std::printf("UEC_TSS_SMOKE FAIL errors=%d\n", errors);
  return 1;
#endif
}
