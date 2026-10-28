
#include "uec_switch.h"
#include <cstdio>
#include <cstdlib>
#include <vector>

static UecFrame make_frame(int src, int dst, int seed, uint8_t dscp) {
  UecFrame f;
  f.dmac[0] = 0x02; f.dmac[5] = (uint8_t)dst;
  f.smac[5] = (uint8_t)src;
  f.dscp = dscp;
  f.payload.resize(64 + src);
  for (size_t i = 0; i < f.payload.size(); i++)
    f.payload[i] = (uint8_t)((seed * 37 + i * 13 + 5) & 0xFF);
  return f;
}

int sc_main(int argc, char** argv) {
  int N = (argc > 1) ? std::atoi(argv[1]) : 4;
  if (N < 2 || N > 16) { std::fprintf(stderr, "N out of range\n"); return 2; }

  UecSwitch sw("sw", N);
  std::vector<UecFrame> sent(N);
  for (int p = 0; p < N; p++) {
    uint8_t dscp = (p % 3 == 0) ? 46 : ((p % 3 == 1) ? 12 : 0);
    sent[p] = make_frame(p, (p + 1) % N, p + 1, dscp);
    sw.rx[p]->write(sent[p]);
  }
  UecFrame unk = make_frame(0, 0, 99, 0);
  unk.dmac[0] = 0x03;
  unk.dmac[5] = 0x0F;
  sw.rx[0]->write(unk);

  int got = 0, errors = 0, flooded = 0;
  for (int t = 0; t < 2000 && (got < N || flooded < N - 1); t++) {
    sc_start(10, SC_NS);
    for (int p = 0; p < N; p++) {
      UecFrame f;
      while (sw.tx[p]->nb_read(f)) {
        if (f.dmac[0] == 0x03) {
          if (p == 0) errors++;
          else flooded++;
          continue;
        }
        int src = f.smac[5];
        if (src < 0 || src >= N || f.payload != sent[src].payload) errors++;
        if (f.tc != sw.classify_tc(f.dscp)) errors++;
        got++;
      }
    }
  }

  std::printf("UEC_SWITCH_SMOKE: N=%d frames=%d/%d flood=%d/%d errors=%d\n",
              N, got, N, flooded, N - 1, errors);
  if (got == N && flooded == N - 1 && errors == 0) {
    std::printf("UEC_SWITCH_SMOKE PASS\n");
    sc_stop();
    return 0;
  }
  std::printf("UEC_SWITCH_SMOKE FAIL\n");
  sc_stop();
  return 1;
}
