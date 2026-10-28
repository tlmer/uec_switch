

#include "uec_uet_tss.h"

#include <cstdio>
#include <vector>

using namespace uec_uet;

int main() {
  uint8_t key[32];
  for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x31 + i * 5);
  const uint8_t aad[TssEngine::kAadLen] = {10, 0, 0, 1, 10, 0, 0, 2, 0x42, 0x42, 0, 0};
  std::vector<uint8_t> clear(96);
  for (size_t i = 0; i < clear.size(); i++) clear[i] = (uint8_t)(i * 17 + 3);

  TssEngine t;
  if (!t.add_sd(1, 0x1234, true, key)) {
    std::printf("UEC_TSS_RED FAIL setup\n");
    return 1;
  }
  std::vector<uint8_t> blob, out;
  if (!t.seal(1, 100, aad, clear, blob)) {
    std::printf("UEC_TSS_RED FAIL seal\n");
    return 1;
  }
  std::vector<uint8_t> bad = blob;
  bad[20] ^= 0x80;
  const bool rejected = !t.open(bad, aad, out);
  if (rejected) {
    std::printf("UEC_TSS_RED PASS tampered envelope rejected\n");
    return 0;
  }
  std::printf("UEC_TSS_RED FAIL tampered envelope accepted\n");
  return 1;
}
