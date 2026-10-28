

#pragma once
#include <cstdint>
#include <cstring>
#include "uec_switch.h"

namespace uec_pfc {

static constexpr uint16_t ETH_P_PAUSE = 0x8808;
static constexpr uint16_t OPCODE       = 0x0101;

inline UecFrame make(uint16_t class_enable, const uint16_t quanta[8],
                     uint8_t sa_last = 0xEE) {
  UecFrame f;
  const uint8_t da[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x01};
  const uint8_t sa[6] = {0x02, 0x00, 0x00, 0x00, 0x00, sa_last};
  std::memcpy(f.dmac, da, 6);
  std::memcpy(f.smac, sa, 6);
  f.ethertype = ETH_P_PAUSE;
  f.payload.assign(46, 0);                 
  f.payload[0] = (uint8_t)(OPCODE >> 8);
  f.payload[1] = (uint8_t)(OPCODE & 0xFF);
  f.payload[2] = (uint8_t)(class_enable >> 8);
  f.payload[3] = (uint8_t)(class_enable & 0xFF);
  for (int i = 0; i < 8; i++) {
    f.payload[4 + 2 * i] = (uint8_t)(quanta[i] >> 8);
    f.payload[5 + 2 * i] = (uint8_t)(quanta[i] & 0xFF);
  }
  return f;
}

inline bool parse(const UecFrame& f, uint16_t& class_enable, uint16_t quanta[8]) {
  if (f.ethertype != ETH_P_PAUSE || f.payload.size() < 20) return false;
  uint16_t op = (uint16_t)((f.payload[0] << 8) | f.payload[1]);
  if (op != OPCODE) return false;
  class_enable = (uint16_t)((f.payload[2] << 8) | f.payload[3]);
  for (int i = 0; i < 8; i++)
    quanta[i] = (uint16_t)((f.payload[4 + 2 * i] << 8) | f.payload[5 + 2 * i]);
  return true;
}

inline bool is(const UecFrame& f) {
  uint16_t e, q[8];
  return parse(f, e, q);
}

}  
