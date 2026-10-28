

#pragma once
#include "uec_pcm.h"
#include <algorithm>
#include <cstdint>

namespace uec_pcm {

class WindowCc {
 public:
  WindowCc(Engine& e, int ccc, uint32_t mss = 4096,
           uint32_t min_cwnd = 8192, uint32_t max_cwnd = 1u << 24)
      : e_(e), ccc_(ccc), mss_(mss), min_(min_cwnd), max_(max_cwnd) {}

  void init(uint32_t cwnd_bytes, uint64_t rate_bps) {
    cwnd_ = std::min(max_, std::max(min_, cwnd_bytes));
    rate_ = rate_bps;
    apply();
  }
  void on_ack(int ev_idx, bool ecn, int64_t rtt_ns) {
    e_.on_ack(ccc_, ev_idx, ecn, rtt_ns);
    if (ecn) cwnd_ = std::max(min_, (uint32_t)((uint64_t)cwnd_ * 7 / 8));
    else cwnd_ = std::min(max_, cwnd_ + mss_);
    apply();
  }
  void on_rto() {
    cwnd_ = std::max(min_, cwnd_ / 2);
    apply();
  }
  int select_path(uint64_t flow_hash) { return e_.select_ev(ccc_, flow_hash); }
  uint32_t cwnd() const { return cwnd_; }
  uint64_t rate() const { return rate_; }

 private:
  void apply() { e_.set_control(ccc_, cwnd_, rate_); }
  Engine& e_;
  int ccc_;
  uint32_t mss_, min_, max_;
  uint32_t cwnd_ = 0;
  uint64_t rate_ = 0;
};

}  
