

#pragma once

#include "uec_pcm_algo.h"

#include <algorithm>
#include <cstdint>

namespace uec_uet {

struct CcConfig {
  bool     enable = false;
  uint32_t init_cwnd = 8192;        
  uint32_t min_cwnd = 4096;
  uint32_t max_cwnd = 1u << 20;
  uint32_t mss = 4096;              
};

class CcRuntime {
 public:
  explicit CcRuntime(const CcConfig& c)
      : cfg_(c), win_(engine_, 0, c.mss, c.min_cwnd, c.max_cwnd) {
    win_.init(c.init_cwnd, 0);
  }

  bool enabled() const { return cfg_.enable; }
  uint32_t cwnd() const { return win_.cwnd(); }
  uint64_t inflight() const { return inflight_; }

  
  bool can_send(uint64_t bytes) const {
#ifdef UET_CC_RED_NOWIN
    (void)bytes;
    return true;   
#else
    if (!cfg_.enable) return true;
    return inflight_ + bytes <= (uint64_t)win_.cwnd();
#endif
  }

  void on_send(uint64_t bytes) { inflight_ += bytes; }
  void on_complete(uint64_t bytes) {
    inflight_ = (inflight_ > bytes) ? inflight_ - bytes : 0;
  }

  void on_ack(bool ce, int64_t rtt_ns = 0) {
    if (!cfg_.enable) return;
    acks_++;
#ifdef UET_CC_RED_NOECN
    ce = false;   
#endif
    if (ce) ces_++;
    win_.on_ack(0, ce, rtt_ns);
  }

  void on_rto() {
    if (!cfg_.enable) return;
    rtos_++;
    win_.on_rto();
  }

  uec_pcm::Engine& pcm() { return engine_; }
  const uec_pcm::Engine& pcm() const { return engine_; }
  uint64_t acks() const { return acks_; }
  uint64_t ces() const { return ces_; }
  uint64_t rtos() const { return rtos_; }

 private:
  CcConfig cfg_;
  uec_pcm::Engine engine_;
  uec_pcm::WindowCc win_;
  uint64_t inflight_ = 0;
  uint64_t acks_ = 0;
  uint64_t ces_ = 0;
  uint64_t rtos_ = 0;
};

}  
