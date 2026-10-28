

#pragma once
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <map>
#include <vector>

namespace uec_pcm {

enum AccOp : uint8_t { ACC_SUM = 0, ACC_MAX, ACC_MIN, ACC_LAST, ACC_EWMA };

struct Signal {
  AccOp op = ACC_SUM;
  double alpha = 0.25;      
  int64_t value = 0;
  bool valid = false;
};

struct EvEntry {
  uint32_t entropy = 0;
  uint32_t penalty = 0;
};

struct Control {
  uint32_t cwnd_bytes = 0;
  uint64_t rate_bps = 0;      
};

class Engine {
 public:
  static constexpr int NSIG = 32;

  void configure_signal(int idx, AccOp op, double alpha = 0.25) {
    if (idx < 0 || idx >= NSIG) return;
    sig_[idx].op = op;
    sig_[idx].alpha = std::min(1.0, std::max(0.0, alpha));
    sig_[idx].valid = false;
    sig_[idx].value = 0;
  }
  void reset_signal(int idx) {
    if (idx >= 0 && idx < NSIG) { sig_[idx].valid = false; sig_[idx].value = 0; }
  }
  void update_signal(int idx, int64_t x) {
    if (idx < 0 || idx >= NSIG) return;
    Signal& s = sig_[idx];
    switch (s.op) {
      case ACC_SUM: s.value += x; break;
      case ACC_MAX: if (!s.valid || x > s.value) s.value = x; break;
      case ACC_MIN: if (!s.valid || x < s.value) s.value = x; break;
      case ACC_LAST: s.value = x; break;
      case ACC_EWMA:
        if (!s.valid) s.value = x;
        else s.value = (int64_t)std::llround(x * s.alpha + s.value * (1.0 - s.alpha));
        break;
    }
    s.valid = true;
    updates_++;
  }
  
  
  void update_batch(const std::vector<std::pair<int, int64_t>>& ups) {
    for (const auto& u : ups) update_signal(u.first, u.second);
    batches_++;
  }
  int64_t signal(int idx) const {
    return (idx >= 0 && idx < NSIG) ? sig_[idx].value : 0;
  }
  bool signal_valid(int idx) const {
    return idx >= 0 && idx < NSIG && sig_[idx].valid;
  }

  
  void configure_ev(int ccc, int depth) {
    EvTable& t = ev_[ccc];
    t.entries.assign(depth > 0 ? depth : 1, EvEntry());
    t.skip_count = 0;
  }
  void set_ev(int ccc, int idx, uint32_t entropy, uint32_t penalty = 0) {
    EvTable& t = ev_[ccc];
    if (idx >= 0 && idx < (int)t.entries.size()) {
      t.entries[idx].entropy = entropy;
      t.entries[idx].penalty = penalty;
    }
  }
  int depth(int ccc) const {
    auto it = ev_.find(ccc);
    return it == ev_.end() ? 0 : (int)it->second.entries.size();
  }
  const EvEntry& ev(int ccc, int idx) const {
    static const EvEntry empty;
    auto it = ev_.find(ccc);
    if (it == ev_.end() || idx < 0 || idx >= (int)it->second.entries.size())
      return empty;
    return it->second.entries[idx];
  }
  
  
  int select_ev(int ccc, uint64_t flow_hash) {
    auto it = ev_.find(ccc);
    if (it == ev_.end() || it->second.entries.empty()) return -1;
    EvTable& t = it->second;
    uint32_t minp = UINT32_MAX;
    for (const auto& e : t.entries) minp = std::min(minp, e.penalty);
    std::vector<int> best;
    for (int i = 0; i < (int)t.entries.size(); i++)
      if (t.entries[i].penalty == minp) best.push_back(i);
    t.skip_count += (uint64_t)t.entries.size() - best.size();
    int pick = best[(size_t)(flow_hash % best.size())];
    t.last_selected = pick;
    selections_++;
    return pick;
  }
  uint64_t ev_skip_count(int ccc) const {
    auto it = ev_.find(ccc);
    return it == ev_.end() ? 0 : it->second.skip_count;
  }
  int ev_last_selected(int ccc) const {
    auto it = ev_.find(ccc);
    return it == ev_.end() ? -1 : it->second.last_selected;
  }
  void update_ev(int ccc, int idx, uint32_t penalty) {
    EvTable& t = ev_[ccc];
    if (idx >= 0 && idx < (int)t.entries.size())
      t.entries[idx].penalty = penalty;
  }

  
  void set_ack_signal(int idx) { ack_signal_ = idx; }
  void on_ack(int ccc, int ev_idx, bool ecn, int64_t rtt_ns) {
    EvTable& t = ev_[ccc];
    if (ev_idx >= 0 && ev_idx < (int)t.entries.size()) {
      uint32_t p = t.entries[ev_idx].penalty;
      if (ecn) p = std::min(0xFFFFu, p + 2);
      else if (p > 0) p--;
      t.entries[ev_idx].penalty = p;
    }
    if (ack_signal_ >= 0 && ack_signal_ < NSIG) update_signal(ack_signal_, rtt_ns);
    acks_++;
  }
  void set_control(int ccc, uint32_t cwnd_bytes, uint64_t rate_bps) {
    ctl_[ccc] = {cwnd_bytes, rate_bps};
  }
  Control control(int ccc) const {
    auto it = ctl_.find(ccc);
    return it == ctl_.end() ? Control() : it->second;
  }
  uint64_t updates() const { return updates_; }
  uint64_t batches() const { return batches_; }
  uint64_t selections() const { return selections_; }
  uint64_t acks() const { return acks_; }

 private:
  struct EvTable {
    std::vector<EvEntry> entries;
    uint64_t skip_count = 0;
    int last_selected = -1;
  };
  Signal sig_[NSIG];
  std::map<int, EvTable> ev_;
  std::map<int, Control> ctl_;
  int ack_signal_ = -1;
  uint64_t updates_ = 0, batches_ = 0, selections_ = 0, acks_ = 0;
};

}  
