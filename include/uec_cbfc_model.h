

#pragma once
#include <cstdint>
#include <vector>
#include <array>
#include <algorithm>

class CbfcEngine {
 public:
  CbfcEngine(int vc_n = 32, int window = 32, int cf_period = 8, int cc_period = 16)
      : vc_n_(vc_n), window_(window), cf_period_(cf_period),
        cc_period_(cc_period),
        credits_(vc_n, window), consumed_(vc_n, 0), freed_(vc_n, 0),
        pending_cf_(vc_n, 0) {}

  int vc_count() const { return vc_n_; }
  int credit(int vc) const { return in_range(vc) ? credits_[vc] : -1; }
  int consumed(int vc) const { return in_range(vc) ? consumed_[vc] : -1; }
  int freed(int vc) const { return in_range(vc) ? freed_[vc] : -1; }
  int total_credits() const {
    int s = 0; for (int c : credits_) s += c; return s;
  }

  
  void set_credit(int vc, int c) {
    if (in_range(vc)) credits_[vc] = c;
  }

  bool can_send(int vc) const {
    return in_range(vc) && credits_[vc] > 0 && !cc_snap_pending_;
  }
  bool send(int vc) {
    if (!can_send(vc)) return false;
    credits_[vc]--;
    consumed_[vc]++;
    if (++cc_phase_ >= cc_period_) { cc_phase_ = 0; cc_snap_pending_ = true; }
    return true;
  }
  void rx(int vc) {                    
    if (!in_range(vc)) return;
    freed_[vc]++;
    if (pending_cf_[vc] < 0x7FFF) pending_cf_[vc]++;
    freed_events_++;
  }

  bool cf_due() const { return freed_events_ >= cf_period_; }
  uint64_t make_cf() {
    if (vc_n_ < 2) return 0;
    int pairs = vc_n_ / 2;
    for (int t = 0; t < pairs; t++) {
      int idx = (cf_pair_idx_ + t) % pairs;
      int a = 2 * idx, b = a + 1;
      if (pending_cf_[a] || pending_cf_[b]) {
        uint64_t m = cf_msg(a, pending_cf_[a], b, pending_cf_[b]);
        pending_cf_[a] = pending_cf_[b] = 0;
        freed_events_ = 0;
        cf_pair_idx_ = (idx + 1) % pairs;
        return m;
      }
    }
    return 0;
  }
  void on_cf(uint64_t msg) {
    int v1, c1, v2, c2;
    if (!parse_cf(msg, v1, c1, v2, c2)) return;
#ifndef SW_CBFC_RED
    if (in_range(v1)) credits_[v1] = std::min(window_, credits_[v1] + c1);
    if (in_range(v2)) credits_[v2] = std::min(window_, credits_[v2] + c2);
#endif
  }

  bool cc_due() const { return cc_snap_pending_; }
  void make_cc(uint8_t& group, std::array<uint32_t, 16>& vals) {
    group = (uint8_t)cc_group_;
    for (int i = 0; i < 16; i++) {
      int v = cc_group_ * 16 + i;
      vals[i] = (v < vc_n_) ? (uint32_t)consumed_[v] : 0;
      if (v < vc_n_) consumed_[v] = 0;
    }
    cc_group_ ^= 1;
    cc_snap_pending_ = false;
  }
  
  void on_cc(uint8_t group, const std::array<uint32_t, 16>& vals) {
    (void)group; (void)vals;
  }
  uint64_t cc_total(const std::array<uint32_t, 16>& vals) const {
    uint64_t s = 0; for (uint32_t v : vals) s += v; return s;
  }

  
  static uint64_t cf_msg(int vc1, int cnt1, int vc2, int cnt2) {
    uint64_t m = 0;
    auto put = [&m](int sh, uint8_t b) { m |= (uint64_t)b << sh; };
    put(0, 0x5C);                                  
    put(8, 0x10);                                  
    put(16, (uint8_t)(((vc1 & 0x1F) << 3) | ((cnt1 >> 12) & 0x7)));
    put(24, (uint8_t)((cnt1 >> 4) & 0xFF));
    put(32, (uint8_t)(((cnt1 & 0xF) << 4) | 0x6));
    put(40, (uint8_t)(((vc2 & 0x1F) << 3) | ((cnt2 >> 12) & 0x7)));
    put(48, (uint8_t)((cnt2 >> 4) & 0xFF));
    put(56, (uint8_t)(((cnt2 & 0xF) << 4) | 0x0));
    return m;
  }
  static bool parse_cf(uint64_t m, int& vc1, int& cnt1, int& vc2, int& cnt2) {
    if ((uint8_t)(m & 0xFF) != 0x5C || (uint8_t)((m >> 8) & 0xFF) != 0x10)
      return false;
    vc1 = (int)((m >> 19) & 0x1F);
    cnt1 = (int)((((m >> 16) & 0x7) << 12) | (((m >> 24) & 0xFF) << 4) |
                 ((m >> 36) & 0xF));
    vc2 = (int)((m >> 43) & 0x1F);
    cnt2 = (int)((((m >> 40) & 0x7) << 12) | (((m >> 48) & 0xFF) << 4) |
                 ((m >> 60) & 0xF));
    return vc1 >= 0 && vc1 < 32 && vc2 >= 0 && vc2 < 32;
  }

 private:
  bool in_range(int vc) const { return vc >= 0 && vc < vc_n_; }
  int vc_n_, window_, cf_period_, cc_period_;
  std::vector<int> credits_, consumed_, freed_, pending_cf_;
  int freed_events_ = 0;
  int cc_phase_ = 0;
  int cc_group_ = 0;
  int cf_pair_idx_ = 0;
  bool cc_snap_pending_ = false;
};
