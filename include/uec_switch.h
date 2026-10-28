
#pragma once
#include <systemc.h>
#include <vector>
#include "uec_cbfc_model.h"
#include <deque>
#include <map>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>

struct UecFrame {
  int      ingress = -1;
  uint8_t  dmac[6] = {0};
  uint8_t  smac[6] = {0};
  uint16_t ethertype = 0x0800;
  uint8_t  dscp = 0;
  int      tc = 0;
  bool     ecn = false;
  bool     trimmable = false;
  bool     trimmed = false;
  size_t   ip_offset = 0;     
  uint32_t fcs = 0;           
  bool     fcs_valid = false;
  std::vector<uint8_t> payload;

  
  bool     has_vlan = false;
  bool     has_qinq = false;       
  uint16_t vlan = 0;
  uint16_t vlan_inner = 0;
  uint16_t inner_ethertype = 0;
  bool     is_ipv4 = false, is_ipv6 = false, is_ufh = false;
  bool     is_multicast = false;
  uint8_t  hop_limit = 0;
  uint8_t  proto = 0;
  uint32_t src_ip = 0, dst_ip = 0;
  uint8_t  dst_last = 0;
  uint16_t src_port = 0, dst_port = 0;
  int      cells = 0;   
  
  
  int      cbfc_vc = 0;          
  bool     has_csig = false, csig_wide = false;
  uint8_t  csig_t = 0, csig_d = 0, csig_r = 0;
  uint32_t csig_s = 0, csig_lm = 0;
  uint8_t  csig_bytes = 0;    
  size_t   csig_off = 0;
  
  bool     is_ufh32 = false, is_ufh16 = false, ufh_bad_version = false;
  uint32_t ufh_dst = 0;
  uint16_t ufh_src = 0;
  uint8_t  ufh_flags = 0;
  size_t   ufh_off = 0;

  
  sc_time  t_enq = SC_ZERO_TIME;
  uint32_t wire_bytes = 0;    
};

struct UecPortStats {
  uint64_t rx_pkts = 0, rx_bytes = 0;
  uint64_t tx_pkts = 0, tx_bytes = 0;
  uint64_t rx_drop = 0, tx_drop = 0;
  uint64_t shaper_defer = 0;
  uint64_t lat_n = 0;
  double   lat_sum_ns = 0.0, lat_min_ns = 0.0, lat_max_ns = 0.0;
  sc_time  first_tx;
  sc_time  last_tx;
};

inline std::ostream& operator<<(std::ostream& os, const UecFrame& f) {
  os << "UecFrame{in=" << f.ingress << ",len=" << f.payload.size()
     << ",dscp=" << (unsigned)f.dscp << ",tc=" << f.tc << "}";
  return os;
}

SC_MODULE(UecSwitch) {
  SC_HAS_PROCESS(UecSwitch);
  UecSwitch(sc_module_name nm, int n_ports);

  std::vector<sc_fifo<UecFrame>*> rx;
  std::vector<sc_fifo<UecFrame>*> tx;
  int n_ports;

  std::vector<uint64_t> fwd_count;
  std::vector<uint64_t> flood_count;
  std::vector<uint64_t> drop_count;
  std::vector<uint64_t> ingress_drop;

  
  void add_l2(const uint8_t mac[6], int port);
  void add_l3_ipv4(uint8_t dst_last, int port);
  void add_l3_ipv6(uint8_t dst_last, int port);
  void add_vlan(uint16_t vid, const std::vector<int>& ports);
  void add_mcast(uint8_t group, const std::vector<int>& ports);
  void add_ecmp(uint8_t dst_last, const std::vector<int>& ports);
  void set_qos(int qlim, int ecn_min, int ecn_max, int trim_th, int drop_th, int min_trim);
  void set_features(bool ecn, bool trim);
  void set_features_ex(bool ecn, bool trim, bool csig, bool ufh, bool cbfc, bool pfc);
  void set_ids(uint16_t ufh_et, uint16_t csig_et);
  void set_pfc_xoff(int cells);
  void set_pfc_thresholds(int xoff, int xon, int quanta) {
    pfc_xoff = xoff; pfc_xon = xon; pfc_quanta = quanta;
  }
  void set_port_rate(int p, int gbps) { if (p >= 0 && p < n_ports) port_rate_tab[p] = gbps; }
  int  port_rate(int p) const { return (p >= 0 && p < n_ports) ? port_rate_tab[p] : 0; }
  int  q_cells_used(int p, int tc) const { return q_cells[p][tc]; }
  int  pool_cells_used() const { return pool_used; }
  
  void set_egress_shaper(int p, bool en, int burst_bytes = 16384);
  void set_egress_shaper_all(bool en, int burst_bytes = 16384);
  
  void set_inject(uint32_t dup_every, uint32_t drop_every) {
    inj_dup_every_ = dup_every; inj_drop_every_ = drop_every;
  }
  uint64_t injected_drop_count() const { return inj_drop_cnt_; }
  uint64_t injected_dup_count() const { return inj_dup_cnt_; }
  
  
  uint64_t cbfc_gate_drops() const { return cbfc_gate_drops_; }
  int      cbfc_credit(int vc) { return cbfc_.credit(vc); }
  void     set_cbfc_vc_mode(bool dscp_wide) { cbfc_vc_wide_ = dscp_wide; }
  int      cbfc_vc_of(const UecFrame& f) const {
#ifdef SW_CBFC_VC_RED
    (void)f;
    return 0;                                  
#else
    if (cbfc_vc_wide_) return (f.dscp >> 3) & 31;
    return (f.tc >= 0 && f.tc <= 2) ? f.tc : 0;
#endif
  }
  void     set_cbfc_credits(int vc, int n) { cbfc_.set_credit(vc, n); }
  
  
  void     set_cbfc_remote_cf(bool en, int peer_port = 0) {
    cbfc_remote_cf_ = en; cbfc_peer_port_ = peer_port;
  }
  uint64_t cf_tx_frames() const { return cf_tx_frames_; }
  uint64_t cf_rx_frames() const { return cf_rx_frames_; }
  uint64_t cc_tx_frames() const { return cc_tx_frames_; }
  uint64_t cc_rx_frames() const { return cc_rx_frames_; }

  
  
  void     set_pfc_deadlock_timeout(int ns) { pfc_deadlock_ns = ns; }
  uint64_t pfc_recovery_count() const { return pfc_recoveries_; }
  void set_ecmp_flowlet(bool en, int gap_ns = 100) {
    flowlet_en = en; flowlet_gap_ns = gap_ns;
  }
  const UecPortStats& port_stats(int p) const { return stats_[(p >= 0 && p < n_ports) ? p : 0]; }
  double tx_pps(int p) const;
  double tx_gbps(int p) const;
  uint64_t shaper_deferrals(int p) const {
    return (p >= 0 && p < n_ports) ? stats_[p].shaper_defer : 0;
  }
  
  void set_csig_wide(bool en) { csig_wide_en = en; }
  void set_csig_tpids(uint16_t compact, uint16_t wide) {
    csig_tpid = compact; csig_wide_tpid = wide;
  }
  void set_csig_locator(int p, uint32_t lm) {
    if (p >= 0 && p < n_ports) csig_locator_tab[p] = lm;
  }
  void set_csig_strip(int p, bool en) {
    if (p >= 0 && p < n_ports) csig_strip_tab[p] = en;
  }
  void set_csig_unsupported(bool strip) { csig_unsupported_strip = strip; }
  void set_csig_quant_compact(uint8_t t, int64_t min, int64_t max);
  void set_csig_quant_wide(uint8_t t, uint8_t e, uint32_t b);
  void set_csig_local(uint8_t t, bool valid, int64_t raw) {
    if (t < 16) { csig_local_valid_[t] = valid; csig_local_raw_[t] = raw; }
  }
  void set_csig_experimental(bool max_agg) { csig_exp_max = max_agg; }
  uint64_t csig_rx_count() const { return csig_rx_cnt_; }
  uint64_t csig_update_count() const { return csig_upd_cnt_; }
  uint64_t csig_dnm_count() const { return csig_dnm_cnt_; }
  uint64_t csig_strip_count() const { return csig_strip_cnt_; }
  uint64_t csig_trim_d_count() const { return csig_trimd_cnt_; }
  uint64_t csig_unsupported_count() const { return csig_unsup_cnt_; }
  void set_ufh_addr_bits(uint8_t bits) { ufh_addr_bits_ = (bits > 32) ? 32 : bits; }
  void add_ufh_route(uint32_t dst, uint8_t prefix, int port);
  void remove_ufh_route(uint32_t dst, uint8_t prefix, int port);
  size_t   ufh_route_count() const { return ufh_routes_.size(); }
  uint64_t ufh_bad_version_count() const { return ufh_bad_ver_cnt_; }
  uint64_t pfc_events() const { return pfc_xoff_events; }
  uint64_t pfc_rx_count() const { return pfc_rx_events; }
  uint64_t pfc_xon_count() const { return pfc_xon_events; }
  uint64_t pfc_tx_count() const { return pfc_tx_frames; }
  uint64_t cf_updates() const { return cbfc_cf_updates; }
  uint64_t cc_updates() const { return cbfc_cc_updates; }
  
  void set_mac_learning(bool en, int age_ticks = 1000) {
    mac_learn_en = en; mac_age_ticks = age_ticks;
  }
  void set_igmp_snoop(bool en) { igmp_snoop_en = en; }
  void set_pvid(int p, uint16_t vid, bool untag_egress = false) {
    if (p >= 0 && p < n_ports) {
      pvid_en_tab[p] = true; pvid_tab[p] = vid; untag_egress_tab[p] = untag_egress;
    }
  }
  void add_ecmp_member(uint8_t last, int port);
  void remove_ecmp_member(uint8_t last, int port);
  void add_mcast_member(uint8_t group, int port);
  void remove_mcast_member(uint8_t group, int port);
  uint64_t mac_learned() const { return mac_learned_cnt; }
  uint64_t mac_aged() const { return mac_aged_cnt; }
  size_t   mac_table_size() const { return mac_dyn.size(); }
  int      mac_lookup_port(const uint8_t mac[6]) const;
  std::vector<int> mcast_members(uint8_t group) const;
  std::vector<int> ecmp_members(uint8_t last) const;
  uint64_t trim_count(int p) const { return (p >= 0 && p < n_ports) ? trim_cnt[p] : 0; }
  uint64_t trim_drop_count(int p) const { return (p >= 0 && p < n_ports) ? trim_drop_cnt[p] : 0; }
  void set_trim_codepoints(uint8_t trimmable, uint8_t trimmed) {
    dscp_trimmable = trimmable; dscp_trimmed = trimmed;
  }
  void set_trim_last_hop(bool en, uint8_t dscp = 14) {
    trim_last_hop_en = en; dscp_trim_last_hop = dscp;
  }
  uint32_t frame_fcs(const UecFrame& f) const;

  int  classify_tc(uint8_t dscp) const;
  void parse(UecFrame& f) const;
  int  lookup(const uint8_t* dmac) const;

protected:
  std::vector<std::pair<std::array<uint8_t,6>,int>> l2_tab;
  std::map<uint8_t,int> l3_v4, l3_v6;
  std::map<uint8_t,std::vector<int>> mcast_tab;
  std::map<uint8_t,std::vector<int>> ecmp_tab;
  std::map<uint16_t,std::vector<int>> vlan_tab;

  std::vector<std::array<std::deque<UecFrame>,3>> queues;
  std::vector<std::array<int,3>> q_cells;
  std::vector<int> wrr_phase;
  std::vector<int> port_rate_tab;
  std::vector<uint64_t> trim_cnt, trim_drop_cnt;
  
  std::vector<UecPortStats> stats_;
  std::vector<bool> shaper_en_tab;
  std::vector<double> shaper_tokens;
  std::vector<int> shaper_burst;
  std::vector<sc_time> shaper_last;
  void shaper_refill(int p);
  int  wire_len(const UecFrame& f) const {
    return 14 + (int)f.payload.size() + 4;
  }
  bool flowlet_en = false;
  int  flowlet_gap_ns = 100;
  uint64_t flowlet_new_cnt = 0;
  struct FlowletEntry { int port = 0; sc_time last; };
  std::map<uint64_t, FlowletEntry> flowlet_tab;
  uint64_t flow_key(const UecFrame& f) const;
  int pool_used = 0;
  int cell_bytes = 256, pool_max = 32768;
  int q_limit = 64, ecn_min_th = 16, ecn_max_th = 32;
  int trim_th = 48, drop_th = 60, min_trim = 24;
  uint8_t dscp_trimmable = 10, dscp_trimmed = 12, dscp_trim_last_hop = 14;
  bool trim_last_hop_en = false;
  bool ecn_en = true, trim_en = true;
  bool csig_en = false, ufh_en = true, pfc_en = false, cbfc_en = false;
  uint16_t ufh_tpid = 0x88B5, csig_tpid = 0x88B6;
  
  bool csig_wide_en = true;
  uint16_t csig_wide_tpid = 0x88B7;
  std::vector<uint32_t> csig_locator_tab;
  std::vector<bool> csig_strip_tab;
  bool csig_unsupported_strip = false, csig_exp_max = true;
  std::array<std::array<int64_t, 33>, 8> csig_bounds_ = {};
  uint8_t  csig_wide_e_[16] = {};
  uint32_t csig_wide_b_[16] = {};
  bool     csig_local_valid_[16] = {};
  int64_t  csig_local_raw_[16] = {};
  sc_time  csig_rate_start_;
  uint64_t csig_rx_cnt_ = 0, csig_upd_cnt_ = 0, csig_dnm_cnt_ = 0;
  uint64_t csig_strip_cnt_ = 0, csig_trimd_cnt_ = 0, csig_unsup_cnt_ = 0;
  void csig_defaults();
  void csig_egress(UecFrame& f, int p, int tc, int depth_cells);
  int64_t csig_local_value(const UecFrame& f, int p, int tc, int depth_cells) const;
  uint32_t csig_quantize(uint8_t t, int64_t raw, bool wide) const;
  void csig_write_tag(UecFrame& f) const;
  void csig_mark_trimmed(UecFrame& f);
  void csig_strip(UecFrame& f);
  bool csig_supported(uint8_t t, bool wide) const;
  
  struct UfhRoute { uint32_t dst = 0; uint8_t prefix = 0; int port = -1; };
  std::vector<UfhRoute> ufh_routes_;
  uint8_t ufh_addr_bits_ = 32;
  uint64_t ufh_bad_ver_cnt_ = 0;
  int ufh_route_lookup(uint32_t dst) const;
  int pfc_xoff = 16, pfc_xon = 8, pfc_quanta = 1000;
  uint64_t pfc_xoff_events = 0, pfc_xon_events = 0, pfc_rx_events = 0;
  uint64_t pfc_tx_frames = 0, cbfc_cf_updates = 0, cbfc_cc_updates = 0;
  std::vector<std::array<sc_time, 3>> pause_until;
  std::vector<std::array<sc_time, 3>> pause_start;
  int      pfc_deadlock_ns = 1000000;   
  uint64_t pfc_recoveries_ = 0;
  std::vector<std::array<bool, 3>> pfc_paused;
  void emit_pfc(int port, int tc, uint16_t quanta);
  int cf_ctr = 0, cc_ctr = 0;
  uint32_t inj_dup_every_ = 0, inj_drop_every_ = 0;
  uint64_t inj_pkt_cnt_ = 0, inj_drop_cnt_ = 0, inj_dup_cnt_ = 0;
  CbfcEngine cbfc_{32, 32, 8, 16};
  uint64_t cbfc_gate_drops_ = 0;
  bool     cbfc_vc_wide_ = false;
  bool     cbfc_remote_cf_ = false;
  int      cbfc_peer_port_ = 0;
  uint64_t cf_tx_frames_ = 0, cf_rx_frames_ = 0;
  uint64_t cc_tx_frames_ = 0, cc_rx_frames_ = 0;
  UecFrame make_cbfc_frame(uint64_t msg) const;
  UecFrame make_cbfc_cc_frame(uint8_t group,
                              const std::array<uint32_t, 16>& vals) const;

  bool vlan_ok(uint16_t vid, int port) const;
  bool trim_ip_packet(UecFrame& f);
  
  
  bool trim_uet_packet(UecFrame& f, size_t o, size_t hdr_len, size_t orig_plen);
  void mark_ce(UecFrame& f);
  static uint16_t ipv4_checksum(const uint8_t* p, size_t hdr_len);
  
  struct MacDyn {
    std::array<uint8_t, 6> mac;
    int port = 0;
    uint64_t last = 0;
  };
  std::vector<MacDyn> mac_dyn;
  std::vector<uint16_t> pvid_tab;
  std::vector<bool> pvid_en_tab, untag_egress_tab;
  bool mac_learn_en = false, igmp_snoop_en = false;
  int mac_age_ticks = 1000;
  uint64_t tick_ = 0, mac_learned_cnt = 0, mac_aged_cnt = 0;
  void mac_learn(const UecFrame& f, int p);
  void mac_age();
  void maybe_tag_pvid(UecFrame& f, int p);
  void maybe_untag(UecFrame& f, int e);
  void snoop_multicast(const UecFrame& f, int p);
  void enqueue(UecFrame f, int e);
  bool schedule_port(int p);
  int  l3_lookup(const UecFrame& f) const;
  std::vector<int> others(int p) const;
  std::vector<int> forward(UecFrame& f, bool& drop);
  void main_thread();

private:
  static constexpr int FIFO_DEPTH = 1024;
};
