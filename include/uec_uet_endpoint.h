

#pragma once
#include "uec_uet_pkt.h"
#include "uec_uet_mr.h"
#include "uec_uet_cc.h"
#include "uec_inc_sep.h"
#include "uec_uet_tss_path.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <vector>
#include <deque>

namespace uec_uet {

struct EndpointConfig {
  std::array<uint8_t, 6> mac{{0x02, 0, 0, 0, 0, 0x0a}};
  uint32_t ip = 0x0a000001;
  std::array<uint8_t, 6> peer_mac{{0x02, 0, 0, 0, 0, 0x0b}};
  uint32_t peer_ip = 0x0a000002;
  uint16_t local_pdc = 0x10;
  uint16_t remote_pdc = 0x20;
  
  
  std::vector<uint16_t> local_pdcs;
  uint32_t job_id = 0x123456;
  uint64_t rto_ns = 200000;     
  int max_retx = 5;
  int window = 64;              
  uint8_t tos = 0;              
  bool ordered = false;         
  bool sack = false;            

  
  
  
  bool enforce_mr = false;
  uint64_t recv_base = 0;       
  
  
  int recv_pool = -1;

  
  uint64_t write_mkey = 0xDEADBEEFCAFEBABEULL;
  uint64_t read_mkey  = 0x1122334455667788ULL;
  uint64_t send_match = 0;
  uint16_t pid = 0;
  uint16_t ri = 0;

  
  uint32_t rsp_chunk = 0;

  
  
  bool inc_enable = false;

  
  
  
  uint32_t rsp_pipeline = 0;

  
  
  CcConfig cc;

  
  
  
  
  bool tss_enable = false;
  uint32_t tss_sdi = 0;
  uint32_t tss_ssi = 0;
  bool tss_use_ssi = true;
  int tss_kdf = 0;              
  uint8_t tss_key[32] = {0};    
};

struct Completion {
  uint32_t msg_id = 0;
  uint8_t rc = RC_OK;
  bool read = false;
  std::vector<uint8_t> data;
};

class Endpoint {
 public:
  using TxFn = std::function<void(const std::vector<uint8_t>&)>;

  struct Stats {
    uint64_t tx_pkts = 0, rx_pkts = 0;
    uint64_t tx_retx = 0, tx_drop = 0, rx_drop = 0;
    uint64_t ack_tx = 0, ack_rx = 0, nack_tx = 0, nack_rx = 0;
    uint64_t dup_rx = 0, crc_err = 0, pdc_miss = 0;
    uint64_t write_rx = 0, send_rx = 0, read_rx = 0;
    uint64_t completions = 0;
    
    uint64_t ce_rx = 0;         
    uint64_t ack_m_tx = 0;      
    uint64_t ack_m_rx = 0;      
    uint64_t trim_rx = 0;       
    uint64_t trim_last_hop_rx = 0;
    uint64_t nack_trim_rx = 0;  
    uint64_t nack_trim_last_hop_rx = 0;
    uint64_t reorder_rx = 0;    
    uint64_t read_retx = 0;     
    uint64_t sack_tx = 0, sack_rx = 0, sack_skip = 0;
    
    uint64_t mr_fail = 0;
    uint64_t mr_ok = 0;
    
    uint64_t atomics_rx = 0;
    uint64_t atomic_fail = 0;
    
    uint64_t msg_chunks = 0;     
    uint64_t msg_err = 0;        
    
    uint64_t retx_exhausted = 0; 
    uint64_t ack_req_rx = 0;     
    uint64_t reset_count = 0;    
    
    uint64_t pool_alloc = 0;      
    uint64_t pool_fail = 0;       
    uint64_t pool_delivered = 0;  
    
    uint64_t cc_defer = 0;        
    uint64_t cc_ack = 0;          
    uint64_t cc_ce = 0;           
    uint64_t cc_rto = 0;          
    
    uint64_t cmpl_rx = 0;
    
    uint64_t inc_rx = 0;
    
    uint64_t tss_sealed = 0;
    uint64_t tss_opened = 0;
    uint64_t tss_auth_fail = 0;
    uint64_t tss_replay = 0;
  };

  explicit Endpoint(const EndpointConfig& cfg) : cfg_(cfg) {
    if (cfg_.cc.enable) cc_.reset(new CcRuntime(cfg_.cc));
    if (cfg_.tss_enable) {
      TssPathConfig tc;
      tc.sdi = cfg_.tss_sdi;
      tc.ssi = cfg_.tss_ssi;
      tc.use_ssi = cfg_.tss_use_ssi;
      tc.kdf_mode = cfg_.tss_kdf;
      std::copy(cfg_.tss_key, cfg_.tss_key + 32, tc.key);
      tss_.reset(tss_path_create(tc));
    }
  }

  void set_tx(TxFn fn) { tx_ = std::move(fn); }
  void drop_next_tx(bool en = true) { drop_next_tx_ = en; }
  void set_now(uint64_t ns) { now_ns_ = ns; }
  uint64_t now() const { return now_ns_; }
  const Stats& stats() const { return st_; }
  bool tss_active() const { return tss_ != nullptr; }
  TssPathStats tss_path_stats() const {
    return tss_ ? tss_->stats() : TssPathStats{};
  }

  
  bool local_allowed(uint64_t off, uint32_t len, bool write) const {
#ifndef UET_MR_LIFE_RED
    for (int i = 0; i < MrTable::kEntries; i++) {
      const MrEntry* e = mr_.get(i);
      if (!e || !e->armed) continue;
      if (write ? !e->local_write : !e->local_read) continue;
      if (off >= e->base && off + len <= e->base + e->length) return true;
    }
    return false;
#else
    (void)off; (void)len; (void)write;
    return true;   
#endif
  }

  void reset() {
    pending_.clear();
    pending_msg_.clear();
    pdc_rx_.clear();
    rsp_acc_.clear();
    completions_.clear();
    messages_.clear();
    send_buf_.clear();
    send_active_ = false;
    msg_active_ = false;
    send_pool_idx_ = -1;
    pools_.reset_state();
    cc_backlog_.clear();
    cc_pumping_ = false;
    if (cfg_.cc.enable) cc_.reset(new CcRuntime(cfg_.cc));
    else                cc_.reset();
    st_.reset_count++;
  }
  
  
  uec_inc::Engine& inc_engine() { return inc_eng_; }
  uec_inc::Sep& inc_sep() { return inc_sep_; }
  bool take_inc_response(uec_inc::Response& out) {
    if (inc_rsp_.empty()) return false;
    out = inc_rsp_.front();
    inc_rsp_.erase(inc_rsp_.begin());
    return true;
  }
  size_t inc_response_count() const { return inc_rsp_.size(); }

  
  bool     cmpl_valid() const { return cmpl_valid_; }
  uint64_t cmpl_data() const { return cmpl_data_; }
  void set_tx_psn(uint16_t rpdc, uint32_t v) { tx_psn_[rpdc] = v; }
  void set_rx_psn(uint16_t dpdcid, uint32_t v) { rx_of(dpdcid).next = v; }

  
  
  bool local_write(uint64_t off, const std::vector<uint8_t>& data) {
    if (!local_allowed(off, (uint32_t)data.size(), true)) return false;
    set_mem(off, data);
    return true;
  }
  bool local_read(uint64_t off, uint32_t len, std::vector<uint8_t>& out) const {
    if (!local_allowed(off, len, false)) return false;
    return get_mem(off, len, out);
  }

  
  MrTable& mr() { return mr_; }
  const MrTable& mr() const { return mr_; }

  
  
  BufferPools& pools() { return pools_; }
  const BufferPools& pools() const { return pools_; }
  PoolStats pool_stats() const {
    return cfg_.recv_pool >= 0 ? pools_.stats((uint32_t)cfg_.recv_pool)
                               : PoolStats{};
  }
  bool pool_release(uint32_t idx) {
    return cfg_.recv_pool >= 0 &&
           pools_.release((uint32_t)cfg_.recv_pool, idx);
  }

  
  bool      cc_enabled() const { return cc_ != nullptr && cc_->enabled(); }
  uint32_t  cc_cwnd() const { return cc_ ? cc_->cwnd() : 0; }
  uint64_t  cc_inflight() const { return cc_ ? cc_->inflight() : 0; }
  uec_pcm::Engine* cc_pcm() { return cc_ ? &cc_->pcm() : nullptr; }

  
  bool send_write(uint64_t off, const std::vector<uint8_t>& data) {
    return send_write(off, data, cfg_.tos);
  }

  
  
  
  
  bool send_write(uint64_t off, const std::vector<uint8_t>& data, uint8_t tos,
                  uint8_t next = NEXT_REQ_STD, bool hd = false,
                  uint64_t hdr = 0, uint16_t rpdc = 0xFFFF) {
    if (data.size() > kMaxPayload) return false;
    uint32_t msg_id = next_msg_id_++;
    const uint16_t rp = (rpdc == 0xFFFF) ? cfg_.remote_pdc : rpdc;
    Packet p = Packet::make_write(tx_psn_[rp]++, cfg_.local_pdc, rp,
                                  msg_id, cfg_.job_id,
                                  off, cfg_.write_mkey, data);
    p.ses.pid = cfg_.pid;
    p.ses.ri  = cfg_.ri;
    p.ses_next = next;
    p.ses.hd = hd;
    p.ses.header_data = hdr;
    p.tos = tos;
    return start_request(p, false, 0);
  }

  bool send_send(const std::vector<uint8_t>& data) {
    return send_send(data, cfg_.tos);
  }

  bool send_send(const std::vector<uint8_t>& data, uint8_t tos,
                 uint8_t next = NEXT_REQ_STD, bool hd = false,
                 uint64_t hdr = 0) {
    if (data.size() > kMaxPayload) return false;
    uint32_t msg_id = next_msg_id_++;
    Packet p = Packet::make_send(tx_psn_[cfg_.remote_pdc]++, cfg_.local_pdc,
                                 cfg_.remote_pdc, msg_id, cfg_.job_id, data);
    p.ses.pid = cfg_.pid;
    p.ses.ri  = cfg_.ri;
    p.ses.match_bits = cfg_.send_match;
    p.ses_next = next;
    p.ses.hd = hd;
    p.ses.header_data = hdr;
    p.tos = tos;
    return start_request(p, false, 0);
  }

  bool send_read(uint64_t off, uint32_t len,
                 uint8_t next = NEXT_REQ_STD, uint16_t rpdc = 0xFFFF) {
    uint32_t msg_id = next_msg_id_++;
    const uint16_t rp = (rpdc == 0xFFFF) ? cfg_.remote_pdc : rpdc;
    Packet p = Packet::make_read(tx_psn_[rp]++, cfg_.local_pdc, rp,
                                 msg_id, cfg_.job_id,
                                 off, cfg_.read_mkey, len);
    p.ses.pid = cfg_.pid;
    p.ses.ri  = cfg_.ri;
    p.ses_next = next;
    p.tos = cfg_.tos;
    return start_request(p, true, len);
  }

  
  bool send_ctrl_ack_req(uint16_t rpdc = 0xFFFF) {
    const uint16_t rp = (rpdc == 0xFFFF) ? cfg_.remote_pdc : rpdc;
    Packet p = Packet::make_ctrl(CTRL_ACK_REQ, 0, cfg_.local_pdc, rp);
    p.src_ip = cfg_.ip;
    p.dst_ip = cfg_.peer_ip;
    p.smac = cfg_.mac;
    p.dmac = cfg_.peer_mac;
    p.entropy = 0x4c4c;
    emit(p);
    return true;
  }

  
  
  
  
  bool send_atomic(uint64_t off, uint8_t op, uint8_t dt, uint64_t operand,
                   bool fetch, uint64_t cmp = 0, uint64_t swap = 0,
                   bool cswap = false) {
    std::vector<uint8_t> pl(cswap ? 36 : 12, 0);
    pl[0] = op;
    pl[1] = dt;
    put_le64(pl, 4, operand);
    if (cswap) {
      put_le64(pl, 12, cmp);
      put_le64(pl, 28, swap);
    }
    uint32_t msg_id = next_msg_id_++;
    Packet p = Packet::make_request(fetch ? SES_FETCH_ATOMIC : SES_ATOMIC,
                                    PDS_RUD_REQ, tx_psn_[cfg_.remote_pdc]++,
                                    cfg_.local_pdc, cfg_.remote_pdc, msg_id,
                                    cfg_.job_id, off, cfg_.write_mkey, pl);
    p.ses.pid = cfg_.pid;
    p.ses.ri  = cfg_.ri;
    p.ses.req_len = cswap ? 32 : 8;
    p.tos = cfg_.tos;
    
    
    return start_request(p, true, 8);
  }

  
  
  
  bool send_write_seg(uint64_t msg_base, const std::vector<uint8_t>& chunk,
                      uint8_t ses_flags, uint32_t msg_off,
                      uint32_t total_len, bool hd = false,
                      uint64_t hdr = 0) {
    if (chunk.size() > kMaxPayload) return false;
    uint32_t msg_id = next_msg_id_++;
    Packet p = Packet::make_write(tx_psn_[cfg_.remote_pdc]++, cfg_.local_pdc,
                                  cfg_.remote_pdc, msg_id, cfg_.job_id,
                                  msg_base, cfg_.write_mkey, chunk);
    p.ses.pid = cfg_.pid;
    p.ses.ri  = cfg_.ri;
    p.ses.flags = ses_flags;
    p.ses.req_len = total_len;
    p.ses.payload_len = (uint32_t)chunk.size();
    p.ses.msg_off = msg_off;
    p.ses.hd = hd;
    p.ses.header_data = hdr;
    p.tos = cfg_.tos;
    return start_request(p, false, 0);
  }

  
  
  bool send_send_seg(const std::vector<uint8_t>& chunk, uint8_t ses_flags,
                     uint32_t msg_off, uint32_t total_len) {
    if (chunk.size() > kMaxPayload) return false;
    uint32_t msg_id = next_msg_id_++;
    Packet p = Packet::make_send(tx_psn_[cfg_.remote_pdc]++, cfg_.local_pdc,
                                 cfg_.remote_pdc, msg_id, cfg_.job_id, chunk);
    p.ses.pid = cfg_.pid;
    p.ses.ri  = cfg_.ri;
    p.ses.match_bits = cfg_.send_match;
    p.ses.flags = ses_flags;
    p.ses.req_len = total_len;
    p.ses.payload_len = (uint32_t)chunk.size();
    p.ses.msg_off = msg_off;
    p.tos = cfg_.tos;
    return start_request(p, false, 0);
  }

  
  void on_frame(const std::vector<uint8_t>& wire) {
    
    
    
    
    
    std::vector<uint8_t> opened;
    const std::vector<uint8_t>* fp = &wire;
    if (tss_ != nullptr) {
      const TssOpenResult r = tss_->open_frame(wire, opened);
      if (r == TssOpenResult::AuthFail) {
        st_.tss_auth_fail++;
        st_.rx_drop++;
        return;
      }
      if (r == TssOpenResult::Replay) {
        st_.tss_replay++;
        st_.rx_drop++;
        return;
      }
      if (r == TssOpenResult::Ok) {
        st_.tss_opened++;
        fp = &opened;
      }
    }
    Packet p;
    if (!p.decode(*fp)) {
      st_.rx_drop++;
      return;
    }
    
    
    if (!p.crc_valid && !p.trimmed) {
      st_.crc_err++;
      st_.rx_drop++;
      return;
    }
    st_.rx_pkts++;
    if ((p.tos & 0x03) == 0x03) st_.ce_rx++;
    switch (p.kind) {
      case Kind::Request:  on_request(p); break;
      case Kind::Ack:      on_ack(p); break;
      case Kind::Response: on_response(p); break;
      case Kind::Nack:     on_nack(p); break;
      case Kind::Ctrl:     on_ctrl(p); break;
    }
  }

  void tick(uint64_t ns) {
    now_ns_ = ns;
    pump_rsp(true);             
    std::vector<uint32_t> due;
    for (const auto& kv : pending_) {
      if (ns >= kv.second.last_ns + cfg_.rto_ns) due.push_back(kv.first);
    }
    for (uint32_t psn : due) {
      auto it = pending_.find(psn);
      if (it == pending_.end()) continue;
      if (it->second.sacked) {
        
        if (ns < it->second.sacked_ns + 4 * cfg_.rto_ns) {
          st_.sack_skip++;
          continue;
        }
        it->second.sacked = false;
      }
      if (it->second.retx >= cfg_.max_retx) {
        st_.retx_exhausted++;
        if (cc_) {
          cc_->on_rto();
          st_.cc_rto++;
        }
        finish(psn, RC_TOO_LONG, {});
        continue;
      }
      it->second.pkt.req.flags |= PDS_REQ_RETX;
      it->second.retx++;
      it->second.last_ns = ns;
      st_.tx_retx++;
      if (it->second.read) st_.read_retx++;
      emit(it->second.pkt);
    }
  }

  bool poll(Completion& out) {
    if (completions_.empty()) return false;
    out = completions_.front();
    completions_.erase(completions_.begin());
    st_.completions++;
    return true;
  }

  
  void set_mem(uint64_t off, const std::vector<uint8_t>& data) {
    if (off + data.size() > mem_.size()) mem_.resize(off + data.size());
    std::copy(data.begin(), data.end(), mem_.begin() + off);
  }
  bool get_mem(uint64_t off, size_t len, std::vector<uint8_t>& out) const {
    if (off + len > mem_.size()) return false;
    out.assign(mem_.begin() + off, mem_.begin() + off + len);
    return true;
  }
  bool get_message(uint32_t msg_id, std::vector<uint8_t>& out) const {
    auto it = messages_.find(msg_id);
    if (it == messages_.end()) return false;
    out = it->second;
    return true;
  }
  size_t mem_size() const { return mem_.size(); }

 private:
  
  static constexpr size_t kMaxPayload = 16384;

  static uint64_t get_le64(const std::vector<uint8_t>& v, size_t off) {
    uint64_t x = 0;
    for (int i = 7; i >= 0; i--) x = (x << 8) | v[off + (size_t)i];
    return x;
  }
  static void put_le64(std::vector<uint8_t>& v, size_t off, uint64_t x) {
    for (int i = 0; i < 8; i++) v[off + (size_t)i] = (uint8_t)(x >> (8 * i));
  }

  
  static bool atom_op_ok(uint8_t op) {
    switch (op) {
      case 0x00: case 0x01: case 0x02: case 0x03:
      case 0x07: case 0x08: case 0x0a: case 0x0c:
      case 0x0d: case 0x0e: case 0x0f: case 0x10:
      case 0x11: case 0x12: return true;
      default: return false;
    }
  }
  static bool atom_is_cswap(uint8_t op) { return op >= 0x0d && op <= 0x12; }

  
  static uint64_t atom_apply(uint8_t op, uint8_t dt, uint64_t oldv,
                             uint64_t operand, uint64_t cmp) {
#ifdef UET_ATOMIC_RED
    
    (void)op; (void)dt; (void)operand; (void)cmp;
    return oldv;
#else
    const bool sg = (dt == 0x06);
    auto lt = [sg](uint64_t a, uint64_t b) {
      return sg ? (int64_t)a < (int64_t)b : a < b;
    };
    auto gt = [sg](uint64_t a, uint64_t b) {
      return sg ? (int64_t)a > (int64_t)b : a > b;
    };
    switch (op) {
      case 0x00: return lt(oldv, operand) ? oldv : operand;   
      case 0x01: return gt(oldv, operand) ? oldv : operand;   
      case 0x02: return oldv + operand;                       
      case 0x03: return oldv - operand;                       
      case 0x07: return oldv | operand;                       
      case 0x08: return oldv & operand;                       
      case 0x0a: return oldv ^ operand;                       
      case 0x0c: return operand;                              
      case 0x0d: return oldv == cmp ? operand : oldv;         
      case 0x0e: return oldv != cmp ? operand : oldv;         
      case 0x0f: return !gt(oldv, cmp) ? operand : oldv;      
      case 0x10: return lt(oldv, cmp) ? operand : oldv;       
      case 0x11: return !lt(oldv, cmp) ? operand : oldv;      
      case 0x12: return gt(oldv, cmp) ? operand : oldv;       
      default:   return oldv;
    }
#endif
  }

  void handle_atomic(const Packet& p) {
    const bool fetch = p.ses.opcode == SES_FETCH_ATOMIC;
    const uint8_t aop = p.payload.size() > 0 ? p.payload[0] : 0;
    const uint8_t dt  = p.payload.size() > 1 ? p.payload[1] : 0;
    const bool cs     = atom_is_cswap(aop);
    const size_t need = cs ? 36 : 12;

    
    if (!atom_op_ok(aop) || (dt != 0x06 && dt != 0x07) ||
        p.ses.req_len != (cs ? 32u : 8u)) {
      st_.atomic_fail++;
      send_error_response(p, RC_UNSUPPORTED_OP);
      return;
    }
    if (p.payload.size() != need) {
      st_.atomic_fail++;
      send_error_response(p, RC_UNSUPPORTED_SIZE);
      return;
    }
    if (p.ses.buffer_offset & 7ULL) {
      st_.atomic_fail++;
      send_error_response(p, RC_BAD_ADDR);
      return;
    }

    uint64_t oldv = 0;
    std::vector<uint8_t> cur;
    if (get_mem(p.ses.buffer_offset, 8, cur)) oldv = get_le64(cur, 0);
    const uint64_t operand = get_le64(p.payload, cs ? 28 : 4);
    const uint64_t cmp     = cs ? get_le64(p.payload, 12) : 0;
    const uint64_t newv    = atom_apply(aop, dt, oldv, operand, cmp);

    std::vector<uint8_t> wb(8);
    put_le64(wb, 0, newv);
    set_mem(p.ses.buffer_offset, wb);
    st_.atomics_rx++;

    Packet r;
    if (fetch) {
      std::vector<uint8_t> ov(8);
      put_le64(ov, 0, oldv);
      r = Packet::make_read_response(RC_OK, p.ses.msg_id, p.ses.job_id, 8,
                                     p.ses.msg_id, 0,
                                     ack_psn(rx_of(p.req.dpdcid)),
                                     p.req.dpdcid, p.req.spdcid, ov);
    } else {
      r = Packet::make_response(RC_OK, p.ses.msg_id, p.ses.job_id, 8,
                                ack_psn(rx_of(p.req.dpdcid)),
                                p.req.dpdcid, p.req.spdcid);
    }
    r.src_ip = cfg_.ip; r.dst_ip = cfg_.peer_ip;
    r.smac = cfg_.mac; r.dmac = cfg_.peer_mac;
    r.entropy = 0x7e7e;
    emit(r);
  }

  struct Pending {
    Packet pkt;
    uint64_t last_ns = 0;
    int retx = 0;
    bool read = false;
    uint32_t read_len = 0;
    bool sacked = false;
    uint64_t sacked_ns = 0;
  };

  EndpointConfig cfg_;
  TxFn tx_;
  Stats st_;
  uint64_t now_ns_ = 0;
  uint32_t next_msg_id_ = 1;
  std::map<uint16_t, uint32_t> tx_psn_;   
  bool drop_next_tx_ = false;
  std::map<uint32_t, Pending> pending_;          
  std::map<uint32_t, std::deque<Packet>> tgt_rsp_q_;  
  std::map<uint32_t, uint32_t> pending_msg_;     
  struct PdcRx {
    uint32_t next = 0;
    bool any = false;                  
    std::set<uint32_t> seen;
    std::map<uint32_t, Packet> ro;               
  };
  std::map<uint16_t, PdcRx> pdc_rx_;
#ifdef UET_PDC_RED_GLOBAL
  PdcRx red_rx_;                    
#endif
  PdcRx& rx_of(uint16_t dpdcid) {
#ifdef UET_PDC_RED_GLOBAL
    (void)dpdcid;
    return red_rx_;                 
#else
    return pdc_rx_[dpdcid];
#endif
  }
  bool is_local_pdc(uint16_t dpdcid) const {
    if (!cfg_.local_pdcs.empty()) {
      for (uint16_t v : cfg_.local_pdcs)
        if (v == dpdcid) return true;
      return false;
    }
    return dpdcid == cfg_.local_pdc;
  }
  std::vector<uint8_t> mem_;
  std::map<uint32_t, std::vector<uint8_t>> messages_;
  std::vector<Completion> completions_;
  std::map<uint32_t, std::vector<uint8_t>> rsp_acc_;  
  MrTable mr_;                                   
  BufferPools pools_;                            
  int send_pool_idx_ = -1;                       
  struct CcQueued { Packet p; bool read = false; uint32_t read_len = 0; };
  std::unique_ptr<CcRuntime> cc_;                
  std::unique_ptr<TssPathIf> tss_;               
  std::deque<CcQueued> cc_backlog_;              
  bool cc_pumping_ = false;
  static constexpr size_t kCcBacklogMax = 1024;  
  
  uec_inc::Engine inc_eng_;
  uec_inc::Sep    inc_sep_{inc_eng_};
  std::deque<uec_inc::Response> inc_rsp_;
  
  bool     msg_active_ = false;
  uint64_t msg_base_ = 0;
  uint32_t msg_total_ = 0;
  uint32_t msg_written_ = 0;   
  
  bool     cmpl_valid_ = false;
  uint64_t cmpl_data_ = 0;
  
  bool     send_active_ = false;
  uint32_t send_total_ = 0;
  uint32_t send_off_ = 0;
  std::vector<uint8_t> send_buf_;

  
  
  bool start_request(Packet& p, bool read, uint32_t read_len) {
    if (pending_.size() >= (size_t)cfg_.window) return false;
    if (cc_ && cc_->enabled() &&
        (!cc_backlog_.empty() || !cc_->can_send(p.payload.size()))) {
      if (cc_backlog_.size() >= kCcBacklogMax) return false;
      cc_backlog_.push_back(CcQueued{p, read, read_len});
      st_.cc_defer++;
      return true;
    }
    return start_now(p, read, read_len);
  }

  bool start_now(Packet& p, bool read, uint32_t read_len) {
    uint32_t psn = p.req.psn;
    p.src_ip = cfg_.ip;
    p.dst_ip = cfg_.peer_ip;
    p.smac = cfg_.mac;
    p.dmac = cfg_.peer_mac;
    p.entropy = (uint16_t)(0x4000u + (psn & 0x3fffu));
    if (cfg_.ordered) p.req.type = PDS_ROD_REQ;
    Pending pend;
    pend.pkt = p;
    pend.last_ns = now_ns_;
    pend.read = read;
    pend.read_len = read_len;
    pending_[psn] = pend;
    pending_msg_[p.ses.msg_id] = psn;
    if (cc_) cc_->on_send(p.payload.size());
    emit(p);
    return true;
  }

  void pump_cc() {
    if (!cc_ || cc_pumping_) return;
    cc_pumping_ = true;
    while (!cc_backlog_.empty() &&
           pending_.size() < (size_t)cfg_.window &&
           cc_->can_send(cc_backlog_.front().p.payload.size())) {
      CcQueued q = cc_backlog_.front();
      cc_backlog_.pop_front();
      start_now(q.p, q.read, q.read_len);
    }
    cc_pumping_ = false;
  }

  
  
  
  bool tss_should_seal(const Packet& p) const {
    if (p.payload.empty()) return false;
    if (p.kind == Kind::Request)
      return p.ses.opcode == SES_WRITE || p.ses.opcode == SES_SYNC_WRITE ||
             p.ses.opcode == SES_SEND;
    if (p.kind == Kind::Response) return p.rsp_data;
    return false;
  }

  void emit(const Packet& p) {
    if (drop_next_tx_) {
      drop_next_tx_ = false;
      st_.tx_drop++;
      return;
    }
    std::vector<uint8_t> frame;
    if (tss_ != nullptr && tss_should_seal(p)) {
      
      
      const std::vector<uint8_t> clear = p.encode();
      if (clear.empty() || !tss_->seal_frame(clear, frame)) {
        st_.tx_drop++;
        return;
      }
      st_.tss_sealed++;
    } else {
      frame = p.encode();
    }
    if (frame.empty()) return;
    st_.tx_pkts++;
    if (tx_) tx_(frame);
  }

  void send_ack_cc(uint32_t cack_psn, uint8_t flags, uint16_t spd,
                   uint16_t dpd, const PdcRx& rx) {
    
    uint32_t base = cack_psn + 1;
    uint64_t bitmap = 0;
    for (uint32_t i = 0; i < 64; i++) {
      uint32_t psn = base + i;
      if (rx.seen.count(psn) || rx.ro.count(psn))
        bitmap |= (1ULL << i);
    }
    Packet a = Packet::make_ack_cc(cack_psn, 1, bitmap, 0, spd, dpd, flags);
    a.src_ip = cfg_.ip;
    a.dst_ip = cfg_.peer_ip;
    a.smac = cfg_.mac;
    a.dmac = cfg_.peer_mac;
    a.entropy = 0x5a5a;
    st_.ack_tx++;
    st_.sack_tx++;
    if (flags & 0x20) st_.ack_m_tx++;
    emit(a);
  }

  void send_ack(uint32_t cack_psn, uint8_t flags, uint16_t spd, uint16_t dpd,
                const PdcRx& rx) {
    if (cfg_.sack) {
      send_ack_cc(cack_psn, flags, spd, dpd, rx);
      return;
    }
    Packet a = Packet::make_ack(cack_psn, 0, spd, dpd, flags);
    a.src_ip = cfg_.ip;
    a.dst_ip = cfg_.peer_ip;
    a.smac = cfg_.mac;
    a.dmac = cfg_.peer_mac;
    a.entropy = 0x5a5a;
    st_.ack_tx++;
    if (flags & 0x20) st_.ack_m_tx++;
    emit(a);
  }

  uint32_t ack_psn(const PdcRx& rx) const {
    
    
    return rx.any ? (rx.next - 1) : 0;
  }

  void send_nack(uint8_t code, uint32_t psn, uint16_t spd, uint16_t dpd) {
    Packet n = Packet::make_nack(code, psn, spd, dpd, 0);
    n.src_ip = cfg_.ip;
    n.dst_ip = cfg_.peer_ip;
    n.smac = cfg_.mac;
    n.dmac = cfg_.peer_mac;
    n.entropy = 0x6b6b;
    st_.nack_tx++;
    emit(n);
  }

  void send_read_response(const Packet& p, bool ce) {
    std::vector<uint8_t> data;
    if (p.ses.req_len > kMaxPayload ||
        !get_mem(p.ses.buffer_offset, p.ses.req_len, data)) {
      Packet r = Packet::make_response(RC_BAD_ADDR, p.ses.msg_id,
                                       p.ses.job_id, p.ses.req_len,
                                       ack_psn(rx_of(p.req.dpdcid)),
                                       p.req.dpdcid, p.req.spdcid);
      r.src_ip = cfg_.ip; r.dst_ip = cfg_.peer_ip;
      r.smac = cfg_.mac; r.dmac = cfg_.peer_mac; r.entropy = 0x7c7c;
      r.tos = ce ? 0x03 : 0;
      emit(r);
      return;
    }
    
    
    const size_t chunk = cfg_.rsp_chunk ? cfg_.rsp_chunk : data.size();
#ifdef UET_PIPE_RED_NOPIPE
    const bool pipelined = false;         
#else
    const bool pipelined = cfg_.rsp_pipeline != 0;
#endif
    for (size_t off = 0; off < data.size(); off += chunk) {
      const size_t n = std::min(chunk, data.size() - off);
      std::vector<uint8_t> part(data.begin() + off, data.begin() + off + n);
      Packet r = Packet::make_read_response(RC_OK, p.ses.msg_id,
                                            p.ses.job_id,
                                            (uint32_t)data.size(),
                                            p.ses.msg_id, (uint32_t)off,
                                            ack_psn(rx_of(p.req.dpdcid)),
                                            p.req.dpdcid, p.req.spdcid, part);
      r.src_ip = cfg_.ip; r.dst_ip = cfg_.peer_ip;
      r.smac = cfg_.mac; r.dmac = cfg_.peer_mac; r.entropy = 0x7c7c;
      r.tos = ce ? 0x03 : 0;
      if (pipelined) tgt_rsp_q_[p.req.psn].push_back(r);
      else emit(r);
    }
    if (pipelined) pump_rsp(false);
  }

  
  
  
  void pump_rsp(bool full) {
    if (tgt_rsp_q_.empty()) return;
    const size_t per = full ? (size_t)-1
                            : (size_t)(cfg_.rsp_pipeline ? cfg_.rsp_pipeline : 1);
    for (auto& kv : tgt_rsp_q_) {
      std::deque<Packet>& q = kv.second;
      size_t n = 0;
      while (!q.empty() && n < per) {
        emit(q.front());
        q.pop_front();
        n++;
      }
    }
    for (auto it = tgt_rsp_q_.begin(); it != tgt_rsp_q_.end();) {
      if (it->second.empty()) it = tgt_rsp_q_.erase(it);
      else ++it;
    }
  }

  
  
  
  void send_ok_response(const Packet& p) {
    Packet r = Packet::make_response(RC_OK, p.ses.msg_id, p.ses.job_id,
                                     p.ses.req_len,
                                     ack_psn(rx_of(p.req.dpdcid)),
                                     p.req.dpdcid, p.req.spdcid);
    r.src_ip = cfg_.ip; r.dst_ip = cfg_.peer_ip;
    r.smac = cfg_.mac; r.dmac = cfg_.peer_mac;
    r.entropy = 0x7f7f;
    emit(r);
  }

  void send_error_response(const Packet& p, uint8_t rc) {
    Packet r = Packet::make_response(rc, p.ses.msg_id, p.ses.job_id,
                                     p.ses.req_len,
                                     ack_psn(rx_of(p.req.dpdcid)),
                                     p.req.dpdcid, p.req.spdcid);
    r.src_ip = cfg_.ip; r.dst_ip = cfg_.peer_ip;
    r.smac = cfg_.mac; r.dmac = cfg_.peer_mac;
    r.entropy = 0x7d7d;
    emit(r);
  }

  
  
  bool deliver(const Packet& p) {
    if (p.ses.opcode == SES_ATOMIC || p.ses.opcode == SES_FETCH_ATOMIC) {
      handle_atomic(p);      
      return true;
    }
    if (p.ses.opcode == SES_WRITE || p.ses.opcode == SES_SYNC_WRITE) {
      
      
      
      const bool som = (p.ses.flags & SES_SOM) != 0;
      const bool eom = (p.ses.flags & SES_EOM) != 0;
      const uint32_t chunk = (uint32_t)p.payload.size();
      uint64_t chunk_base = p.ses.buffer_offset;
#ifndef UET_SOMEOM_RED
      if (!som) chunk_base += (uint64_t)p.ses.msg_off;
#endif

      if (!som && !msg_active_) {
        st_.msg_err++;
        send_error_response(p, RC_NO_MATCH);
        return true;
      }
      if (!som && (chunk_base < msg_base_ ||
                   chunk_base + chunk > msg_base_ + msg_total_)) {
        st_.msg_err++;
        send_error_response(p, RC_BAD_ADDR);
        return true;
      }
#ifndef UET_FRAG_RED
      
      
      if (!som && p.ses.msg_off != msg_written_) {
        st_.msg_err++;
        send_error_response(p, RC_BAD_ADDR);
        return true;
      }
#endif
      if (som && eom && p.ses.req_len != 0 && chunk != p.ses.req_len) {
        st_.msg_err++;
        send_error_response(p, RC_UNSUPPORTED_SIZE);
        return true;
      }
      if (p.ses.req_len != 0 && chunk > p.ses.req_len) {
        st_.msg_err++;
        send_error_response(p, RC_UNSUPPORTED_SIZE);
        return true;
      }

#ifndef UET_CMPL_RED
      if (som && p.ses.hd) {
        cmpl_valid_ = true;
        cmpl_data_  = p.ses.header_data;
        st_.cmpl_rx++;
      }
#endif
      const bool fragmented = msg_active_ || !som;
      set_mem(chunk_base, p.payload);
      st_.write_rx++;
      messages_[p.ses.msg_id] = p.payload;
      if (som) {
        msg_base_ = p.ses.buffer_offset;
        msg_total_ = p.ses.req_len;
        msg_active_ = true;
        msg_written_ = 0;
      } else {
        st_.msg_chunks++;
      }
      msg_written_ += chunk;
      if (eom) {
        msg_active_ = false;
        if (fragmented) {
          send_ok_response(p);   
          return true;
        }
      }
      return false;              
    }
    if (p.ses.opcode == SES_SEND) {
      
#ifdef UET_INC_RED_NOJOIN
      const bool inc_on = false;        
#else
      const bool inc_on = cfg_.inc_enable;
#endif
      if (inc_on && p.payload.size() >= 13) {
        uint32_t ip = (uint32_t)p.payload[0] |
                      ((uint32_t)p.payload[1] << 8) |
                      ((uint32_t)p.payload[2] << 16) |
                      ((uint32_t)p.payload[3] << 24);
        uint64_t iv = 0;
        for (int i = 0; i < 8; i++) iv = (iv << 8) | p.payload[(size_t)(4 + i)];
        uec_inc::Info info;
        const int rank = p.payload[12];
        if (uec_inc::Info::decode(iv, info)) {
          std::vector<uint8_t> body(p.payload.begin() + 13, p.payload.end());
          uec_inc::Request req = inc_sep_.make_request(ip, rank, info, body);
          auto rsps = inc_sep_.rx(req);
          for (const auto& r : rsps) inc_rsp_.push_back(r);
          st_.inc_rx++;
          st_.send_rx++;
          return false;                 
        }
      }
      st_.send_rx++;
      
      
      std::vector<uint8_t> msg = p.payload;
      if (p.ses.hd && p.ses_next == NEXT_REQ_MEDIUM) {
        std::vector<uint8_t> with_hdr(8 + msg.size());
        for (int i = 0; i < 8; i++)
          with_hdr[(size_t)i] = (uint8_t)(p.ses.header_data >> (8 * (7 - i)));
        std::copy(msg.begin(), msg.end(), with_hdr.begin() + 8);
        msg = with_hdr;
      }
      
      
      const bool som = (p.ses.flags & SES_SOM) != 0;
      const bool eom = (p.ses.flags & SES_EOM) != 0;
      const uint32_t xfer = (uint32_t)msg.size();
#ifdef UET_REASM_RED_SENDOFF
      const uint32_t off = 0;   
#else
      const uint32_t off = som ? 0 : p.ses.msg_off;
#endif

      if (!som && !send_active_) {
        st_.msg_err++;
        send_error_response(p, RC_NO_MATCH);
        return true;
      }
      if (!som && send_total_ != 0 &&
          (off != send_off_ || (uint64_t)off + xfer > send_total_)) {
        st_.msg_err++;
        send_error_response(p, RC_BAD_ADDR);
        return true;
      }

      const bool fragmented = send_active_ || !som;

      
      const BufferPools::Pool* pp = nullptr;
      uint64_t dst = cfg_.recv_base + off;
      if (cfg_.recv_pool >= 0) {
        pp = pools_.get((uint32_t)cfg_.recv_pool);
        if (pp == nullptr) {
          st_.pool_fail++;
          send_active_ = false;
          send_error_response(p, RC_BAD_ADDR);
          return true;
        }
        if (som) {
          if (send_pool_idx_ >= 0) {       
            pools_.release((uint32_t)cfg_.recv_pool, (uint32_t)send_pool_idx_);
            send_pool_idx_ = -1;
          }
          const int idx = pools_.alloc((uint32_t)cfg_.recv_pool);
          if (idx < 0) {
            st_.pool_fail++;
            send_active_ = false;
            send_error_response(p, RC_UNDELIVERABLE);
            return true;
          }
          send_pool_idx_ = idx;
          st_.pool_alloc++;
          if ((uint64_t)p.ses.req_len > pp->buf_size) {
            st_.pool_fail++;
            pools_.release((uint32_t)cfg_.recv_pool, (uint32_t)idx);
            send_pool_idx_ = -1;
            send_active_ = false;
            send_error_response(p, RC_TOO_LONG);
            return true;
          }
        } else if (send_pool_idx_ < 0) {
          st_.pool_fail++;
          send_error_response(p, RC_NO_MATCH);
          return true;
        }
        if ((uint64_t)off + xfer > pp->buf_size) {
          st_.pool_fail++;
          pools_.release((uint32_t)cfg_.recv_pool, (uint32_t)send_pool_idx_);
          send_pool_idx_ = -1;
          send_active_ = false;
          send_buf_.clear();
          send_off_ = 0;
          send_error_response(p, RC_TOO_LONG);
          return true;
        }
        dst = pp->base + (uint64_t)send_pool_idx_ * pp->buf_size + off;
      }

      if (som) {
        send_active_ = true;
        send_total_  = p.ses.req_len;
        send_off_    = 0;
        send_buf_.clear();
      }
      send_buf_.insert(send_buf_.end(), msg.begin(), msg.end());
      send_off_ += xfer;
      if (!som) st_.msg_chunks++;
      if ((cfg_.enforce_mr || cfg_.recv_pool >= 0) && !msg.empty())
        set_mem(dst, msg);
      if (eom) {
        send_active_ = false;
        messages_[p.ses.msg_id] = send_buf_;
        if (cfg_.recv_pool >= 0 && send_pool_idx_ >= 0) {
          pools_.mark_delivered((uint32_t)cfg_.recv_pool,
                                (uint32_t)send_pool_idx_);
          st_.pool_delivered++;
          send_pool_idx_ = -1;
        }
        if (fragmented) {
          send_ok_response(p);    
          return true;
        }
      } else {
        messages_[p.ses.msg_id] = msg;   
      }
      return false;               
    } else if (p.ses.opcode == SES_READ) {
      st_.read_rx++;
      send_read_response(p, (p.tos & 0x03) == 0x03);
      return true;
    }
    return false;
  }

  void on_request(const Packet& p) {
    if (!is_local_pdc(p.req.dpdcid)) {
      st_.pdc_miss++;
      send_nack(NACK_INV_DPDCID, p.req.psn, p.req.dpdcid, p.req.spdcid);
      return;
    }
#ifdef UET_PDC_RED_ACKPDC
    const uint16_t spd = cfg_.local_pdc; 
    const uint16_t dpd = cfg_.remote_pdc;
#else
    const uint16_t spd = p.req.dpdcid;   
    const uint16_t dpd = p.req.spdcid;   
#endif
    PdcRx& rx = rx_of(p.req.dpdcid);
    const uint32_t psn = p.req.psn;
    const uint8_t aflags = ((p.tos & 0x03) == 0x03) ? 0x20 : 0;

    
    
    if (p.trimmed) {
      if (p.trimmed_last_hop) st_.trim_last_hop_rx++;
      else st_.trim_rx++;
      send_nack(p.trimmed_last_hop ? NACK_TRIMMED_LAST_HOP : NACK_TRIMMED,
                psn, spd, dpd);
      return;
    }

    
    
    if (rx.seen.count(psn) || rx.ro.count(psn)) {
      st_.dup_rx++;
      if (p.ses.opcode == SES_READ) send_read_response(p, aflags != 0);
      else send_ack(ack_psn(rx), aflags, spd, dpd, rx);
      return;
    }

    
    
    
    
    const bool one_packet = (p.ses.flags & SES_SOM) && (p.ses.flags & SES_EOM);
    if ((p.ses.opcode == SES_WRITE || p.ses.opcode == SES_SEND) &&
        one_packet && p.ses.req_len != 0 && p.payload.size() < p.ses.req_len) {
      st_.trim_rx++;
      send_nack(NACK_TRIMMED, psn, spd, dpd);
      return;
    }

    
    
    
    if (cfg_.enforce_mr) {
      uint8_t rc = mr_.authorize(p.ses.opcode, p.ses.job_id, p.ses.pid,
                                 p.ses.ri, p.ses.match_bits,
                                 p.ses.buffer_offset, p.ses.req_len,
                                 (uint32_t)kMaxPayload, &pools_);
      if (rc != RC_OK) {
        st_.mr_fail++;
        if (!rx.seen.count(psn)) {
          rx.seen.insert(psn);
          rx.any = true;
          if (psn == rx.next)
            while (rx.seen.count(rx.next)) rx.next++;
        }
        send_error_response(p, rc);
        return;
      }
      st_.mr_ok++;
    }

    
    if (p.req.type == PDS_ROD_REQ && psn > rx.next) {
      rx.ro.emplace(psn, p);
      st_.reorder_rx++;
      send_ack(ack_psn(rx), aflags, spd, dpd, rx);
      return;
    }

    rx.seen.insert(psn);
    rx.any = true;
    
    
    if (psn == rx.next)
      while (rx.seen.count(rx.next)) rx.next++;
    bool read_resp = deliver(p);
    
    while (!rx.ro.empty() && rx.ro.begin()->first == rx.next) {
      Packet q = rx.ro.begin()->second;
      rx.ro.erase(rx.ro.begin());
      rx.seen.insert(rx.next);
      rx.next++;
      rx.any = true;
      while (rx.seen.count(rx.next)) rx.next++;
      deliver(q);
    }
    if (!read_resp) send_ack(ack_psn(rx), aflags, spd, dpd, rx);
  }

  
  void on_ctrl(const Packet& p) {
    if (p.ctrl.ctrl_type != CTRL_ACK_REQ) return;
    st_.ack_req_rx++;
#ifndef UET_REC_RED_ACKREQ
    if (!is_local_pdc(p.ctrl.dpdcid)) return;
    PdcRx& rx = rx_of(p.ctrl.dpdcid);
    const uint8_t aflags = ((p.tos & 0x03) == 0x03) ? 0x20 : 0;
    send_ack(ack_psn(rx), aflags, p.ctrl.dpdcid, p.ctrl.spdcid, rx);
#endif
  }

  void on_ack(const Packet& p) {
    st_.ack_rx++;
    if (p.ack.flags & 0x20) st_.ack_m_rx++;
    if (p.ack.cc) {
      st_.sack_rx++;
      int64_t base = (int64_t)p.ack.cack_psn + p.ack.sack_psn_offset;
      for (int i = 0; i < 64; i++) {
        if (!(p.ack.sack_bitmap & (1ULL << i))) continue;
        int64_t psn = base + i;
        if (psn < 0 || psn > 0xFFFFFFFFLL) continue;
        auto it = pending_.find((uint32_t)psn);
        if (it == pending_.end()) continue;
        it->second.sacked = true;
        it->second.sacked_ns = now_ns_;
      }
    }
    uint32_t cack = p.ack.cack_psn;
    std::vector<uint32_t> done;
    for (const auto& kv : pending_) {
      if (kv.second.read) continue;
      if (kv.first <= cack) done.push_back(kv.first);
    }
    const bool ce = (p.ack.flags & 0x20) != 0;
    for (uint32_t psn : done) {
      if (cc_) {
        auto it = pending_.find(psn);
        if (it != pending_.end()) {
          cc_->on_ack(ce, (int64_t)(now_ns_ - it->second.last_ns));
          st_.cc_ack++;
          if (ce) st_.cc_ce++;
        }
      }
      finish(psn, RC_OK, {});
    }
  }

  void on_response(const Packet& p) {
    uint32_t msg_id = p.rsp.msg_id;
#ifdef UET_PIPE_RED_FIFO
    
    (void)msg_id;
    if (pending_.empty()) return;
    const uint32_t psn = pending_.begin()->first;
#else
    auto mi = pending_msg_.find(msg_id);
    uint32_t psn;
    if (mi != pending_msg_.end()) {
      psn = mi->second;
    } else {
      
      
      
      psn = p.ack.cack_psn;
      if (pending_.find(psn) == pending_.end()) return;
    }
#endif
    if (p.rsp.rc != RC_OK) {
      rsp_acc_.erase(psn);
      finish(psn, p.rsp.rc, {});
      return;
    }
    if (!p.rsp_data) {
      rsp_acc_.erase(psn);
      finish(psn, RC_OK, {});
      return;
    }
    
    std::vector<uint8_t>& acc = rsp_acc_[psn];
    if (acc.size() < (size_t)p.rsp.msg_off + p.payload.size())
      acc.resize((size_t)p.rsp.msg_off + p.payload.size());
    std::copy(p.payload.begin(), p.payload.end(),
              acc.begin() + p.rsp.msg_off);
    const uint32_t total = p.rsp.mod_len;
#ifndef UET_REASM_RED_READCHUNK
    if (total != 0 && (uint64_t)p.rsp.msg_off + p.payload.size() < total)
      return;                                   
#endif
    if (total != 0) acc.resize(total);
    std::vector<uint8_t> full = acc;
    rsp_acc_.erase(psn);
    finish(psn, RC_OK, full);
  }

  void on_nack(const Packet& p) {
    st_.nack_rx++;
    if (p.nack.nack_code == NACK_TRIMMED) st_.nack_trim_rx++;
    if (p.nack.nack_code == NACK_TRIMMED_LAST_HOP) {
      st_.nack_trim_rx++;
      st_.nack_trim_last_hop_rx++;
    }
    auto it = pending_.find(p.nack.psn);
    if (it == pending_.end()) return;
    
    
    if (it->second.retx >= cfg_.max_retx) {
      st_.retx_exhausted++;
      finish(p.nack.psn, RC_TOO_LONG, {});
      return;
    }
    it->second.retx++;
    it->second.pkt.req.flags |= PDS_REQ_RETX;
    it->second.last_ns = now_ns_;
    st_.tx_retx++;
    emit(it->second.pkt);
  }

  void finish(uint32_t psn, uint8_t rc, const std::vector<uint8_t>& data) {
    auto it = pending_.find(psn);
    if (it == pending_.end()) return;
    if (cc_) cc_->on_complete(it->second.pkt.payload.size());
    Completion c;
    c.msg_id = it->second.pkt.ses.msg_id;
    c.rc = rc;
    c.read = it->second.read;
    c.data = data;
    completions_.push_back(c);
    pending_msg_.erase(c.msg_id);
    pending_.erase(it);
    pump_cc();
  }
};

}  
