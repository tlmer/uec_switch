

#pragma once
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace uec_inc {

enum Rc : uint8_t {
  RC_OK               = 0x01,
  RC_BAD_GENERATION   = 0x02,
  RC_NO_MATCH         = 0x05,
  RC_UNSUPPORTED_OP   = 0x06,
  RC_UNSUPPORTED_SIZE = 0x07,
  RC_AMO_UNSUPPORTED_DT = 0x10,
};

enum Op : uint8_t {
  OP_REDUCE = 0x00, OP_ALLREDUCE = 0x01, OP_BCAST = 0x02,
  OP_BARRIER = 0x03, OP_EXSCAN = 0x04, OP_SYNCBCAST = 0x05,
};

enum Reduce : uint8_t {
  R_MIN = 0x00, R_MAX = 0x01, R_SUM = 0x02, R_SUM_SCALE = 0x03,
  R_PROD = 0x04, R_LOR = 0x05, R_LAND = 0x06, R_BOR = 0x07,
  R_BAND = 0x08, R_LXOR = 0x09, R_BXOR = 0x0A,
  R_MINLOC = 0x0B, R_MAXLOC = 0x0C,
};

enum DType : uint8_t {
  DT_INT32 = 0x04, DT_UINT32 = 0x05, DT_BF16 = 0x10, DT_FP16 = 0x11,
};

struct Info {
  uint8_t  ver = 0, rt = 0, ip = 0, fo = 0, rsvd = 0;
  uint8_t  op_type = 0, data_type = 0, reduce_op = 0;
  uint32_t cid = 0;
  uint32_t csn = 0;             
  uint64_t encode() const {
    uint64_t v = 0;
    v |= (uint64_t)(ver & 3) << 62;
    v |= (uint64_t)(rt & 1) << 61;
    v |= (uint64_t)(ip & 1) << 60;
    v |= (uint64_t)(fo & 1) << 59;
    v |= (uint64_t)(rsvd & 7) << 56;
    v |= (uint64_t)op_type << 48;
    v |= (uint64_t)(cid & 0xFFFFF) << 28;
    v |= (uint64_t)(csn & 0xFFF) << 16;
    v |= (uint64_t)data_type << 8;
    v |= (uint64_t)reduce_op;
    return v;
  }
  static bool decode(uint64_t v, Info& out) {
    out.ver = (uint8_t)((v >> 62) & 3);
    out.rt = (uint8_t)((v >> 61) & 1);
    out.ip = (uint8_t)((v >> 60) & 1);
    out.fo = (uint8_t)((v >> 59) & 1);
    out.rsvd = (uint8_t)((v >> 56) & 7);
    out.op_type = (uint8_t)((v >> 48) & 0xFF);
    out.cid = (uint32_t)((v >> 28) & 0xFFFFF);
    out.csn = (uint32_t)((v >> 16) & 0xFFF);
    out.data_type = (uint8_t)((v >> 8) & 0xFF);
    out.reduce_op = (uint8_t)(v & 0xFF);
    return true;
  }
};

struct Result {
  uint8_t rc = RC_OK;
  bool deferred = false;
  bool complete = false;
  uint32_t cid = 0, csn = 0;
  std::map<int, std::vector<uint8_t>> outputs;  
  std::vector<int> acks;                         
};

inline int dtype_size(uint8_t dt) {
  switch (dt) {
    case DT_INT32: case DT_UINT32: return 4;
    case DT_BF16: case DT_FP16: return 2;
    default: return 0;
  }
}
inline bool dtype_ok(uint8_t dt) { return dtype_size(dt) != 0; }
inline bool reduce_op_ok(uint8_t op) { return op <= R_MAXLOC; }
inline bool op_ok(uint8_t op) { return op <= OP_SYNCBCAST; }
inline bool float_dtype(uint8_t dt) { return dt == DT_BF16 || dt == DT_FP16; }

inline size_t elem_size(uint8_t dt, uint8_t rop) {
  if (rop == R_MINLOC || rop == R_MAXLOC) return 8;
  return (size_t)dtype_size(dt);
}

inline float half_to_float(uint16_t h) {
  uint32_t sign = (uint32_t)(h & 0x8000) << 16;
  uint32_t exp = (h >> 10) & 0x1F;
  uint32_t man = h & 0x3FF;
  uint32_t f;
  if (exp == 0) {
    if (man == 0) {
      f = sign;
    } else {
      int e = -14;
      while ((man & 0x400) == 0) { man <<= 1; e--; }
      man &= 0x3FF;
      f = sign | ((uint32_t)(e + 127) << 23) | (man << 13);
    }
  } else if (exp == 31) {
    f = sign | 0x7F800000u | (man << 13);
  } else {
    f = sign | ((uint32_t)((int)exp - 15 + 127) << 23) | (man << 13);
  }
  float out;
  std::memcpy(&out, &f, 4);
  return out;
}

inline uint16_t float_to_half(float val) {
  uint32_t u;
  std::memcpy(&u, &val, 4);
  uint32_t sign = (u >> 16) & 0x8000;
  int32_t exp = (int32_t)((u >> 23) & 0xFF) - 127;
  uint32_t man = u & 0x7FFFFF;
  if (exp == 128) {                       
    if (man) return (uint16_t)(sign | 0x7E00 | (man >> 13));
    return (uint16_t)(sign | 0x7C00);
  }
  if (exp > 15) return (uint16_t)(sign | 0x7C00);
  if (exp >= -14) {
    uint16_t h = (uint16_t)(sign | ((exp + 15) << 10) | (man >> 13));
    uint32_t rem = man & 0x1FFF;
    if (rem > 0x1000 || (rem == 0x1000 && (h & 1))) h++;
    return h;
  }
  if (exp < -24) return (uint16_t)sign;
  uint32_t m32 = 0x800000u | man;
  int shift = -exp - 1;
  uint32_t h = m32 >> shift;
  uint32_t half_bit = 1u << (shift - 1);
  uint32_t rem = m32 & ((1u << shift) - 1);
  if (rem > half_bit || (rem == half_bit && (h & 1))) h++;
  return (uint16_t)(sign | h);            
}

inline float bf16_to_float(uint16_t h) {
  uint32_t u = (uint32_t)h << 16;
  float f;
  std::memcpy(&f, &u, 4);
  return f;
}

inline uint16_t float_to_bf16(float val) {
  uint32_t u;
  std::memcpy(&u, &val, 4);
  uint32_t lsb = (u >> 16) & 1;
  u += 0x7FFF + lsb;                      
  return (uint16_t)(u >> 16);
}

class Engine {
 public:
  bool add_comm(uint32_t cid, const std::vector<int>& ranks, int root = 0,
                uint32_t factor = 1, int max_inflight_ops = 8,
                size_t max_bytes = 1u << 20) {
    if (ranks.empty()) return false;
    Comm c;
    c.cid = cid;
    c.ranks = ranks;
    c.root = root;
    c.factor = factor ? factor : 1;
    c.max_inflight = max_inflight_ops > 0 ? max_inflight_ops : 1;
    c.max_bytes = max_bytes;
    comms_[cid] = c;
    return true;
  }
  bool remove_comm(uint32_t cid) { return comms_.erase(cid) != 0; }
  bool has_comm(uint32_t cid) const { return comms_.count(cid) != 0; }
  uint32_t csn(uint32_t cid) const {
    auto it = comms_.find(cid);
    return it == comms_.end() ? 0 : it->second.csn;
  }
  void set_csn(uint32_t cid, uint32_t csn) {
    auto it = comms_.find(cid);
    if (it != comms_.end()) it->second.csn = csn & 0xFFF;
  }
  size_t pending_ops(uint32_t cid) const {
    auto it = pending_.find(cid);
    return it == pending_.end() ? 0 : it->second.size();
  }
  void set_ordering_natural(bool en) { natural_ = en; }
  const std::vector<int>& last_order() const { return last_order_; }
  uint64_t ops_completed() const { return ops_completed_; }
  uint64_t defer_count() const { return defer_count_; }
  uint64_t error_count() const { return error_count_; }
  uint64_t bytes_reduced() const { return bytes_reduced_; }

  
  
  std::vector<Result> submit(int rank, const Info& in,
                             const std::vector<uint8_t>& payload) {
    std::vector<Result> res;
    auto ci = comms_.find(in.cid);
    if (ci == comms_.end() || !is_member(ci->second, rank)) {
      res.push_back(err(in, RC_NO_MATCH));
      return res;
    }
    Comm& c = ci->second;
    if (in.ver != 0 || !op_ok(in.op_type)) {
      res.push_back(err(in, RC_UNSUPPORTED_OP));
      return res;
    }
    const bool reduction = (in.op_type == OP_REDUCE || in.op_type == OP_ALLREDUCE ||
                            in.op_type == OP_EXSCAN);
    if (reduction && (!dtype_ok(in.data_type) ||
                      !reduce_op_ok(in.reduce_op) ||
                      (float_dtype(in.data_type) &&
                       in.reduce_op != R_MIN && in.reduce_op != R_MAX &&
                       in.reduce_op != R_SUM &&
                       in.reduce_op != R_MINLOC && in.reduce_op != R_MAXLOC))) {
      res.push_back(err(in, dtype_ok(in.data_type) ? RC_UNSUPPORTED_OP
                                                    : RC_AMO_UNSUPPORTED_DT));
      return res;
    }
    
    
    
    if (reduction) {
      size_t es = elem_size(in.data_type, in.reduce_op);
      if (es == 0 || payload.empty() || payload.size() % es != 0) {
        res.push_back(err(in, RC_UNSUPPORTED_SIZE));
        return res;
      }
    }
    if (in.op_type == OP_BARRIER && !payload.empty()) {
      res.push_back(err(in, RC_UNSUPPORTED_SIZE));
      return res;
    }
    if (in.op_type == OP_BCAST && rank != c.root && !payload.empty()) {
      res.push_back(err(in, RC_NO_MATCH));
      return res;
    }
    if (in.op_type == OP_SYNCBCAST && rank != c.root && !payload.empty()) {
      res.push_back(err(in, RC_NO_MATCH));
      return res;
    }
    uint32_t dist = (in.csn - c.csn) & 0xFFF;
    if (dist != 0 && dist > (uint32_t)c.max_inflight) {
      res.push_back(err(in, RC_BAD_GENERATION));   
      return res;
    }

    auto& cmap = pending_[in.cid];
    auto si = cmap.find(in.csn);
    if (si == cmap.end()) {
      if ((int)cmap.size() >= c.max_inflight ||
          buffered_bytes(c) + payload.size() > c.max_bytes) {
        defer_count_++;
        Result d;
        d.rc = RC_OK; d.deferred = true; d.cid = in.cid; d.csn = in.csn;
        res.push_back(d);
        return res;
      }
      OpState st;
      st.info = in;
      si = cmap.emplace(in.csn, st).first;
    }
    OpState& st = si->second;
    if (st.inputs.count(rank)) {            
      res.push_back(err(in, RC_BAD_GENERATION));
      return res;
    }
    if (st.inputs.empty()) st.info = in;    
    st.inputs[rank] = payload;
    c.buffered_bytes += payload.size();

    
    while (true) {
      auto hi = cmap.find(c.csn);
      if (hi == cmap.end() || !ready(c, hi->second)) break;
      Result r = complete(c, hi->second);
      if (r.rc != RC_OK) {
        
        c.buffered_bytes -= buffered_payload(hi->second);
        cmap.erase(hi);
        res.push_back(r);
        break;
      }
      c.buffered_bytes -= buffered_payload(hi->second);
      cmap.erase(hi);
      c.csn = (c.csn + 1) & 0xFFF;
      ops_completed_++;
      res.push_back(r);
    }
    if (res.empty()) {
      Result p;
      p.rc = RC_OK; p.cid = in.cid; p.csn = in.csn;
      res.push_back(p);
    }
    return res;
  }

 private:
  struct Comm {
    uint32_t cid = 0;
    std::vector<int> ranks;
    int root = 0;
    uint32_t factor = 1;
    uint32_t csn = 0;
    int max_inflight = 8;
    size_t max_bytes = 1u << 20;
    size_t buffered_bytes = 0;
  };
  struct OpState {
    Info info;
    std::map<int, std::vector<uint8_t>> inputs;
  };
  std::map<uint32_t, Comm> comms_;
  std::map<uint32_t, std::map<uint32_t, OpState>> pending_;
  bool natural_ = true;
  std::vector<int> last_order_;
  uint64_t ops_completed_ = 0, defer_count_ = 0, error_count_ = 0;
  uint64_t bytes_reduced_ = 0;

  static bool is_member(const Comm& c, int r) {
    return std::find(c.ranks.begin(), c.ranks.end(), r) != c.ranks.end();
  }
  static size_t buffered_payload(const OpState& s) {
    size_t n = 0;
    for (const auto& kv : s.inputs) n += kv.second.size();
    return n;
  }
  size_t buffered_bytes(const Comm& c) const { return c.buffered_bytes; }
  Result err(const Info& in, uint8_t rc) {
    error_count_++;
    Result r; r.rc = rc; r.cid = in.cid; r.csn = in.csn;
    return r;
  }
  bool ready(const Comm& c, const OpState& s) const {
    switch (s.info.op_type) {
      case OP_BCAST:
        return s.inputs.count(c.root) != 0;
      case OP_BARRIER:
      case OP_ALLREDUCE:
      case OP_REDUCE:
      case OP_EXSCAN:
      case OP_SYNCBCAST:
        if ((int)s.inputs.size() < (int)c.ranks.size()) return false;
        for (int r : c.ranks) if (!s.inputs.count(r)) return false;
        return true;
      default:
        return false;
    }
  }
  
  static uint32_t get32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
  }
  static void put32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
  }
  static uint16_t get16(const uint8_t* p) {
    return (uint16_t)(p[0] | (p[1] << 8));
  }
  static void put16(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
  }
  static int32_t load_i32(const std::vector<uint8_t>& p) {
    return (int32_t)get32(p.data());
  }
  static uint32_t load_u32(const std::vector<uint8_t>& p) {
    return get32(p.data());
  }
  static float load_float(const std::vector<uint8_t>& p, uint8_t dt) {
    uint16_t h = get16(p.data());
    return dt == DT_BF16 ? bf16_to_float(h) : half_to_float(h);
  }
  static std::vector<uint8_t> store_i32(int32_t v) {
    std::vector<uint8_t> p(4); put32(p.data(), (uint32_t)v); return p;
  }
  static std::vector<uint8_t> store_u32(uint32_t v) {
    std::vector<uint8_t> p(4); put32(p.data(), v); return p;
  }
  static std::vector<uint8_t> store_float(float v, uint8_t dt) {
    std::vector<uint8_t> p(2);
    put16(p.data(), dt == DT_BF16 ? float_to_bf16(v) : float_to_half(v));
    return p;
  }

  
  
  static bool apply_int32(uint8_t op, int32_t x, int32_t& acc) {
    switch (op) {
      case R_MIN: acc = std::min(acc, x); return true;
      case R_MAX: acc = std::max(acc, x); return true;
      case R_SUM:
      case R_SUM_SCALE: acc = (int32_t)((uint32_t)acc + (uint32_t)x); return true;
      case R_PROD: acc = (int32_t)((uint32_t)acc * (uint32_t)x); return true;
      case R_LOR: acc = (acc != 0 || x != 0) ? 1 : 0; return true;
      case R_LAND: acc = (acc != 0 && x != 0) ? 1 : 0; return true;
      case R_BOR: acc = (int32_t)((uint32_t)acc | (uint32_t)x); return true;
      case R_BAND: acc = (int32_t)((uint32_t)acc & (uint32_t)x); return true;
      case R_LXOR: acc = ((acc != 0) != (x != 0)) ? 1 : 0; return true;
      case R_BXOR: acc = (int32_t)((uint32_t)acc ^ (uint32_t)x); return true;
      default: return false;
    }
  }
  static bool apply_uint32(uint8_t op, uint32_t x, uint32_t& acc) {
    switch (op) {
      case R_MIN: acc = std::min(acc, x); return true;
      case R_MAX: acc = std::max(acc, x); return true;
      case R_SUM:
      case R_SUM_SCALE: acc = acc + x; return true;
      case R_PROD: acc = acc * x; return true;
      case R_LOR: acc = (acc != 0 || x != 0) ? 1 : 0; return true;
      case R_LAND: acc = (acc != 0 && x != 0) ? 1 : 0; return true;
      case R_BOR: acc |= x; return true;
      case R_BAND: acc &= x; return true;
      case R_LXOR: acc = ((acc != 0) != (x != 0)) ? 1 : 0; return true;
      case R_BXOR: acc ^= x; return true;
      default: return false;
    }
  }
  static bool apply_float(uint8_t op, float x, float& acc) {
    switch (op) {
      case R_MIN: if (x < acc) acc = x; return true;
      case R_MAX: if (x > acc) acc = x; return true;
      case R_SUM: acc += x; return true;
      default: return false;
    }
  }
  static std::vector<uint8_t> identity(uint8_t dt, uint8_t op) {
    if (op == R_MINLOC || op == R_MAXLOC) {
      std::vector<uint8_t> p(8, 0);
      std::vector<uint8_t> v;
      if (dt == DT_INT32) {
        int32_t x = (op == R_MINLOC) ? INT32_MAX : INT32_MIN;
        v = store_i32(x);
      } else if (dt == DT_UINT32) {
        uint32_t x = (op == R_MINLOC) ? UINT32_MAX : 0;
        v = store_u32(x);
      } else {
        float x = (op == R_MINLOC) ? INFINITY : -INFINITY;
        v = store_float(x, dt);
      }
      std::copy(v.begin(), v.end(), p.begin());
      put32(p.data() + 4, 0xFFFFFFFFu);       
      return p;
    }
    if (dt == DT_INT32) {
      int32_t v = 0;
      if (op == R_MIN) v = INT32_MAX;
      else if (op == R_MAX) v = INT32_MIN;
      else if (op == R_PROD || op == R_LAND) v = 1;
      else if (op == R_BAND) v = -1;
      return store_i32(v);
    }
    if (dt == DT_UINT32) {
      uint32_t v = 0;
      if (op == R_MIN) v = UINT32_MAX;
      else if (op == R_PROD || op == R_LAND) v = 1;
      else if (op == R_BAND) v = 0xFFFFFFFFu;
      return store_u32(v);
    }
    float v = 0.0f;
    if (op == R_MIN) v = INFINITY;
    else if (op == R_MAX) v = -INFINITY;
    return store_float(v, dt);
  }
  std::vector<int> order_for(const Comm& c) const {
    std::vector<int> o = c.ranks;
    std::sort(o.begin(), o.end());
    if (!natural_) std::reverse(o.begin(), o.end());
    return o;
  }

  Result complete(Comm& c, const OpState& s) {
    Result r;
    r.rc = RC_OK; r.complete = true; r.cid = c.cid; r.csn = s.info.csn;
    std::vector<int> order = order_for(c);
    last_order_ = order;
    bytes_reduced_ += buffered_payload(s);

    const uint8_t op = s.info.op_type;
    if (op == OP_BARRIER) {
      r.acks = c.ranks;
      return r;
    }
    if (op == OP_BCAST || op == OP_SYNCBCAST) {
      auto ri = s.inputs.find(c.root);
      if (ri == s.inputs.end()) { return err(s.info, RC_NO_MATCH); }
      const std::vector<uint8_t>& data = ri->second;
      for (int rank : c.ranks) {
        if (rank != c.root) r.outputs[rank] = data;
      }
      if (s.info.fo) r.outputs[c.root] = data;
      else r.acks.push_back(c.root);
      return r;
    }

    const uint8_t dt = s.info.data_type;
    const uint8_t rop = s.info.reduce_op;
    if ((int)order.size() != (int)s.inputs.size()) {
      return err(s.info, RC_NO_MATCH);
    }
    size_t sz = s.inputs.at(order[0]).size();
    for (int rank : order)
      if (s.inputs.at(rank).size() != sz)
        return err(s.info, RC_UNSUPPORTED_SIZE);   
    if (op == OP_EXSCAN) {
      std::vector<uint8_t> acc = identity(dt, rop);
      if (acc.size() != sz) {
        
        std::vector<uint8_t> expanded(sz);
        for (size_t off = 0; off < sz; off += acc.size())
          std::copy(acc.begin(), acc.end(), expanded.begin() + off);
        acc.swap(expanded);
      }
      for (int rank : order) {
        r.outputs[rank] = acc;               
        if (!step(dt, rop, acc, s.inputs.at(rank), c.factor))
          return err(s.info, RC_UNSUPPORTED_OP);
      }
      return r;
    }
    std::vector<uint8_t> acc = s.inputs.at(order[0]);
    for (size_t i = 1; i < order.size(); i++) {
      if (!step(dt, rop, acc, s.inputs.at(order[i]), c.factor))
        return err(s.info, RC_UNSUPPORTED_OP);
    }
    if (rop == R_SUM_SCALE) acc = scale(dt, acc, c.factor);
    if (op == OP_REDUCE) {
      r.outputs[c.root] = acc;
      for (int rank : c.ranks) if (rank != c.root) r.acks.push_back(rank);
    } else {                                
      for (int rank : c.ranks) r.outputs[rank] = acc;
    }
    return r;
  }

  static bool value_less(uint8_t dt, const uint8_t* a, const uint8_t* b) {
    if (dt == DT_INT32) {
      int32_t x, y;
      std::memcpy(&x, a, 4); std::memcpy(&y, b, 4);
      return x < y;
    }
    if (dt == DT_UINT32) {
      uint32_t x, y;
      std::memcpy(&x, a, 4); std::memcpy(&y, b, 4);
      return x < y;
    }
    uint16_t ha, hb;
    std::memcpy(&ha, a, 2); std::memcpy(&hb, b, 2);
    float x = dt == DT_BF16 ? bf16_to_float(ha) : half_to_float(ha);
    float y = dt == DT_BF16 ? bf16_to_float(hb) : half_to_float(hb);
    return x < y;
  }
  static bool value_equal(uint8_t dt, const uint8_t* a, const uint8_t* b) {
    if (dt == DT_INT32 || dt == DT_UINT32) return std::memcmp(a, b, 4) == 0;
    uint16_t ha, hb;
    std::memcpy(&ha, a, 2); std::memcpy(&hb, b, 2);
    float x = dt == DT_BF16 ? bf16_to_float(ha) : half_to_float(ha);
    float y = dt == DT_BF16 ? bf16_to_float(hb) : half_to_float(hb);
    return x == y;
  }
  static bool step_loc(uint8_t dt, uint8_t rop, std::vector<uint8_t>& acc,
                       const std::vector<uint8_t>& x, size_t off) {
    const uint8_t* av = acc.data() + off;
    const uint8_t* xv = x.data() + off;
    uint32_t al = get32(av + 4), xl = get32(xv + 4);
    bool take = false;
    if (rop == R_MINLOC) {
      if (value_less(dt, xv, av)) take = true;
      else if (value_equal(dt, xv, av) && xl < al) take = true;
    } else {
      if (value_less(dt, av, xv)) take = true;
      else if (value_equal(dt, xv, av) && xl < al) take = true;
    }
    if (take) std::copy(x.begin() + off, x.begin() + off + 8, acc.begin() + off);
    return true;
  }
  static bool step(uint8_t dt, uint8_t rop, std::vector<uint8_t>& acc,
                   const std::vector<uint8_t>& x, uint32_t factor) {
    (void)factor;
    size_t es = elem_size(dt, rop);
    if (es == 0 || acc.size() != x.size() || acc.empty() || acc.size() % es)
      return false;
    for (size_t off = 0; off < acc.size(); off += es) {
      if (rop == R_MINLOC || rop == R_MAXLOC) {
        if (!step_loc(dt, rop, acc, x, off)) return false;
        continue;
      }
      std::vector<uint8_t> a(acc.begin() + off, acc.begin() + off + es);
      std::vector<uint8_t> v(x.begin() + off, x.begin() + off + es);
      bool ok;
      if (dt == DT_INT32) {
        int32_t aa = load_i32(a), vv = load_i32(v);
        ok = apply_int32(rop, vv, aa);
        a = store_i32(aa);
      } else if (dt == DT_UINT32) {
        uint32_t aa = load_u32(a), vv = load_u32(v);
        ok = apply_uint32(rop, vv, aa);
        a = store_u32(aa);
      } else {
        float aa = load_float(a, dt), vv = load_float(v, dt);
        ok = apply_float(rop, vv, aa);
        a = store_float(aa, dt);
      }
      if (!ok) return false;
      std::copy(a.begin(), a.begin() + es, acc.begin() + off);
    }
    return true;
  }
  static std::vector<uint8_t> scale(uint8_t dt, const std::vector<uint8_t>& acc,
                                    uint32_t factor) {
    if (factor == 0) factor = 1;
    size_t es = elem_size(dt, R_SUM);
    std::vector<uint8_t> out = acc;
    for (size_t off = 0; off + es <= out.size(); off += es) {
      std::vector<uint8_t> a(out.begin() + off, out.begin() + off + es);
      if (dt == DT_INT32) {
        a = store_i32((int32_t)((int64_t)load_i32(a) / (int64_t)factor));
      } else if (dt == DT_UINT32) {
        a = store_u32((uint32_t)((uint64_t)load_u32(a) / factor));
      } else {
        a = store_float(load_float(a, dt) / (float)factor, dt);
      }
      std::copy(a.begin(), a.begin() + es, out.begin() + off);
    }
    return out;
  }

};

inline const char* rc_name(uint8_t rc) {
  switch (rc) {
    case RC_OK: return "RC_OK";
    case RC_BAD_GENERATION: return "RC_BAD_GENERATION";
    case RC_NO_MATCH: return "RC_NO_MATCH";
    case RC_UNSUPPORTED_OP: return "RC_UNSUPPORTED_OP";
    case RC_UNSUPPORTED_SIZE: return "RC_UNSUPPORTED_SIZE";
    case RC_AMO_UNSUPPORTED_DT: return "RC_AMO_UNSUPPORTED_DT";
    default: return "RC_?";
  }
}

}  
