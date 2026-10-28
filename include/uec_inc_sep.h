

#pragma once
#include "uec_inc.h"
#include <cstdint>
#include <map>
#include <vector>

namespace uec_inc {

inline uint32_t crc32_bytes(const std::vector<uint8_t>& data) {
  uint32_t crc = 0xFFFFFFFFu;
  for (uint8_t b : data) {
    crc ^= b;
    for (int i = 0; i < 8; i++)
      crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1u)));
  }
  return crc ^ 0xFFFFFFFFu;
}

struct Request {
  uint32_t psn = 0;
  uint32_t crc = 0;
  Info info;
  int rank = -1;
  std::vector<uint8_t> payload;
};

struct Response {
  uint32_t psn = 0;
  uint32_t crc = 0;
  int rank = -1;
  bool empty = false;                 
  std::vector<uint8_t> payload;
};

class Sep {
 public:
  explicit Sep(Engine& eng) : eng_(eng) {}

  Request make_request(uint32_t psn, int rank, const Info& info,
                       const std::vector<uint8_t>& payload) {
    Request r;
    r.psn = psn; r.rank = rank; r.info = info; r.payload = payload;
    r.crc = request_crc(r);
    return r;
  }
  uint32_t request_crc(const Request& r) const {
    std::vector<uint8_t> b;
    append_header(b, r.psn, r.info, r.rank);
    b.insert(b.end(), r.payload.begin(), r.payload.end());
    return crc32_bytes(b);
  }
  uint32_t response_crc(const Response& r) const {
    std::vector<uint8_t> b;
    append_header(b, r.psn, Info(), r.rank);  
    b.push_back(r.empty ? 1 : 0);
    b.insert(b.end(), r.payload.begin(), r.payload.end());
    return crc32_bytes(b);
  }

  std::vector<Response> rx(const Request& r) {
    requests_++;
    if (r.crc != request_crc(r)) { crc_errors_++; return {}; }
    auto ci = cache_.find(r.psn);
    if (ci != cache_.end()) {
      dup_hits_++;
      return ci->second;
    }
    if (r.psn != expected_psn_) { psn_gaps_++; expected_psn_ = r.psn; }
    expected_psn_ = r.psn + 1;

    std::vector<Result> rs = eng_.submit(r.rank, r.info, r.payload);
    std::vector<Response> out;
    for (const Result& res : rs) {
      for (const auto& kv : res.outputs) {
        Response p;
        p.psn = r.psn; p.rank = kv.first; p.empty = false; p.payload = kv.second;
        p.crc = response_crc(p);
        out.push_back(p);
      }
      for (int a : res.acks) {
        Response p;
        p.psn = r.psn; p.rank = a; p.empty = true;
        p.crc = response_crc(p);
        out.push_back(p);
      }
    }
    cache_[r.psn] = out;
    if (drop_next_) {
      drop_next_ = false;
      dropped_ += out.size();
      return {};
    }
    responses_ += out.size();
    return out;
  }

  void set_drop_next(bool en = true) { drop_next_ = en; }
  bool has_cache(uint32_t psn) const { return cache_.count(psn) != 0; }
  std::vector<Response> retransmit(uint32_t psn) {
    auto it = cache_.find(psn);
    if (it == cache_.end()) return {};
    retransmits_++;
    return it->second;
  }

  uint64_t crc_errors() const { return crc_errors_; }
  uint64_t dup_hits() const { return dup_hits_; }
  uint64_t dropped() const { return dropped_; }
  uint64_t retransmits() const { return retransmits_; }
  uint64_t psn_gaps() const { return psn_gaps_; }
  uint64_t requests() const { return requests_; }
  uint64_t responses() const { return responses_; }

 private:
  Engine& eng_;
  std::map<uint32_t, std::vector<Response>> cache_;
  uint32_t expected_psn_ = 0;
  bool drop_next_ = false;
  uint64_t crc_errors_ = 0, dup_hits_ = 0, dropped_ = 0, retransmits_ = 0;
  uint64_t psn_gaps_ = 0, requests_ = 0, responses_ = 0;

  static void append_header(std::vector<uint8_t>& b, uint32_t psn,
                            const Info& info, int rank) {
    b.push_back((uint8_t)psn); b.push_back((uint8_t)(psn >> 8));
    b.push_back((uint8_t)(psn >> 16)); b.push_back((uint8_t)(psn >> 24));
    uint64_t v = info.encode();
    for (int i = 7; i >= 0; i--) b.push_back((uint8_t)(v >> (i * 8)));
    b.push_back((uint8_t)rank);
  }
};

}  
