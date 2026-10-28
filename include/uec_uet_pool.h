

#pragma once

#include <cstdint>
#include <vector>

namespace uec_uet {

struct PoolStats {
  uint32_t total = 0;        
  uint32_t free = 0;
  uint32_t allocated = 0;    
  uint32_t delivered = 0;    
  uint64_t alloc_fail = 0;   
  uint64_t release_calls = 0;
  uint64_t double_release = 0;
};

class BufferPools {
 public:
  struct Pool {
    uint32_t id = 0;
    uint64_t base = 0;
    uint32_t buf_size = 0;
    uint32_t count = 0;
    
    
    std::vector<uint8_t> state;
    uint64_t alloc_fail = 0;
    uint64_t release_calls = 0;
    uint64_t double_release = 0;
  };

  bool add(uint32_t id, uint64_t base, uint32_t buf_size, uint32_t count) {
    if (buf_size == 0 || count == 0) return false;
    if (get(id) != nullptr) return false;
    Pool p;
    p.id = id;
    p.base = base;
    p.buf_size = buf_size;
    p.count = count;
    p.state.assign(count, 0);
    pools_.push_back(std::move(p));
    return true;
  }

  const Pool* get(uint32_t id) const {
    for (const Pool& p : pools_)
      if (p.id == id) return &p;
    return nullptr;
  }

  Pool* get(uint32_t id) {
    for (Pool& p : pools_)
      if (p.id == id) return &p;
    return nullptr;
  }

  bool has(uint32_t id) const { return get(id) != nullptr; }

  
  int alloc(uint32_t id) {
    Pool* p = get(id);
    if (p == nullptr) return -1;
    for (uint32_t i = 0; i < p->count; i++) {
      if (p->state[i] == 0) {
        p->state[i] = 1;
        return (int)i;
      }
    }
#ifdef UET_POOL_RED_OVERALLOC
    
    p->state[p->count - 1] = 1;
    return (int)p->count - 1;
#else
    p->alloc_fail++;
    return -1;
#endif
  }

  bool mark_delivered(uint32_t id, uint32_t idx) {
    Pool* p = get(id);
    if (p == nullptr || idx >= p->count) return false;
    if (p->state[idx] == 0) return false;
    p->state[idx] = 2;
    return true;
  }

  bool release(uint32_t id, uint32_t idx) {
    Pool* p = get(id);
    if (p == nullptr || idx >= p->count) return false;
    if (p->state[idx] == 0) {
      p->double_release++;
      return false;
    }
    p->state[idx] = 0;
    p->release_calls++;
    return true;
  }

  void release_all(uint32_t id) {
    Pool* p = get(id);
    if (p == nullptr) return;
    for (uint8_t& s : p->state) {
      if (s != 0) {
        s = 0;
        p->release_calls++;
      }
    }
  }

  
  void reset_state() {
    for (Pool& p : pools_) p.state.assign(p.count, 0);
  }

  PoolStats stats(uint32_t id) const {
    PoolStats s;
    const Pool* p = get(id);
    if (p == nullptr) return s;
    s.total = p->count;
    s.alloc_fail = p->alloc_fail;
    s.release_calls = p->release_calls;
    s.double_release = p->double_release;
    for (uint8_t st : p->state) {
      if (st == 0) s.free++;
      else if (st == 1) s.allocated++;
      else s.delivered++;
    }
    return s;
  }

  void note_alloc_fail(uint32_t id) {
    Pool* p = get(id);
    if (p != nullptr) p->alloc_fail++;
  }

 private:
  std::vector<Pool> pools_;
};

inline bool pool_range_ok(const BufferPools::Pool& p, uint64_t off,
                          uint32_t len) {
#ifdef UET_POOL_RED_BOUNDS
  (void)p; (void)off; (void)len;
  return true;   
#else
  const uint64_t span = (uint64_t)p.buf_size * p.count;
  if (off < p.base) return false;
  const uint64_t rel = off - p.base;
  if (rel > span) return false;
  if (len == 0) return rel < span || span == 0;
  if (rel + len > span) return false;
  const uint64_t within = rel % p.buf_size;
  return within + len <= p.buf_size;
#endif
}

}  
