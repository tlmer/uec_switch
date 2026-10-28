

#pragma once
#include "uec_uet_pkt.h"
#include "uec_uet_pool.h"

#include <array>
#include <cstdint>

namespace uec_uet {

struct MrEntry {
  bool     valid = false;
  uint64_t mkey = 0;
  uint32_t job_id = 0;      
  uint16_t pid = 0;         
  uint16_t ri = 0;          
  uint64_t base = 0;
  uint32_t length = 0;
  bool     local_read = false;
  bool     local_write = false;
  bool     remote_read = false;
  bool     remote_write = false;
  uint64_t match_bits = 0;  
  uint64_t match_mask = 0;  
  bool     armed = true;    
  int32_t  pool_id = -1;    
};

class MrTable {
 public:
  static constexpr int kEntries = 16;

  void clear() { entries_.fill(MrEntry{}); }

  bool set(int idx, const MrEntry& e) {
    if (idx < 0 || idx >= kEntries) return false;
    entries_[idx] = e;
    entries_[idx].valid = true;
    return true;
  }

  
  
  bool set_mkey(int idx, uint64_t new_mkey) {
#ifdef UET_REC_RED_ROTATE
    (void)idx; (void)new_mkey;
    return true;                     
#else
    if (idx < 0 || idx >= kEntries || !entries_[idx].valid) return false;
    entries_[idx].mkey = new_mkey;
    return true;
#endif
  }
  void disable(int idx) {
    if (idx >= 0 && idx < kEntries) entries_[idx].valid = false;
  }
  
  bool set_armed(int idx, bool armed) {
    if (idx < 0 || idx >= kEntries || !entries_[idx].valid) return false;
    entries_[idx].armed = armed;
    return true;
  }

  void remove(int idx) {
    if (idx >= 0 && idx < kEntries) entries_[idx] = MrEntry{};
  }

  const MrEntry* get(int idx) const {
    if (idx < 0 || idx >= kEntries) return nullptr;
    return entries_[idx].valid ? &entries_[idx] : nullptr;
  }

  
  const MrEntry* find_mkey(uint64_t mkey) const {
    const MrEntry& e = entries_[mkey & (kEntries - 1)];
    return (e.valid && e.mkey == mkey) ? &e : nullptr;
  }

  
  const MrEntry* find_job(uint32_t job_id) const {
    for (const MrEntry& e : entries_)
      if (e.valid && e.job_id == job_id) return &e;
    return nullptr;
  }

  
  uint8_t authorize(uint8_t opcode, uint32_t job_id, uint16_t pid, uint16_t ri,
                    uint64_t match, uint64_t buffer_offset, uint32_t req_len,
                    uint32_t max_bytes,
                    const BufferPools* pools = nullptr) const {
#ifdef UET_MR_RED_NOAUTH
    
    (void)opcode; (void)job_id; (void)pid; (void)ri; (void)match;
    (void)buffer_offset; (void)req_len; (void)max_bytes;
    return RC_OK;
#else
    const bool is_send  = opcode == SES_SEND;
    const bool is_read  = opcode == SES_READ;
    const bool is_atomic = opcode == SES_ATOMIC || opcode == SES_FETCH_ATOMIC;
    const bool is_write = opcode == SES_WRITE || opcode == SES_SYNC_WRITE ||
                          is_atomic;   
    const bool mkey_mode = (match != 0) && !is_send;
    const MrEntry* e = mkey_mode ? find_mkey(match) : find_job(job_id);

    if (is_send) {
      if (req_len > max_bytes) return RC_TOO_LONG;
      if (!e) return RC_NO_MATCH;
#ifndef UET_MR_ARM_RED
      if (!e->armed) return RC_NO_MATCH;
#endif
#ifndef UET_MR_RED_SENDMATCH
      if (e->match_mask != 0 &&
          ((match ^ e->match_bits) & e->match_mask) != 0)
        return RC_NO_MATCH;
#endif
      if (e->pid != 0 && e->pid != pid) return RC_NO_MATCH;
      if (e->ri != 0 && e->ri != ri) return RC_NO_MATCH;
      return RC_OK;
    }

    if (req_len > max_bytes) return RC_TOO_LONG;
    if (!e) return RC_NO_MATCH;
#ifndef UET_MR_ARM_RED
    if (!e->armed) return RC_NO_MATCH;
#endif
    if (mkey_mode && e->job_id != 0 && e->job_id != job_id)
      return RC_BAD_MKEY;
    if (e->pid != 0 && e->pid != pid) return RC_BAD_MKEY;
    if (e->ri != 0 && e->ri != ri) return RC_BAD_MKEY;
    if (is_read && !e->remote_read) return RC_BAD_MKEY;
    if (is_write && !e->remote_write) return RC_BAD_MKEY;
    if (buffer_offset < e->base ||
        buffer_offset + (uint64_t)req_len > e->base + (uint64_t)e->length)
      return RC_BAD_ADDR;
    
    if (e->pool_id >= 0) {
      const BufferPools::Pool* pp =
          (pools != nullptr) ? pools->get((uint32_t)e->pool_id) : nullptr;
      if (pp == nullptr) return RC_BAD_ADDR;
      if (!pool_range_ok(*pp, buffer_offset, req_len)) return RC_BAD_ADDR;
    }
    return RC_OK;
#endif  
  }

 private:
  std::array<MrEntry, kEntries> entries_{};
};

}  
