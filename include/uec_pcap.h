

#pragma once
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "uec_switch.h"

namespace uec_pcap {

inline uint32_t crc32(const uint8_t* p, size_t n) {
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < n; i++) {
    crc ^= p[i];
    for (int b = 0; b < 8; b++)
      crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1u)));
  }
  return crc ^ 0xFFFFFFFFu;
}

inline std::vector<uint8_t> wire(const UecFrame& f, bool include_fcs = true) {
  std::vector<uint8_t> v;
  v.reserve(18 + f.payload.size() + 4);
  v.insert(v.end(), f.dmac, f.dmac + 6);
  v.insert(v.end(), f.smac, f.smac + 6);
  v.push_back((uint8_t)(f.ethertype >> 8));
  v.push_back((uint8_t)(f.ethertype & 0xFF));
  v.insert(v.end(), f.payload.begin(), f.payload.end());
  if (include_fcs) {
    uint32_t c = f.fcs_valid ? f.fcs : crc32(v.data(), v.size());
    v.push_back((uint8_t)(c & 0xFF));
    v.push_back((uint8_t)((c >> 8) & 0xFF));
    v.push_back((uint8_t)((c >> 16) & 0xFF));
    v.push_back((uint8_t)((c >> 24) & 0xFF));
  }
  return v;
}

inline bool from_wire(const uint8_t* p, size_t n, UecFrame& f,
                      bool has_fcs = true) {
  if (n < (has_fcs ? 18u : 14u)) return false;
  std::memcpy(f.dmac, p, 6);
  std::memcpy(f.smac, p + 6, 6);
  f.ethertype = (uint16_t)((p[12] << 8) | p[13]);
  f.payload.assign(p + 14, p + n - (has_fcs ? 4 : 0));
  if (has_fcs) {
    f.fcs = (uint32_t)p[n - 4] | ((uint32_t)p[n - 3] << 8) |
            ((uint32_t)p[n - 2] << 16) | ((uint32_t)p[n - 1] << 24);
    f.fcs_valid = true;
  } else {
    f.fcs = 0;
    f.fcs_valid = false;
  }
  return true;
}

inline bool write_le32(FILE* fp, uint32_t v) {
  uint8_t b[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
  return std::fwrite(b, 1, 4, fp) == 4;
}
inline bool read_le32(FILE* fp, uint32_t& v) {
  uint8_t b[4];
  if (std::fread(b, 1, 4, fp) != 4) return false;
  v = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
  return true;
}

class Writer {
 public:
  bool open(const std::string& path) {
    fp_ = std::fopen(path.c_str(), "wb");
    if (!fp_) return false;
    
    
    if (!write_le32(fp_, 0xA1B2C3D4u) || !write_le32(fp_, 0x00040002u) ||
        !write_le32(fp_, 0u) || !write_le32(fp_, 0u) ||
        !write_le32(fp_, 65535u) || !write_le32(fp_, 1u)) return false;
    return true;                                  
    return true;
  }
  bool write(const UecFrame& f, uint32_t sec = 0, uint32_t usec = 0,
             bool include_fcs = true) {
    if (!fp_) return false;
    std::vector<uint8_t> w = wire(f, include_fcs);
    uint32_t n = (uint32_t)w.size();
    if (!write_le32(fp_, sec) || !write_le32(fp_, usec) ||
        !write_le32(fp_, n) || !write_le32(fp_, n)) return false;
    return std::fwrite(w.data(), 1, w.size(), fp_) == w.size();
  }
  void close() { if (fp_) { std::fclose(fp_); fp_ = nullptr; } }
  ~Writer() { close(); }
 private:
  FILE* fp_ = nullptr;
};

class Reader {
 public:
  bool open(const std::string& path, bool has_fcs = true) {
    has_fcs_ = has_fcs;
    fp_ = std::fopen(path.c_str(), "rb");
    if (!fp_) return false;
    uint32_t magic;
    if (!read_le32(fp_, magic)) return false;
    if (magic == 0xA1B2C3D4u || magic == 0xA1B23C4Du) swap_ = false;
    else if (magic == 0xD4C3B2A1u || magic == 0x4D3CB2A1u) swap_ = true;
    else return false;
    auto rd = [&](uint32_t& v) { return read32(v); };
    uint32_t ver, tz, sig, snap, link;
    if (!rd(ver) || !rd(tz) || !rd(sig) || !rd(snap) || !rd(link))
      return false;
    
    if (ver != 0x00040002u && ver != 0x00020004u) return false;
    linktype_ = link;
    return linktype_ == 1;                   
  }
  bool next(UecFrame& f, uint32_t& sec, uint32_t& usec) {
    if (!fp_) return false;
    uint32_t n, orig;
    if (!read32(sec) || !read32(usec) || !read32(n) || !read32(orig)) return false;
    if (n == 0 || n > 65535) return false;
    std::vector<uint8_t> buf(n);
    if (std::fread(buf.data(), 1, n, fp_) != n) return false;
    return from_wire(buf.data(), buf.size(), f, has_fcs_);
  }
  void close() { if (fp_) { std::fclose(fp_); fp_ = nullptr; } }
  ~Reader() { close(); }
  uint32_t linktype() const { return linktype_; }
 private:
  bool read32(uint32_t& v) {
    if (!swap_) return read_le32(fp_, v);
    uint8_t b[4];
    if (std::fread(b, 1, 4, fp_) != 4) return false;
    v = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
        ((uint32_t)b[2] << 8) | (uint32_t)b[3];
    return true;
  }
  FILE* fp_ = nullptr;
  uint32_t linktype_ = 0;
  bool swap_ = false;
  bool has_fcs_ = true;
};

}  
