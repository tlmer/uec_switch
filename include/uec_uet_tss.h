

#pragma once

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

namespace uec_uet {

struct TssStats {
  uint64_t sealed = 0;
  uint64_t opened = 0;
  uint64_t auth_fail = 0;
  uint64_t replay = 0;
  uint64_t unknown_sd = 0;
  uint64_t rotated = 0;
  uint64_t prev_ok = 0;
};

class TssEngine {
 public:
  static constexpr int kTagLen = 16;
  static constexpr int kIvLen = 12;
  static constexpr int kAadLen = 12;
  static constexpr int kMaxSd = 8;

  struct Sd {
    bool     valid = false;
    uint32_t sdi = 0;
    bool     use_ssi = false;
    uint32_t ssi = 0;
    uint8_t  key[32] = {0};
    uint8_t  prev[32] = {0};
    bool     has_prev = false;
    bool     tsc_init = false;
    uint64_t tsc_max = 0;
    uint64_t win = 0;        
  };

  
  
  
  
  enum KdfMode { kDirect = 0, kCluster = 1, kServer = 2 };

  static void hmac256_(const uint8_t* key, size_t klen, const uint8_t* data,
                       size_t dlen, uint8_t out[32]) {
    unsigned int olen = 32;
    HMAC(EVP_sha256(), key, (int)klen, data, dlen, out, &olen);
  }

  static void derive_sd_key(const uint8_t master[32], KdfMode m, uint32_t sdi,
                            uint32_t ssi, uint8_t out[32]) {
    static const char salt[] = "UEC-TSS-KDF";
    uint8_t prk[32];
    hmac256_((const uint8_t*)salt, sizeof(salt) - 1, master, 32, prk);
    uint8_t info[16];
    size_t n = 0;
    info[n++] = (m == kServer) ? 0x53 : 0x43;   
#ifndef UET_TSS_RED_KDF
    info[n++] = (uint8_t)(sdi >> 24); info[n++] = (uint8_t)(sdi >> 16);
    info[n++] = (uint8_t)(sdi >> 8);  info[n++] = (uint8_t)sdi;
    info[n++] = (uint8_t)(ssi >> 24); info[n++] = (uint8_t)(ssi >> 16);
    info[n++] = (uint8_t)(ssi >> 8);  info[n++] = (uint8_t)ssi;
#endif
    info[n++] = 0x01;
    hmac256_(prk, 32, info, n, out);
  }

  bool set_master_key(KdfMode m, const uint8_t key[32]) {
    if (m == kDirect) return false;
    kdf_mode_ = m;
    std::memcpy(master_, key, 32);
    have_master_ = true;
    return true;
  }

  bool add_sd_kdf(uint32_t sdi, uint32_t ssi, bool use_ssi) {
    if (!have_master_) return false;
    uint8_t k[32];
    derive_sd_key(master_, (KdfMode)kdf_mode_, sdi, ssi, k);
    return add_sd(sdi, ssi, use_ssi, k);
  }

  bool add_sd(uint32_t sdi, uint32_t ssi, bool use_ssi, const uint8_t key[32]) {
    for (Sd& s : sds_) {
      if (s.valid && s.sdi == sdi) return false;
    }
    for (Sd& s : sds_) {
      if (s.valid) continue;
      s = Sd{};
      s.valid = true;
      s.sdi = sdi;
      s.ssi = ssi;
      s.use_ssi = use_ssi;
      std::memcpy(s.key, key, 32);
      return true;
    }
    return false;
  }

  bool rotate_sd(uint32_t sdi, const uint8_t new_key[32]) {
    Sd* s = find(sdi);
    if (s == nullptr) return false;
    std::memcpy(s->prev, s->key, 32);
    s->has_prev = true;
    std::memcpy(s->key, new_key, 32);
    st_.rotated++;
    return true;
  }

  const TssStats& stats() const { return st_; }

  
  bool seal(uint32_t sdi, uint64_t tsc, const uint8_t aad[kAadLen],
            const std::vector<uint8_t>& clear, std::vector<uint8_t>& out) {
    Sd* s = find(sdi);
    if (s == nullptr) return false;
    const size_t hlen = s->use_ssi ? 16u : 12u;
    out.assign(hlen + clear.size() + kTagLen, 0);
    const uint32_t tf = (1u << 27) | (s->use_ssi ? (1u << 26) : 0u) |
                        (sdi & 0xFFFFFFu);
    put_be32(&out[0], tf);
    size_t p = 4;
    if (s->use_ssi) {
      put_be32(&out[p], s->ssi);
      p += 4;
    }
    put_be64(&out[p], tsc & 0xFFFFFFFFFFFFULL);   
    p += 8;
    uint8_t iv[kIvLen];
    make_iv(s, tsc, iv);
    if (!gcm_seal(s->key, iv, aad, clear, &out[p], &out[p + clear.size()]))
      return false;
    st_.sealed++;
    return true;
  }

  
  
  bool open(const std::vector<uint8_t>& secure, const uint8_t aad[kAadLen],
            std::vector<uint8_t>& clear) {
    if (secure.size() < 12u + kTagLen) return false;
    const uint32_t tf = get_be32(&secure[0]);
    const bool sp = (tf & (1u << 26)) != 0;
    const uint32_t sdi = tf & 0xFFFFFFu;
    Sd* s = find(sdi);
    if (s == nullptr) {
      st_.unknown_sd++;
      return false;
    }
    const size_t hlen = sp ? 16u : 12u;
    if (secure.size() < hlen + kTagLen) return false;
    const uint64_t tsc = get_be64(&secure[hlen - 8]) & 0xFFFFFFFFFFFFULL;
    const size_t clen = secure.size() - hlen - kTagLen;

    uint8_t iv[kIvLen];
    make_iv(s, tsc, iv);
    const uint8_t* ct = &secure[hlen];
    const uint8_t* tag = &secure[hlen + clen];
    clear.assign(clen, 0);
    bool ok = false;
#ifndef UET_TSS_RED_NOTAG
    ok = gcm_open(s->key, iv, aad, ct, clen, tag, clear.data());
    if (!ok && s->has_prev) {
      ok = gcm_open(s->prev, iv, aad, ct, clen, tag, clear.data());
      if (ok) st_.prev_ok++;
    }
#else
    ok = gcm_open(s->key, iv, aad, ct, clen, tag, clear.data(), true);
    if (!ok && s->has_prev)
      ok = gcm_open(s->prev, iv, aad, ct, clen, tag, clear.data(), true);
#endif
    if (!ok) {
      st_.auth_fail++;
      clear.clear();
      return false;
    }
    
#ifndef UET_TSS_RED_REPLAY
    if (!tsc_accept(s, tsc)) {
      st_.replay++;
      clear.clear();
      return false;
    }
#endif
    st_.opened++;
    return true;
  }

 private:
  uint8_t master_[32] = {0};
  int     kdf_mode_ = kDirect;
  bool    have_master_ = false;

  Sd* find(uint32_t sdi) {
    for (Sd& s : sds_)
      if (s.valid && s.sdi == sdi) return &s;
    return nullptr;
  }

  static void put_be32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
  }
  static uint32_t get_be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
  }
  static void put_be64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * (7 - i)));
  }
  static uint64_t get_be64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
  }

  static void make_iv(const Sd* s, uint64_t tsc, uint8_t iv[kIvLen]) {
    put_be32(iv, s->use_ssi ? s->ssi : s->sdi);
    put_be64(iv + 4, tsc);
  }

  
  
  static bool tsc_accept(Sd* s, uint64_t tsc) {
    if (!s->tsc_init) {
      s->tsc_init = true;
      s->tsc_max = tsc;
      s->win = 1;
      return true;
    }
    if (tsc > s->tsc_max) {
      const uint64_t d = tsc - s->tsc_max;
      s->win = (d >= 64) ? 0 : (s->win << d);
      s->win |= 1;
      s->tsc_max = tsc;
      return true;
    }
    const uint64_t d = s->tsc_max - tsc;
    if (d >= 64) return false;
    const uint64_t bit = 1ULL << d;
    if (s->win & bit) return false;
    s->win |= bit;
    return true;
  }

  static bool gcm_seal(const uint8_t key[32], const uint8_t iv[kIvLen],
                       const uint8_t aad[kAadLen],
                       const std::vector<uint8_t>& clear, uint8_t* ct,
                       uint8_t* tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return false;
    int len = 0, outl = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                                 nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kIvLen,
                                  nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) == 1 &&
              EVP_EncryptUpdate(ctx, nullptr, &len, aad, kAadLen) == 1 &&
              EVP_EncryptUpdate(ctx, ct, &outl, clear.data(),
                                (int)clear.size()) == 1 &&
              EVP_EncryptFinal_ex(ctx, ct + outl, &len) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen,
                                  tag) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
  }

  static bool gcm_open(const uint8_t key[32], const uint8_t iv[kIvLen],
                       const uint8_t aad[kAadLen], const uint8_t* ct,
                       size_t clen, const uint8_t* tag, uint8_t* clear,
                       bool skip_tag = false) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return false;
    int len = 0, outl = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                                 nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kIvLen,
                                  nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) == 1 &&
              EVP_DecryptUpdate(ctx, nullptr, &len, aad, kAadLen) == 1 &&
              EVP_DecryptUpdate(ctx, clear, &outl, ct, (int)clen) == 1;
    if (ok && !skip_tag) {
      ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagLen,
                               (void*)tag) == 1 &&
           EVP_DecryptFinal_ex(ctx, clear + outl, &len) == 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
  }

  std::array<Sd, kMaxSd> sds_{};
  TssStats st_{};
};

}  
