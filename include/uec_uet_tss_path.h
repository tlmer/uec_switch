

#pragma once

#include <cstdint>
#include <vector>

namespace uec_uet {

struct TssPathConfig {
  uint32_t sdi = 0;
  uint32_t ssi = 0;
  bool use_ssi = true;
  int kdf_mode = 0;              
  uint8_t key[32] = {0};         
};

struct TssPathStats {
  uint64_t sealed = 0;
  uint64_t opened = 0;
  uint64_t auth_fail = 0;
  uint64_t replay = 0;
};

enum class TssOpenResult {
  NotTss,    
  Ok,        
  AuthFail,  
  Replay,    
};

class TssPathIf {
 public:
  virtual ~TssPathIf() {}
  
  
  virtual bool seal_frame(const std::vector<uint8_t>& clear_frame,
                          std::vector<uint8_t>& secure_frame) = 0;
  
  
  virtual TssOpenResult open_frame(const std::vector<uint8_t>& frame,
                                   std::vector<uint8_t>& clear_frame) = 0;
  virtual const TssPathStats& stats() const = 0;
};

using TssPathFactory = TssPathIf* (*)(const TssPathConfig&);

inline TssPathFactory& tss_path_factory() {
  static TssPathFactory factory = nullptr;
  return factory;
}

inline TssPathIf* tss_path_create(const TssPathConfig& cfg) {
  return tss_path_factory() ? tss_path_factory()(cfg) : nullptr;
}

void uet_tss_path_register();

}  
