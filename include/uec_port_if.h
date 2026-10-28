

#pragma once
#include <cstddef>
#include <cstdint>
#include <deque>
#include <vector>

namespace uec_port {

struct PortBeat {
  uint8_t data = 0;
  bool    sof = false;
  bool    eof = false;
};

class PortSink {
 public:
  virtual ~PortSink() {}
  virtual bool ready() const = 0;                 
  virtual void push(const PortBeat& b) = 0;       
};

class PortSource {
 public:
  virtual ~PortSource() {}
  virtual bool pop(PortBeat& b) = 0;              
};

class PortBeatQueue : public PortSink, public PortSource {
 public:
  explicit PortBeatQueue(size_t depth = 16) : depth_(depth) {}

  bool ready() const override { return q_.size() < depth_; }
  void push(const PortBeat& b) override {
    if (q_.size() < depth_) q_.push_back(b);
    else drops_++;                                
  }
  bool pop(PortBeat& b) override {
    if (q_.empty()) return false;
    b = q_.front();
    q_.pop_front();
    return true;
  }

  size_t   size() const { return q_.size(); }
  uint64_t drops() const { return drops_; }
  void     clear() { q_.clear(); }

 private:
  size_t depth_;
  std::deque<PortBeat> q_;
  uint64_t drops_ = 0;
};

inline bool send_frame(PortSink& s, const std::vector<uint8_t>& frame,
                       int max_spins = 1000000) {
  if (frame.empty()) return false;
  for (size_t i = 0; i < frame.size(); i++) {
    PortBeat b;
    b.data = frame[i];
    b.sof = (i == 0);
#ifdef UET_PORT_RED_EOF
    b.eof = false;                    
#else
    b.eof = (i + 1 == frame.size());
#endif
    int spins = 0;
    while (!s.ready()) {
      if (++spins > max_spins) return false;
    }
    s.push(b);
  }
  return true;
}

inline bool recv_frame(PortSource& s, std::vector<uint8_t>& out,
                       size_t max_bytes = 65536) {
  out.clear();
  PortBeat b;
  while (out.size() < max_bytes) {
    if (!s.pop(b)) return false;
    if (b.sof) out.clear();          
    out.push_back(b.data);
    if (b.eof) return true;
  }
  return false;
}

}  
