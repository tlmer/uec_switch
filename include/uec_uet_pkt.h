

#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace uec_uet {

static constexpr uint16_t kEtherTypeIPv4 = 0x0800;
static constexpr uint8_t  kIpProtoUdp   = 17;
static constexpr uint16_t kUetUdpPort   = 4793;
static constexpr uint8_t  kIpTtl        = 64;

static constexpr size_t kEthLen = 14;
static constexpr size_t kIpLen  = 20;
static constexpr size_t kUdpLen = 8;
static constexpr size_t kPdsReqLen  = 12;
static constexpr size_t kPdsAckLen  = 12;
static constexpr size_t kPdsAckCcLen = 32;
static constexpr size_t kPdsAckCcxLen = 40;
static constexpr size_t kPdsNackLen = 16;
static constexpr size_t kPdsCtrlLen = 16;
static constexpr size_t kSesSmallLen  = 20;
static constexpr size_t kSesMediumLen = 32;
static constexpr size_t kSesStdLen  = 44;
static constexpr size_t kSesRspLen  = 12;
static constexpr size_t kCrcLen     = 4;

static constexpr uint8_t kDscpTrimmable = 10;
static constexpr uint8_t kDscpTrimmed   = 12;
static constexpr uint8_t kDscpTrimLastHop = 14;

enum PdsType : uint8_t {
  PDS_RUD_REQ = 0x02,
  PDS_ROD_REQ = 0x03,
  PDS_ACK     = 0x07,
  PDS_ACK_CC  = 0x08,
  PDS_ACK_CCX = 0x09,
  PDS_NACK    = 0x0a,
  PDS_CTRL    = 0x0b,
};

enum PdsNextHdr : uint8_t {
  NEXT_NONE           = 0x0,
  NEXT_REQ_SMALL      = 0x1,
  NEXT_REQ_MEDIUM     = 0x2,
  NEXT_REQ_STD        = 0x3,
  NEXT_RSP            = 0x4,
  NEXT_RSP_DATA       = 0x5,
  NEXT_RSP_DATA_SMALL = 0x6,
};

enum PdsCtrlType : uint8_t {
  CTRL_NOP         = 0x0,
  CTRL_ACK_REQ     = 0x1,
  CTRL_CLEAR       = 0x2,
  CTRL_CLEAR_REQ   = 0x3,
  CTRL_CLOSE       = 0x4,
  CTRL_CLOSE_REQ   = 0x5,
  CTRL_PROBE       = 0x6,
  CTRL_CREDIT      = 0x7,
  CTRL_CREDIT_REQ  = 0x8,
  CTRL_NEGOTIATION = 0x9,
};

enum PdsReqFlag : uint8_t {
  PDS_REQ_AR   = 0x08,
  PDS_REQ_SYN  = 0x04,
  PDS_REQ_RETX = 0x10,
};

enum SesOpcode : uint8_t {
  SES_NO_OP        = 0x00,
  SES_WRITE        = 0x01,
  SES_READ         = 0x02,
  SES_ATOMIC       = 0x03,
  SES_FETCH_ATOMIC = 0x04,
  SES_SEND         = 0x05,
  SES_SYNC_WRITE   = 0x10,
};

enum SesReqFlag : uint8_t {
  SES_SOM = 0x01,
  SES_EOM = 0x02,
  SES_HD  = 0x04,
  SES_REL = 0x08,
  SES_IE  = 0x10,
  SES_DC  = 0x20,
};

enum SesRspOpcode : uint8_t {
  RSP_DEFAULT   = 0x00,
  RSP_RESPONSE  = 0x01,
  RSP_WITH_DATA = 0x02,
  RSP_NO_RESP   = 0x03,
};

enum SesRc : uint8_t {
  RC_OK                = 0x01,
  RC_NO_MATCH          = 0x05,
  RC_UNSUPPORTED_OP    = 0x06,
  RC_UNSUPPORTED_SIZE  = 0x07,
  RC_BAD_MKEY          = 0x1c,
  RC_BAD_ADDR          = 0x1d,
  RC_UNDELIVERABLE     = 0x1f,   
  RC_TOO_LONG          = 0x22,
};

enum PdsNackCode : uint8_t {
  NACK_NONE            = 0x00,
  NACK_TRIMMED         = 0x01,
  NACK_TRIMMED_LAST_HOP= 0x02,
  NACK_TRIMMED_ACK     = 0x03,
  NACK_NO_PDC_AVAIL    = 0x04,
  NACK_NO_CCC_AVAIL    = 0x05,
  NACK_NO_BITMAP       = 0x06,
  NACK_NO_PKT_BUF      = 0x07,
  NACK_NO_RESOURCE     = 0x0a,
  NACK_PSN_OOR_WINDOW  = 0x0b,
  NACK_ROD_OOO         = 0x0d,
  NACK_INV_DPDCID      = 0x0e,
  NACK_CLOSING         = 0x10,
};

inline uint16_t be16(const uint8_t* p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
inline uint32_t be32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
inline uint64_t be64(const uint8_t* p) {
  uint64_t hi = be32(p), lo = be32(p + 4);
  return (hi << 32) | lo;
}
inline void put16(std::vector<uint8_t>& v, size_t off, uint16_t x) {
  v[off] = (uint8_t)(x >> 8); v[off + 1] = (uint8_t)x;
}
inline void put32(std::vector<uint8_t>& v, size_t off, uint32_t x) {
  v[off] = (uint8_t)(x >> 24); v[off + 1] = (uint8_t)(x >> 16);
  v[off + 2] = (uint8_t)(x >> 8); v[off + 3] = (uint8_t)x;
}
inline void put64(std::vector<uint8_t>& v, size_t off, uint64_t x) {
  put32(v, off, (uint32_t)(x >> 32)); put32(v, off + 4, (uint32_t)x);
}

inline uint32_t crc32c(const uint8_t* data, size_t len) {
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (int b = 0; b < 8; b++)
      crc = (crc >> 1) ^ (0x82F63B78u & (uint32_t)(-(int32_t)(crc & 1u)));
  }
  return ~crc;
}
inline void append_crc_be(std::vector<uint8_t>& v, uint32_t crc) {
  v.push_back((uint8_t)(crc >> 24)); v.push_back((uint8_t)(crc >> 16));
  v.push_back((uint8_t)(crc >> 8));  v.push_back((uint8_t)crc);
}
inline bool crc_match_be(const uint8_t* p, uint32_t crc) {
  return be32(p) == crc;
}

struct PdsReq {
  uint8_t  type = PDS_RUD_REQ;
  uint8_t  flags = PDS_REQ_AR;
  int16_t  clear_psn_offset = 0;
  uint32_t psn = 0;
  uint16_t spdcid = 0;
  uint16_t dpdcid = 0;
};

struct PdsAck {
  uint8_t  flags = 0;
  int16_t  ack_psn_offset = 0;
  uint32_t cack_psn = 0;
  uint16_t spdcid = 0;
  uint16_t dpdcid = 0;
  
  bool     cc = false;
  uint8_t  cc_type_flags = 0;
  uint8_t  mpr = 0;
  int16_t  sack_psn_offset = 0;
  uint64_t sack_bitmap = 0;
  uint64_t ack_cc_state = 0;
};

struct PdsNack {
  uint8_t  flags = 0;
  uint8_t  nack_code = NACK_NONE;
  uint8_t  vendor_code = 0;
  uint32_t psn = 0;
  uint16_t spdcid = 0;
  uint16_t dpdcid = 0;
  uint32_t payload = 0;
};

struct PdsCtrl {
  uint8_t  ctrl_type = CTRL_NOP;
  uint8_t  flags = 0;
  uint16_t probe_or_rsvd = 0;
  uint32_t psn = 0;
  uint16_t spdcid = 0;
  uint16_t dpdcid = 0;
  uint32_t payload = 0;
};

struct SesReqStd {
  uint8_t  opcode = SES_WRITE;
  uint8_t  ver = 0;
  uint8_t  flags = SES_SOM | SES_EOM;
  uint16_t msg_id = 0;
  uint8_t  ri_gen = 0;
  uint32_t job_id = 0;              
  uint16_t pid = 0;                 
  uint16_t ri = 0;                  
  uint64_t buffer_offset = 0;
  uint32_t initiator = 0;
  uint64_t match_bits = 0;
  bool     hd = false;              
  uint64_t header_data = 0;
  uint32_t payload_len = 0;         
  uint32_t msg_off = 0;
  uint32_t req_len = 0;
};

struct SesRsp {
  uint8_t  list = 0;
  uint8_t  opcode = RSP_DEFAULT;
  uint8_t  ver = 0;
  uint8_t  rc = RC_OK;
  uint16_t msg_id = 0;
  uint8_t  ri_gen = 0;
  uint32_t job_id = 0;              
  uint32_t mod_len = 0;
  
  uint16_t rd_msg_id = 0;
  uint16_t payload_len = 0;
  uint32_t msg_off = 0;
};

enum class Kind { Request, Ack, Nack, Ctrl, Response };

struct Packet {
  std::array<uint8_t, 6> dmac{{0x02, 0x00, 0x00, 0x00, 0x00, 0x0b}};
  std::array<uint8_t, 6> smac{{0x02, 0x00, 0x00, 0x00, 0x00, 0x0a}};
  uint32_t src_ip = 0x0a000001;      
  uint32_t dst_ip = 0x0a000002;      
  uint8_t  tos = 0;
  uint16_t entropy = 0x4242;         
  Kind     kind = Kind::Request;

  
  
  uint8_t  ses_next = NEXT_REQ_STD;

  PdsReq   req;
  PdsAck   ack;
  PdsNack  nack;
  PdsCtrl  ctrl;
  SesReqStd ses;
  SesRsp   rsp;
  bool     rsp_data = false;        
  std::vector<uint8_t> payload;

  
  bool crc_valid = false;
  bool ip_checksum_valid = false;
  bool trimmed = false;             
  bool trimmed_last_hop = false;

  
  static Packet make_request(uint8_t opcode, uint8_t pds_type, uint32_t psn,
                             uint16_t spdcid, uint16_t dpdcid,
                             uint32_t msg_id, uint32_t job_id,
                             uint64_t buffer_offset, uint64_t match_bits,
                             const std::vector<uint8_t>& data,
                             uint8_t req_flags = PDS_REQ_AR) {
    Packet p;
    p.kind = Kind::Request;
    p.req.type = pds_type;
    p.req.flags = req_flags;
    p.req.psn = psn;
    p.req.spdcid = spdcid;
    p.req.dpdcid = dpdcid;
    p.ses.opcode = opcode;
    p.ses.flags = SES_SOM | SES_EOM;
    p.ses.msg_id = (uint16_t)msg_id;
    p.ses.job_id = job_id & 0xFFFFFFu;
    p.ses.buffer_offset = buffer_offset;
    p.ses.match_bits = match_bits;
    p.ses.req_len = (uint32_t)data.size();
    p.ses.payload_len = (uint32_t)data.size();
    p.payload = data;
    return p;
  }

  static Packet make_write(uint32_t psn, uint16_t spdcid, uint16_t dpdcid,
                           uint32_t msg_id, uint32_t job_id,
                           uint64_t buffer_offset, uint64_t mkey,
                           const std::vector<uint8_t>& data) {
    return make_request(SES_WRITE, PDS_RUD_REQ, psn, spdcid, dpdcid,
                        msg_id, job_id, buffer_offset, mkey, data);
  }

  static Packet make_read(uint32_t psn, uint16_t spdcid, uint16_t dpdcid,
                          uint32_t msg_id, uint32_t job_id,
                          uint64_t buffer_offset, uint64_t mkey,
                          uint32_t len) {
    std::vector<uint8_t> none;
    Packet p = make_request(SES_READ, PDS_RUD_REQ, psn, spdcid, dpdcid,
                            msg_id, job_id, buffer_offset, mkey, none);
    p.ses.req_len = len;
    p.ses.payload_len = 0;
    return p;
  }

  static Packet make_send(uint32_t psn, uint16_t spdcid, uint16_t dpdcid,
                          uint32_t msg_id, uint32_t job_id,
                          const std::vector<uint8_t>& data) {
    return make_request(SES_SEND, PDS_RUD_REQ, psn, spdcid, dpdcid,
                        msg_id, job_id, 0, 0, data);
  }

  static Packet make_ack(uint32_t cack_psn, int16_t ack_psn_offset,
                         uint16_t spdcid, uint16_t dpdcid,
                         uint8_t flags = 0) {
    Packet p;
    p.kind = Kind::Ack;
    p.ack.flags = flags;
    p.ack.cack_psn = cack_psn;
    p.ack.ack_psn_offset = ack_psn_offset;
    p.ack.spdcid = spdcid;
    p.ack.dpdcid = dpdcid;
    return p;
  }

  static Packet make_ack_cc(uint32_t cack_psn, int16_t sack_psn_offset,
                            uint64_t sack_bitmap, uint64_t ack_cc_state,
                            uint16_t spdcid, uint16_t dpdcid,
                            uint8_t flags = 0, uint8_t cc_type_flags = 0,
                            uint8_t mpr = 0) {
    Packet p = make_ack(cack_psn, 0, spdcid, dpdcid, flags);
    p.ack.cc = true;
    p.ack.cc_type_flags = cc_type_flags;
    p.ack.mpr = mpr;
    p.ack.sack_psn_offset = sack_psn_offset;
    p.ack.sack_bitmap = sack_bitmap;
    p.ack.ack_cc_state = ack_cc_state;
    return p;
  }

  static Packet make_nack(uint8_t code, uint32_t psn, uint16_t spdcid,
                          uint16_t dpdcid, uint32_t extra = 0) {
    Packet p;
    p.kind = Kind::Nack;
    p.nack.nack_code = code;
    p.nack.psn = psn;
    p.nack.spdcid = spdcid;
    p.nack.dpdcid = dpdcid;
    p.nack.payload = extra;
    return p;
  }

  static Packet make_ctrl(uint8_t ctrl_type, uint32_t psn, uint16_t spdcid,
                          uint16_t dpdcid, uint32_t extra = 0,
                          uint8_t flags = PDS_REQ_AR) {
    Packet p;
    p.kind = Kind::Ctrl;
    p.ctrl.ctrl_type = ctrl_type;
    p.ctrl.flags = flags;
    p.ctrl.psn = psn;
    p.ctrl.spdcid = spdcid;
    p.ctrl.dpdcid = dpdcid;
    p.ctrl.payload = extra;
    return p;
  }

  static Packet make_response(uint8_t rc, uint16_t msg_id, uint32_t job_id,
                              uint32_t mod_len, uint32_t cack_psn,
                              uint16_t spdcid, uint16_t dpdcid) {
    Packet p;
    p.kind = Kind::Response;
    p.ack.cack_psn = cack_psn;
    p.ack.spdcid = spdcid;
    p.ack.dpdcid = dpdcid;
    p.rsp.rc = rc;
    p.rsp.msg_id = msg_id;
    p.rsp.job_id = job_id & 0xFFFFFFu;
    p.rsp.mod_len = mod_len;
    return p;
  }

  static Packet make_read_response(uint8_t rc, uint16_t msg_id,
                                   uint32_t job_id, uint32_t mod_len,
                                   uint16_t rd_msg_id, uint32_t msg_off,
                                   uint32_t cack_psn, uint16_t spdcid,
                                   uint16_t dpdcid,
                                   const std::vector<uint8_t>& data) {
    Packet p = make_response(rc, msg_id, job_id, mod_len, cack_psn,
                             spdcid, dpdcid);
    p.rsp_data = true;
    p.rsp.opcode = RSP_WITH_DATA;
    p.rsp.rd_msg_id = rd_msg_id;
    p.rsp.payload_len = (uint16_t)data.size();
    p.rsp.msg_off = msg_off;
    p.payload = data;
    return p;
  }

  
  std::vector<uint8_t> encode() const {
    size_t pds_len = kind == Kind::Request ? kPdsReqLen
                   : kind == Kind::Ack ? (ack.cc ? kPdsAckCcLen : kPdsAckLen)
                   : kind == Kind::Response ? kPdsAckLen
                   : kind == Kind::Nack ? kPdsNackLen : kPdsCtrlLen;
#ifdef UET_HDR_RED_STD
    const uint8_t hdr_form = NEXT_REQ_STD;   
#else
    const uint8_t hdr_form = ses_next;
#endif
    size_t req_ses_len = hdr_form == NEXT_REQ_SMALL  ? kSesSmallLen
                       : hdr_form == NEXT_REQ_MEDIUM ? kSesMediumLen
                                                     : kSesStdLen;
    size_t ses_len = kind == Kind::Request ? req_ses_len
                   : kind == Kind::Response ? (rsp_data ? 20u : kSesRspLen) : 0;
    size_t uet_body = pds_len + ses_len + payload.size();
    size_t ip_total = kIpLen + kUdpLen + uet_body + kCrcLen;
    size_t udp_total = kUdpLen + uet_body + kCrcLen;
    if (ip_total > 0xFFFF) return {};

    
    
    std::vector<uint8_t> out(kEthLen + ip_total - kCrcLen, 0);
    
    std::memcpy(&out[0], dmac.data(), 6);
    std::memcpy(&out[6], smac.data(), 6);
    put16(out, 12, kEtherTypeIPv4);

    const size_t ip = kEthLen;
    const size_t udp = ip + kIpLen;
    const size_t pds = udp + kUdpLen;
    const size_t ses = pds + pds_len;

    
    out[ip + 0] = 0x45;
    out[ip + 1] = tos;
    put16(out, ip + 2, (uint16_t)ip_total);
    put16(out, ip + 4, 0);                 
    put16(out, ip + 6, 0x4000);            
    out[ip + 8] = kIpTtl;
    out[ip + 9] = kIpProtoUdp;
    put16(out, ip + 10, 0);                
    put32(out, ip + 12, src_ip);
    put32(out, ip + 16, dst_ip);
    put16(out, ip + 10, ip_checksum((const uint8_t*)&out[ip]));

    
    put16(out, udp + 0, entropy);
    put16(out, udp + 2, kUetUdpPort);
    put16(out, udp + 4, (uint16_t)udp_total);
    put16(out, udp + 6, 0);

    
    uint8_t type = (kind == Kind::Request) ? (uint8_t)req.type
                 : (kind == Kind::Ack) ? (uint8_t)(ack.cc ? PDS_ACK_CC : PDS_ACK)
                 : (kind == Kind::Nack) ? (uint8_t)PDS_NACK
                 : (kind == Kind::Ctrl) ? (uint8_t)PDS_CTRL : (uint8_t)PDS_ACK;
    uint8_t next = (kind == Kind::Request) ? hdr_form
                 : (kind == Kind::Ack) ? NEXT_NONE
                 : (kind == Kind::Response) ? (rsp_data ? NEXT_RSP_DATA : NEXT_RSP)
                 : (kind == Kind::Ctrl) ? (uint8_t)(ctrl.ctrl_type & 0x0F) : 0;
    uint8_t flags = (kind == Kind::Request) ? req.flags
                  : (kind == Kind::Ack || kind == Kind::Response) ? ack.flags
                  : (kind == Kind::Nack) ? nack.flags : ctrl.flags;
    uint16_t prologue = (uint16_t)(((type & 0x1F) << 11) |
                                   ((next & 0x0F) << 7) |
                                   (flags & 0x7F));
    put16(out, pds, prologue);

    if (kind == Kind::Request) {
      put16(out, pds + 2, (uint16_t)req.clear_psn_offset);
      put32(out, pds + 4, req.psn);
      put16(out, pds + 8, req.spdcid);
      put16(out, pds + 10, req.dpdcid);
    } else if (kind == Kind::Ack || kind == Kind::Response) {
      put16(out, pds + 2, (uint16_t)ack.ack_psn_offset);
      put32(out, pds + 4, ack.cack_psn);
      put16(out, pds + 8, ack.spdcid);
      put16(out, pds + 10, ack.dpdcid);
      if (kind == Kind::Ack && ack.cc) {
        out[pds + 12] = ack.cc_type_flags;
        out[pds + 13] = ack.mpr;
        put16(out, pds + 14, (uint16_t)ack.sack_psn_offset);
        put64(out, pds + 16, ack.sack_bitmap);
        put64(out, pds + 24, ack.ack_cc_state);
      }
    } else if (kind == Kind::Nack) {
      out[pds + 2] = nack.nack_code;
      out[pds + 3] = nack.vendor_code;
      put32(out, pds + 4, nack.psn);
      put16(out, pds + 8, nack.spdcid);
      put16(out, pds + 10, nack.dpdcid);
      put32(out, pds + 12, nack.payload);
    } else { 
      put16(out, pds + 2, ctrl.probe_or_rsvd);
      put32(out, pds + 4, ctrl.psn);
      put16(out, pds + 8, ctrl.spdcid);
      put16(out, pds + 10, ctrl.dpdcid);
      put32(out, pds + 12, ctrl.payload);
    }

    if (kind == Kind::Request) {
      encode_ses_req(out, ses);
    } else if (kind == Kind::Response) {
      encode_ses_rsp(out, ses, rsp_data);
    }
    if (!payload.empty())
      std::memcpy(&out[ses + ses_len], payload.data(), payload.size());

    uint32_t crc = crc32c(&out[ip + 12], out.size() - (ip + 12));
    append_crc_be(out, crc);
    return out;
  }

  
  bool decode(const std::vector<uint8_t>& frame) {
    crc_valid = false;
    ip_checksum_valid = false;
    trimmed = false;
    trimmed_last_hop = false;
    if (frame.size() < kEthLen) return false;
    std::memcpy(dmac.data(), &frame[0], 6);
    std::memcpy(smac.data(), &frame[6], 6);

    
    
    uint16_t et = be16(&frame[12]);
    size_t ip = kEthLen;
    bool after_vlan = false;
    for (int depth = 0; depth < 8; depth++) {
      if (et == 0x8100 || et == 0x88A8) {
        if (ip + 4 > frame.size()) return false;
        et = be16(&frame[ip + 2]);
        ip += 4;
        after_vlan = true;
      } else if (et == 0x88B6) {       
        if (after_vlan) {              
          if (ip + 4 > frame.size()) return false;
          et = be16(&frame[ip + 2]);
          ip += 4;
        } else {
          if (ip + 6 > frame.size()) return false;
          et = be16(&frame[ip + 4]);
          ip += 6;
        }
      } else if (et == 0x88B7) {       
        if (after_vlan) {
          if (ip + 8 > frame.size()) return false;
          et = be16(&frame[ip + 6]);
          ip += 8;
        } else {
          if (ip + 10 > frame.size()) return false;
          et = be16(&frame[ip + 8]);
          ip += 10;
        }
      } else if (et == 0x88B5) {       
        if (ip + 12 >= frame.size()) return false;
        ip += 12;
        et = ((frame[ip] >> 4) == 4) ? kEtherTypeIPv4 : 0;
      } else {
        break;
      }
    }
    if (et != kEtherTypeIPv4) return false;
    if (frame.size() < ip + kIpLen + kUdpLen) return false;
    if (frame[ip] != 0x45) return false;
    uint16_t ip_total = be16(&frame[ip + 2]);
    if (ip_total < kIpLen + kUdpLen) return false;
    if (frame.size() < ip + ip_total) return false;
    if (frame[ip + 9] != kIpProtoUdp) return false;
    tos = frame[ip + 1];
    uint8_t dscp = (uint8_t)((tos >> 2) & 0x3F);
    trimmed_last_hop = (dscp == kDscpTrimLastHop);
    trimmed = trimmed_last_hop || (dscp == kDscpTrimmed);
    src_ip = be32(&frame[ip + 12]);
    dst_ip = be32(&frame[ip + 16]);
    ip_checksum_valid = ip_checksum((const uint8_t*)&frame[ip]) == 0;

    const size_t udp = ip + kIpLen;
    if (be16(&frame[udp + 2]) != kUetUdpPort) return false;
    entropy = be16(&frame[udp + 0]);
    uint16_t udp_total = be16(&frame[udp + 4]);
    if (udp_total < kUdpLen) return false;
    if (!trimmed) {
      if (udp_total < kUdpLen + kCrcLen) return false;
      
      if (udp + udp_total < ip + ip_total) return false;
      trimmed = (udp + udp_total != ip + ip_total);
    }

    
    
    
    const size_t crc_off = trimmed ? (ip + ip_total)
                                   : (ip + ip_total - kCrcLen);
    if (!trimmed) {
      uint32_t want = crc32c(&frame[ip + 12], crc_off - (ip + 12));
      crc_valid = crc_match_be(&frame[crc_off], want);
    }

    const size_t pds = udp + kUdpLen;
    uint16_t prologue = be16(&frame[pds]);
    uint8_t type = (uint8_t)((prologue >> 11) & 0x1F);
    uint8_t next = (uint8_t)((prologue >> 7) & 0x0F);
    uint8_t flags = (uint8_t)(prologue & 0x7F);

    if (type == PDS_RUD_REQ || type == PDS_ROD_REQ) {
      if (next != NEXT_REQ_STD && next != NEXT_REQ_SMALL &&
          next != NEXT_REQ_MEDIUM) return false;
      if (pds + kPdsReqLen > crc_off) return false;
      ses_next = next;
      kind = Kind::Request;
      req.type = type; req.flags = flags;
      req.clear_psn_offset = (int16_t)be16(&frame[pds + 2]);
      req.psn = be32(&frame[pds + 4]);
      req.spdcid = be16(&frame[pds + 8]);
      req.dpdcid = be16(&frame[pds + 10]);
      const size_t ses_off = pds + kPdsReqLen;
      const size_t ses_len = next == NEXT_REQ_SMALL  ? kSesSmallLen
                           : next == NEXT_REQ_MEDIUM ? kSesMediumLen
                                                     : kSesStdLen;
      if (ses_off + ses_len <= crc_off) {
        decode_ses_req(frame, ses_off);
        payload.assign(frame.begin() + ses_off + ses_len,
                       frame.begin() + crc_off);
      } else {
        
        
        this->ses = SesReqStd{};
        payload.clear();
      }
      return true;
    }
    if (type == PDS_ACK_CC || type == PDS_ACK_CCX) {
      size_t need = (type == PDS_ACK_CC) ? kPdsAckCcLen : kPdsAckCcxLen;
      if (pds + need > crc_off) return false;
      ack.flags = flags;
      ack.ack_psn_offset = (int16_t)be16(&frame[pds + 2]);
      ack.cack_psn = be32(&frame[pds + 4]);
      ack.spdcid = be16(&frame[pds + 8]);
      ack.dpdcid = be16(&frame[pds + 10]);
      ack.cc = true;
      ack.cc_type_flags = frame[pds + 12];
      ack.mpr = frame[pds + 13];
      ack.sack_psn_offset = (int16_t)be16(&frame[pds + 14]);
      ack.sack_bitmap = be64(&frame[pds + 16]);
      ack.ack_cc_state = be64(&frame[pds + 24]);
      kind = Kind::Ack;
      return true;
    }
    if (type == PDS_ACK) {
      if (pds + kPdsAckLen > crc_off) return false;
      ack.cc = false;
      ack.flags = flags;
      ack.ack_psn_offset = (int16_t)be16(&frame[pds + 2]);
      ack.cack_psn = be32(&frame[pds + 4]);
      ack.spdcid = be16(&frame[pds + 8]);
      ack.dpdcid = be16(&frame[pds + 10]);
      if (next == NEXT_NONE) {
        kind = Kind::Ack;
        return true;
      }
      if (next == NEXT_RSP && pds + kPdsAckLen + kSesRspLen <= crc_off) {
        kind = Kind::Response;
        rsp_data = false;
        decode_ses_rsp(frame, pds + kPdsAckLen, false);
        payload.assign(frame.begin() + pds + kPdsAckLen + kSesRspLen,
                       frame.begin() + crc_off);
        return true;
      }
      if (next == NEXT_RSP_DATA && pds + kPdsAckLen + 20 <= crc_off) {
        kind = Kind::Response;
        rsp_data = true;
        decode_ses_rsp(frame, pds + kPdsAckLen, true);
        payload.assign(frame.begin() + pds + kPdsAckLen + 20,
                       frame.begin() + crc_off);
        return true;
      }
      return false;
    }
    if (type == PDS_NACK) {
      if (pds + kPdsNackLen > crc_off) return false;
      kind = Kind::Nack;
      nack.flags = flags;
      nack.nack_code = frame[pds + 2];
      nack.vendor_code = frame[pds + 3];
      nack.psn = be32(&frame[pds + 4]);
      nack.spdcid = be16(&frame[pds + 8]);
      nack.dpdcid = be16(&frame[pds + 10]);
      nack.payload = be32(&frame[pds + 12]);
      return true;
    }
    if (type == PDS_CTRL) {
      if (pds + kPdsCtrlLen > crc_off) return false;
      kind = Kind::Ctrl;
      ctrl.ctrl_type = next;
      ctrl.flags = flags;
      ctrl.probe_or_rsvd = be16(&frame[pds + 2]);
      ctrl.psn = be32(&frame[pds + 4]);
      ctrl.spdcid = be16(&frame[pds + 8]);
      ctrl.dpdcid = be16(&frame[pds + 10]);
      ctrl.payload = be32(&frame[pds + 12]);
      return true;
    }
    return false;
  }

 private:
  static uint16_t ip_checksum(const uint8_t* ip) {
    uint32_t sum = 0;
    for (size_t i = 0; i < kIpLen; i += 2)
      sum += (uint16_t)(((uint16_t)ip[i] << 8) | ip[i + 1]);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
  }

  void encode_ses_req(std::vector<uint8_t>& v, size_t o) const {
    
    
    
    
    bool len_in_common =
        ses_next == NEXT_REQ_SMALL || ses_next == NEXT_REQ_MEDIUM;
#ifdef UET_HDR_RED_LEN
    len_in_common = false;   
#endif
    v[o + 0] = (uint8_t)(ses.opcode & 0x3F);
    
    
    const uint8_t sflags = (uint8_t)((ses.flags | (ses.hd ? SES_HD : 0)) & 0x3F);
    v[o + 1] = (uint8_t)(((ses.ver & 0x03) << 6) | sflags);
    put16(v, o + 2, len_in_common ? (uint16_t)(ses.req_len & 0x3FFF)
                                  : ses.msg_id);
    v[o + 4] = ses.ri_gen;
    v[o + 5] = (uint8_t)(ses.job_id >> 16);
    v[o + 6] = (uint8_t)(ses.job_id >> 8);
    v[o + 7] = (uint8_t)ses.job_id;
    put16(v, o + 8, (uint16_t)(ses.pid & 0x0FFF));
    put16(v, o + 10, (uint16_t)(ses.ri & 0x0FFF));

    if (ses_next == NEXT_REQ_SMALL) {
      
      put64(v, o + 12, ses.buffer_offset);
      return;
    }
    if (ses_next == NEXT_REQ_MEDIUM) {
      
      put64(v, o + 12, ses.hd ? ses.header_data : ses.buffer_offset);
      put32(v, o + 20, ses.initiator);
      put64(v, o + 24, ses.match_bits);
      return;
    }

    
    put64(v, o + 12, ses.buffer_offset);
    put32(v, o + 20, ses.initiator);
    put64(v, o + 24, ses.match_bits);
    uint64_t field = 0;
    if (ses.hd) {
      field = ses.header_data;
    } else if (ses.flags & SES_SOM) {
      
      
      
      field = 0;
    } else {
      field = ((uint64_t)(ses.payload_len & 0x3FFF) << 32) |
              (uint64_t)ses.msg_off;
    }
    put64(v, o + 32, field);
    put32(v, o + 40, ses.req_len);
  }

  void decode_ses_req(const std::vector<uint8_t>& v, size_t o) {
    const uint16_t common2 = be16(&v[o + 2]);
    ses.opcode = (uint8_t)(v[o + 0] & 0x3F);
    ses.ver = (uint8_t)((v[o + 1] >> 6) & 0x03);
    ses.flags = (uint8_t)(v[o + 1] & 0x3F);
    ses.msg_id = common2;      
    ses.ri_gen = v[o + 4];
    ses.job_id = ((uint32_t)v[o + 5] << 16) | ((uint32_t)v[o + 6] << 8) | v[o + 7];
    ses.pid = (uint16_t)(be16(&v[o + 8]) & 0x0FFF);
    ses.ri = (uint16_t)(be16(&v[o + 10]) & 0x0FFF);
    ses.hd = (ses.flags & SES_HD) != 0;

    if (ses_next == NEXT_REQ_SMALL) {
      
      ses.buffer_offset = be64(&v[o + 12]);
      ses.initiator = 0;
      ses.match_bits = 0;
      ses.header_data = 0;
      ses.payload_len = 0;
      ses.msg_off = 0;
      ses.req_len = (uint32_t)(common2 & 0x3FFF);
      return;
    }
    if (ses_next == NEXT_REQ_MEDIUM) {
      
      const uint64_t u = be64(&v[o + 12]);
      ses.buffer_offset = u;
      ses.initiator = be32(&v[o + 20]);
      ses.match_bits = be64(&v[o + 24]);
      ses.header_data = ses.hd ? u : 0;
      ses.payload_len = 0;
      ses.msg_off = 0;
      ses.req_len = (uint32_t)(common2 & 0x3FFF);
      return;
    }

    
    ses.buffer_offset = be64(&v[o + 12]);
    ses.initiator = be32(&v[o + 20]);
    ses.match_bits = be64(&v[o + 24]);
    uint64_t field = be64(&v[o + 32]);
    if (ses.hd) {
      ses.header_data = field;
      ses.payload_len = 0;
      ses.msg_off = 0;
    } else if (ses.flags & SES_SOM) {
      ses.header_data = 0;
      ses.payload_len = 0;
      ses.msg_off = 0;
    } else {
      ses.header_data = 0;
      ses.payload_len = (uint32_t)((field >> 32) & 0x3FFF);
      ses.msg_off = (uint32_t)field;
    }
    ses.req_len = be32(&v[o + 40]);
  }

  void encode_ses_rsp(std::vector<uint8_t>& v, size_t o, bool data) const {
    v[o + 0] = (uint8_t)(((rsp.list & 0x03) << 6) | (rsp.opcode & 0x3F));
    v[o + 1] = (uint8_t)(((rsp.ver & 0x03) << 6) | (rsp.rc & 0x3F));
    put16(v, o + 2, rsp.msg_id);
    v[o + 4] = rsp.ri_gen;
    v[o + 5] = (uint8_t)(rsp.job_id >> 16);
    v[o + 6] = (uint8_t)(rsp.job_id >> 8);
    v[o + 7] = (uint8_t)rsp.job_id;
    if (!data) {
      put32(v, o + 8, rsp.mod_len);
    } else {
      put16(v, o + 8, rsp.rd_msg_id);
      put16(v, o + 10, rsp.payload_len);
      put32(v, o + 12, rsp.mod_len);
      put32(v, o + 16, rsp.msg_off);
    }
  }

  void decode_ses_rsp(const std::vector<uint8_t>& v, size_t o, bool data) {
    rsp.list = (uint8_t)((v[o + 0] >> 6) & 0x03);
    rsp.opcode = (uint8_t)(v[o + 0] & 0x3F);
    rsp.ver = (uint8_t)((v[o + 1] >> 6) & 0x03);
    rsp.rc = (uint8_t)(v[o + 1] & 0x3F);
    rsp.msg_id = be16(&v[o + 2]);
    rsp.ri_gen = v[o + 4];
    rsp.job_id = ((uint32_t)v[o + 5] << 16) | ((uint32_t)v[o + 6] << 8) | v[o + 7];
    if (!data) {
      rsp.mod_len = be32(&v[o + 8]);
      rsp.rd_msg_id = 0;
      rsp.payload_len = 0;
      rsp.msg_off = 0;
    } else {
      rsp.rd_msg_id = be16(&v[o + 8]);
      rsp.payload_len = be16(&v[o + 10]);
      rsp.mod_len = be32(&v[o + 12]);
      rsp.msg_off = be32(&v[o + 16]);
    }
  }
};

}  
