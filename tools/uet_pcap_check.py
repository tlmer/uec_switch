#!/usr/bin/env python3
# Independent pcap reader/checker for the M3 UET golden frames.
# Deliberately does not use the C++ Packet encoder/decoder: it re-parses
# Ethernet/IPv4/UDP/PDS/SES and recomputes FCS/CRC32C from the bytes.
import struct
import sys

UET_UDP_PORT = 4793
ETH_P_IPV4 = 0x0800
IPPROTO_UDP = 17
PDS_RUD_REQ = 0x02
PDS_ROD_REQ = 0x03
NEXT_REQ_STD = 0x03
SES_WRITE = 0x01
SES_READ = 0x02
SES_SEND = 0x05


def be16(b, o):
    return (b[o] << 8) | b[o + 1]


def be32(b, o):
    return ((b[o] << 24) | (b[o + 1] << 16) |
            (b[o + 2] << 8) | b[o + 3])


def crc32c(data):
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if (crc & 1) else 0)
    return (~crc) & 0xFFFFFFFF


def crc32_eth(data):
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 if (crc & 1) else 0)
    return (~crc) & 0xFFFFFFFF


def ip_checksum_ok(pkt, ip):
    total = be16(pkt, ip + 2)
    hdr = (pkt[ip] & 0x0F) * 4
    if hdr < 20 or ip + total > len(pkt):
        return False
    s = 0
    for i in range(ip, ip + hdr, 2):
        s += be16(pkt, i)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (s & 0xFFFF) == 0xFFFF


def read_pcap(path):
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) < 24:
        raise ValueError('short pcap header')
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != 0xA1B2C3D4:
        raise ValueError('unexpected pcap magic 0x%08x' % magic)
    _, vmaj, vmin, _, _, snap, link = struct.unpack_from('<IHHIIII', data, 0)
    if (vmaj, vmin) != (2, 4) or snap != 65535 or link != 1:
        raise ValueError('bad pcap global header')
    off = 24
    frames = []
    while off + 16 <= len(data):
        sec, usec, incl, orig = struct.unpack_from('<IIII', data, off)
        off += 16
        if incl > len(data) - off or incl == 0:
            raise ValueError('bad record length')
        frames.append(data[off:off + incl])
        off += incl
    return frames


def check_frame(idx, wire):
    if len(wire) < 18:
        raise ValueError('frame %d too short' % idx)
    fcs = struct.unpack_from('<I', wire, len(wire) - 4)[0]
    if crc32_eth(wire[:-4]) != fcs:
        raise ValueError('frame %d Ethernet FCS mismatch' % idx)
    pkt = wire[:-4]
    if be16(pkt, 12) != ETH_P_IPV4:
        raise ValueError('frame %d not IPv4' % idx)
    ip = 14
    if pkt[ip] != 0x45:
        raise ValueError('frame %d not IPv4 IHL=5' % idx)
    total = be16(pkt, ip + 2)
    if ip + total > len(pkt):
        raise ValueError('frame %d IP total length overruns' % idx)
    if not ip_checksum_ok(pkt, ip):
        raise ValueError('frame %d IPv4 checksum bad' % idx)
    if pkt[ip + 9] != IPPROTO_UDP:
        raise ValueError('frame %d not UDP' % idx)
    udp = ip + (pkt[ip] & 0x0F) * 4
    if be16(pkt, udp + 2) != UET_UDP_PORT:
        raise ValueError('frame %d UDP dst != 4793' % idx)
    if udp + be16(pkt, udp + 4) != ip + total:
        raise ValueError('frame %d UDP length mismatch' % idx)
    crc_off = ip + total - 4
    crc = be32(pkt, crc_off)
    if crc32c(pkt[ip + 12:crc_off]) != crc:
        raise ValueError('frame %d UET CRC mismatch' % idx)

    pds = udp + 8
    prologue = be16(pkt, pds)
    ptype = (prologue >> 11) & 0x1F
    nxt = (prologue >> 7) & 0x0F
    if ptype not in (PDS_RUD_REQ, PDS_ROD_REQ) or nxt != NEXT_REQ_STD:
        raise ValueError('frame %d PDS type/next unexpected' % idx)
    psn = be32(pkt, pds + 4)
    spdc = be16(pkt, pds + 8)
    dpdc = be16(pkt, pds + 10)
    ses = pds + 12
    opcode = pkt[ses] & 0x3F
    msg_id = be16(pkt, ses + 2)
    job_id = (pkt[ses + 5] << 16) | (pkt[ses + 6] << 8) | pkt[ses + 7]
    req_len = be32(pkt, ses + 40)
    payload = pkt[ses + 44:crc_off]
    return {
        'psn': psn, 'spdc': spdc, 'dpdc': dpdc, 'opcode': opcode,
        'msg_id': msg_id, 'job_id': job_id, 'req_len': req_len,
        'payload_len': len(payload), 'crc': crc,
    }


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else '/dev/shm/uet_m3.pcap'
    try:
        frames = read_pcap(path)
        if len(frames) != 3:
            raise ValueError('expected 3 frames, got %d' % len(frames))
        exp = [
            (SES_WRITE, 4096),
            (SES_READ, 0),
            (SES_SEND, 64),
        ]
        for i, wire in enumerate(frames):
            f = check_frame(i, wire)
            op, plen = exp[i]
            if f['opcode'] != op:
                raise ValueError('frame %d opcode %u != %u' %
                                 (i, f['opcode'], op))
            if f['payload_len'] != plen:
                raise ValueError('frame %d payload %u != %u' %
                                 (i, f['payload_len'], plen))
            if f['psn'] != 0x100 + i or f['spdc'] != 0x10 or f['dpdc'] != 0x20:
                raise ValueError('frame %d PSN/PDC mismatch' % i)
            if f['msg_id'] != i + 1 or f['job_id'] != 0x123456:
                raise ValueError('frame %d SES id mismatch' % i)
            if i == 1 and f['req_len'] != 4096:
                raise ValueError('frame 1 READ req_len != 4096')
        print('SW_UET_PCAP_EXT PASS frames=%d path=%s' % (len(frames), path))
        return 0
    except Exception as exc:
        print('SW_UET_PCAP_EXT FAIL %s' % exc)
        return 1


if __name__ == '__main__':
    sys.exit(main())
