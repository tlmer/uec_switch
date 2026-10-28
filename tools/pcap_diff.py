#!/usr/bin/env python3
"""Byte-level pcap diff for the UEC switch model (S8).

Usage:
  pcap_diff.py A.pcap B.pcap          # exit 0 if identical, 1 if different
  pcap_diff.py --flip A.pcap B.pcap   # copy A -> B with one payload byte flipped

Supports classic pcap (magic a1b2c3d4 / d4c3b2a1), linktype 1 (Ethernet).
"""
import struct
import sys


def read_pcap(path):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        raise ValueError("%s: short pcap header" % path)
    magic = data[:4]
    if magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"      # magic stored big-endian
    elif magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"      # magic stored little-endian
    else:
        raise ValueError("%s: unsupported magic %s" % (path, magic.hex()))
    # The model writer emits the major/minor version as two 32-bit words
    # (28-byte header), unlike classic pcap's packed 16-bit pair (24 bytes).
    w1 = struct.unpack(endian + "I", data[4:8])[0]
    w2 = struct.unpack(endian + "I", data[8:12])[0]
    if w1 == 2 and w2 == 4:
        hdr_len = 28
        hdr = struct.unpack(endian + "IIIIIII", data[:28])
    else:
        hdr_len = 24
        hdr = struct.unpack(endian + "IHHIIII", data[:24])
    recs = []
    off = hdr_len
    while off + 16 <= len(data):
        ts, tu, incl, orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if off + incl > len(data):
            raise ValueError("%s: truncated record at %d" % (path, off))
        recs.append(((ts, tu, incl, orig), data[off:off + incl]))
        off += incl
    return {"endian": endian, "hdr_len": hdr_len, "hdr": hdr, "recs": recs}


def diff(a, b):
    out = []
    if a["endian"] != b["endian"]:
        out.append("endian %s vs %s" % (a["endian"], b["endian"]))
    if a["hdr"] != b["hdr"]:
        out.append("global header %r vs %r" % (a["hdr"], b["hdr"]))
    if len(a["recs"]) != len(b["recs"]):
        out.append("record count %d vs %d" % (len(a["recs"]), len(b["recs"])))
    for i, (ra, rb) in enumerate(zip(a["recs"], b["recs"])):
        if ra[0] != rb[0]:
            out.append("rec %d header %r vs %r" % (i, ra[0], rb[0]))
        if ra[1] != rb[1]:
            n = min(len(ra[1]), len(rb[1]))
            pos = next((j for j in range(n) if ra[1][j] != rb[1][j]), n)
            out.append("rec %d payload len %d/%d first_diff=%d" %
                       (i, len(ra[1]), len(rb[1]), pos))
    return out


def flip(src, dst):
    p = read_pcap(src)
    if not p["recs"]:
        raise ValueError("no records to flip")
    hdr, data = p["recs"][0]
    if len(data) < 20:
        raise ValueError("first record too short")
    # Flip one byte near the end of the first frame (inside payload/FCS).
    b = bytearray(data)
    b[-5] ^= 0x01
    p["recs"][0] = (hdr, bytes(b))
    with open(dst, "wb") as f:
        if p["hdr_len"] == 28:
            f.write(struct.pack(p["endian"] + "IIIIIII", *p["hdr"]))
        else:
            f.write(struct.pack(p["endian"] + "IHHIIII", *p["hdr"]))
        for (ts, tu, incl, orig), d in p["recs"]:
            f.write(struct.pack(p["endian"] + "IIII", ts, tu, len(d), orig))
            f.write(d)
    return len(p["recs"])


def main(argv):
    if len(argv) == 4 and argv[1] == "--flip":
        n = flip(argv[2], argv[3])
        print("PCAP_FLIP frames=%d src=%s dst=%s" % (n, argv[2], argv[3]))
        return 0
    if len(argv) != 3:
        print(__doc__)
        return 2
    a, b = read_pcap(argv[1]), read_pcap(argv[2])
    d = diff(a, b)
    print("PCAP_DIFF frames=%d/%d diffs=%d" %
          (len(a["recs"]), len(b["recs"]), len(d)))
    for line in d[:20]:
        print("PCAP_DIFF_DETAIL " + line)
    if d:
        print("PCAP_DIFF DIFF")
        return 1
    print("PCAP_DIFF PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
