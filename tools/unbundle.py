#!/usr/bin/env python3
"""Extract files from a .NET single-file bundle (e.g. NotMeter.exe).

usage: unbundle.py NotMeter.exe OUT_DIR [NAME ...]
With NAMEs, only those files are written.
"""
import os
import struct
import sys
import zlib

# Marker that the .NET apphost places right after the bundle header offset.
SIGNATURE = bytes.fromhex(
    "8b1202b96a61203872" "7b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae")


def main():
    exe, out = sys.argv[1], sys.argv[2]
    wanted = set(sys.argv[3:])
    data = open(exe, "rb").read()
    at = data.find(SIGNATURE)
    if at < 8:
        sys.exit("not a .NET single-file bundle")
    pos = struct.unpack_from("<q", data, at - 8)[0]

    def read_string():
        nonlocal pos
        n = shift = 0
        while True:
            b = data[pos]
            pos += 1
            n |= (b & 0x7F) << shift
            shift += 7
            if b < 0x80:
                break
        s = data[pos:pos + n].decode("utf-8")
        pos += n
        return s

    major, _minor, count = struct.unpack_from("<IIi", data, pos)
    pos += 12
    read_string()  # bundle id
    if major >= 2:
        pos += 8 * 4 + 8  # deps.json / runtimeconfig.json locations, flags
    for _ in range(count):
        offset, size = struct.unpack_from("<qq", data, pos)
        pos += 16
        compressed = 0
        if major >= 6:
            compressed = struct.unpack_from("<q", data, pos)[0]
            pos += 8
        pos += 1  # file type
        name = read_string()
        if wanted and name not in wanted:
            continue
        blob = data[offset:offset + (compressed or size)]
        if compressed:
            blob = zlib.decompress(blob, -15)
        path = os.path.join(out, name)
        os.makedirs(os.path.dirname(path) or out, exist_ok=True)
        with open(path, "wb") as f:
            f.write(blob)


if __name__ == "__main__":
    main()
