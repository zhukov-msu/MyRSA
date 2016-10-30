__author__ = 'user'

import struct


def _left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

def sha100500(message):
    # Initialize variables:
    h0 = 0x32631273
    h1 = 0x812AB321
    h2 = 0x435CE1F1
    h3 = 0x8381CAD1
    h4 = 0xC02312EF

    # Pre-processing:
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8
    message += b'\x80'
    message += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)

    message += struct.pack(b'>Q', original_bit_len)
    for i in xrange(0, len(message), 64):
        w = [0] * 80
        for j in xrange(16):
            w[j] = struct.unpack(b'>I', message[i + j*4:i + j*4 + 4])[0]
        for j in xrange(16, 80):
            w[j] = _left_rotate(w[j-2] ^ w[j-6] ^ w[j-11] ^ w[j-12], 1)
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in xrange(80):
            if 0 <= i <= 19:
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff,
                            a, _left_rotate(b, 30), c, d)

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

