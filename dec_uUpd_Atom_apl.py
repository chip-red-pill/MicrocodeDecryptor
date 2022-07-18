import math, sys, struct, hashlib
from Crypto.Cipher import ARC4

def ROR32(v, nBit): return ((v >> nBit) | (v << (32 - nBit))) & 0xFFFFFFFF

class my_SHA256(object):
  k = [
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]
  def __init__(self, h=None):
    self.h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19] if h is None else h[:]
    self.w = [0]*64

  def transform(self, blk):
    w = self.w
    w[:16] = struct.unpack_from(">16L", blk) # assert len(blk) == 0x40
    for i in range(16, 64): # Extend the first 16 words into the remaining 48 words
      s0 = ROR32(w[i-15], 7) ^ ROR32(w[i-15], 18) ^ (w[i-15] >> 3)
      s1 = ROR32(w[i-2], 17) ^ ROR32(w[i- 2], 19) ^ (w[i-2] >> 10)
      w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF
    a,b,c,d,e,f,g,h = self.h

    for i in range(64): # Compression function main loop
      S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25)
      ch = (e & f) ^ ((0xFFFFFFFF ^ e) & g)
      temp1 = (h + S1 + ch + self.k[i] + w[i]) & 0xFFFFFFFF
      S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22)
      maj = (a & b) ^ (a & c) ^ (b & c)
      temp2 = (S0 + maj) & 0xFFFFFFFF
 
      h = g
      g = f
      f = e
      e = (d + temp1) & 0xFFFFFFFF
      d = c
      c = b
      b = a
      a = (temp1 + temp2) & 0xFFFFFFFF

    # Add the compressed chunk to the current hash value:
    self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
    self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
    self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
    self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
    self.h[4] = (self.h[4] + e) & 0xFFFFFFFF
    self.h[5] = (self.h[5] + f) & 0xFFFFFFFF
    self.h[6] = (self.h[6] + g) & 0xFFFFFFFF
    self.h[7] = (self.h[7] + h) & 0xFFFFFFFF

    return self.get(True)

  def get(self, le=False):
    return struct.pack("<8L" if le else ">8L", *self.h)

def calcEntropy(data):
  entropy = 0.0
  for x in range(256):
    p_x = float(data.count(b"%c" % x))/len(data)
    if p_x > 0: entropy -= p_x*math.log(p_x, 2)
  return entropy


aX = [0x9db2770e, 0x5d76919e, 0x994866a2, 0xab13688b] # Secret
abX = struct.pack("<4L", *aX)

hPub_need = bytes.fromhex("a1b4b7417f0fdcdb0feaa26eb5b78fb2cb86153f0ce98803f5cb84ae3a45901d") # Hash of Modulus

def s2i(ab):
  return int(ab[::-1].hex(), 16)

def process(fn):
  fmt = struct.Struct("96s32s256s4s256s")
  with open(fn, "rb") as fi:
    hdr30 = fi.read(0x30) # Top header
    hdr, nonce, modulus, exponent, signature = fmt.unpack(fi.read(fmt.size))
    enc = fi.read() # Everything else is encrypted data
  n,e,ct = s2i(modulus), s2i(exponent), s2i(signature)
  pt =  bytes.fromhex(("%0512X" % pow(ct, e, n)))
  rsa_pad = b"\x00\x01%s\x00" % (b"\xFF"*221) # Padding for 32 bytes of data
  assert pt.startswith(rsa_pad) # Naive padding check
  signed_hash = pt[-32:][::-1]

  hPub = hashlib.sha256(modulus).digest()
  assert hPub == hPub_need

  buf = abX + nonce + abX
  mh = my_SHA256()
  k = b"".join(mh.transform(buf) for i in range(8))
  rc4 = ARC4.new(k)
  rc4.encrypt(b'\x00'*0x200) # Skip 0x200 bytes
  dec = rc4.encrypt(enc)
  with open(fn + ".dec", "wb") as fo: fo.write(dec)
  for cc in range(0, len(dec), 64):
    h = hashlib.sha256(hdr + nonce + dec[:cc]).digest()
    if h == signed_hash:
      print("Hash matched at length 0x%X (%d)" % (cc, cc))
  print("Data entropy: %f" % calcEntropy(dec[:cc]))

def main(argv):
  if len(argv) > 1: process(argv[1])

if __name__=="__main__": main(sys.argv)
