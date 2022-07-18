import struct, sys, os, binascii

class bitsReader(object):
  def __init__(self, ab):
    self.bits = int(binascii.hexlify(ab[::-1]), 16)
    self.o = 0
  def get(self, n=1):
    self.bits, v = divmod(self.bits, 1<<n)
    return v

def decompress(ab):
  cbUnp, = struct.unpack_from("<L", ab)
  print(". Decompressing %d -> %d, be patient..." % (len(ab), cbUnp))
  br = bitsReader(ab[4:])
  r = bytearray()
  while (br.bits):
    flag = br.get(1)
    if flag:
      ncp = br.get(4)
      if ncp < 3: ncp += 16
      offs = br.get(14)
      ocp = len(r) - offs
      for i in range(ncp): r.append(r[ocp+i])
    else:
      r.append(br.get(8))
  if len(r) != cbUnp: print("? Got %d instead of %d..." % (len(r), cbUnp))
  else: print("+ Unpacked OK")
  return bytes(r)

class Elf64_Shdr(object):
  fmt = struct.Struct("<LLQQQQLLQQ")
  def __init__(self, ab, shoff, iSec):
    self.sh_name, self.sh_type, self.sh_flags, self.sh_addr, self.sh_offset, self.sh_size, self.sh_link, self.sh_info, self.sh_addralign, self.sh_entsize = \
      self.fmt.unpack_from(ab, shoff + iSec*self.fmt.size)

def process(fn):
  print("Processing %s" % fn)
  with open(fn, "rb") as fi: ab = fi.read()
  oELF = ab.find(b'\x7FELF\2\1\1\0')
  if oELF < 0:
    print("- Can't find top ELF")
    return
  print(". ELF at 0x%X" % oELF)
  e_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = \
    struct.unpack_from("<16sHHLQQQLHHHHHH", ab, oELF)
  names = Elf64_Shdr(ab, oELF + e_shoff, e_shstrndx)
  oNames = oELF + names.sh_offset
  
  nPARKING, nXURT = b".PARKING\0", b".XURT\0"
  sPARKING, sXURT = None,None

  for iSec in range(e_shnum):
    sec = Elf64_Shdr(ab, oELF + e_shoff, iSec)
    oN = oNames+sec.sh_name
    if ab[oN:oN+len(nPARKING)] == nPARKING: sPARKING = sec
    if ab[oN:oN+len(nXURT)] == nXURT: sXURT = sec

  base,ext = os.path.splitext(fn)
  if not os.path.isdir(base): os.mkdir(base)
  with open(os.path.join(base, "topELF.bin"), "wb") as fo: fo.write(ab[oELF:])
  
  if sPARKING: 
    print(". Parking: 0x%X+%X" % (oELF+sPARKING.sh_offset, sPARKING.sh_size))
    with open(os.path.join(base, "Parking.bin"), "wb") as fo: fo.write(ab[oELF+sPARKING.sh_offset:oELF+sPARKING.sh_offset+sPARKING.sh_size])
  else: print("- Can't find .PARKING")

  if sXURT: 
    print(". XuRT: 0x%X+%X" % (oELF+sXURT.sh_offset, sXURT.sh_size))
    packed = ab[oELF+sXURT.sh_offset:oELF+sXURT.sh_offset+sXURT.sh_size]
#    with open(os.path.join(base, "XuRT.sect"), "wb") as fo: fo.write(packed)
    plain = decompress(packed)
    with open(os.path.join(base, "XuRT.bin"), "wb") as fo: fo.write(plain)
  else: print("- Can't find .XURT")

def main(argv):
  for fn in argv[1:]: process(fn)

if __name__=="__main__": main(sys.argv)
