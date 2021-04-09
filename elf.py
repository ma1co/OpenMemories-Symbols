from makeelf.elf import *
from makeelf.elf import _Strtab, _Symtab

class ElfFile:
 def __init__(self):
  self.elf = Elf32(Ehdr=Elf32_Ehdr(
   e_ident=Elf32_e_ident(EI_DATA=ELFDATA.ELFDATA2LSB),
   e_type=ET.ET_EXEC,
   e_machine=EM.EM_ARM,
   e_shoff=len(Elf32_Ehdr()),
   e_shentsize=len(Elf32_Shdr()),
   e_shstrndx=1,
   little=True,
  ))

  self.shstrtab = _Strtab()
  self.strtab = _Strtab()
  self.symtab = _Symtab()

  self._appendSection()
  self._appendSection(name='.shstrtab', type=SHT.SHT_STRTAB, data=self.shstrtab)
  self._appendSection(name='.strtab', type=SHT.SHT_STRTAB, data=self.strtab)
  self._appendSection(name='.symtab', type=SHT.SHT_SYMTAB, link=2, entsize=len(Elf32_Sym()), data=self.symtab)

 def _appendSection(self, name=None, type=0, flags=0, addr=0, offset=0, size=0, link=0, entsize=0, data=b''):
  name = self.shstrtab.append(name) if name is not None else 0
  self.elf.Shdr_table.append(Elf32_Shdr(
   sh_name=name,
   sh_type=type,
   sh_flags=flags,
   sh_addr=addr,
   sh_offset=offset,
   sh_size=size,
   sh_link=link,
   sh_entsize=entsize,
   little=True,
  ))
  self.elf.sections.append(data)

 def _appendSymbol(self, name=None, addr=0, section=0):
  name = self.strtab.append(name) if name is not None else 0
  self.symtab.append(Elf32_Sym(st_name=name, st_value=addr, st_shndx=section, little=True))

 def _findSection(self, addr):
  for i, shdr in enumerate(self.elf.Shdr_table):
   if shdr.sh_type == SHT.SHT_PROGBITS or shdr.sh_type == SHT.SHT_NOBITS:
    if shdr.sh_addr <= addr < shdr.sh_addr + shdr.sh_size:
     return i
  return 0

 def appendSection(self, name, addr, size, w=False, x=False, offset=None):
  type = SHT.SHT_PROGBITS if offset is not None else SHT.SHT_NOBITS
  flags = SHF.SHF_ALLOC + (w and SHF.SHF_WRITE) + (x and SHF.SHF_EXECINSTR)
  self._appendSection(name=name, type=type, flags=flags, addr=addr, offset=offset or 0, size=size)

 def appendSymbol(self, name, addr):
  section = self._findSection(addr)
  self._appendSymbol(name=name, addr=addr, section=section)

 def __bytes__(self):
  self.elf.Ehdr.e_shnum = len(self.elf.Shdr_table)
  offsets = [shdr.sh_offset for shdr in self.elf.Shdr_table]

  cursor = len(self.elf.Ehdr) + len(self.elf.Shdr_table) * len(Elf32_Shdr())
  for i, shdr in enumerate(self.elf.Shdr_table):
   shdr.sh_offset += cursor
   if shdr.sh_type == SHT.SHT_STRTAB or shdr.sh_type == SHT.SHT_SYMTAB:
    shdr.sh_size = len(self.elf.sections[i])
   if shdr.sh_type == SHT.SHT_SYMTAB:
    shdr.sh_info = len(self.elf.sections[i]) // len(Elf32_Sym())
   cursor += len(self.elf.sections[i])
   if cursor % 0x10:
    cursor += 0x10 - cursor % 0x10

  out = bytes(self.elf)

  for shdr, offset in zip(self.elf.Shdr_table, offsets):
   shdr.sh_offset = offset

  return out
