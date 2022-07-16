#!/usr/bin/env python3
import argparse
import hashlib
import yaml

from elf import ElfFile, ARCH_ARM

architectures = {
 'arm':   (ARCH_ARM, True),
 'armeb': (ARCH_ARM, False),
}

def writeSymbols(data, arch, segments, symbols, output):
 arch = architectures.get(arch)
 if not arch:
  raise Exception('Invalid architecture')

 elf = ElfFile(arch=arch[0], little=arch[1])

 for seg in segments:
  elf.appendSection(seg['name'], seg['addr'], seg['size'], 'w' in seg['flg'], 'x' in seg['flg'], seg.get('offset'))

 for addr, name in symbols:
  elf.appendSymbol(name, addr)

 output.write(bytes(elf))
 output.write(data)

def getKnownFiles():
 with open('known_files.yaml') as f:
  return yaml.safe_load(f) or []

def findSymbols(input, output):
 data = input.read()
 hash = hashlib.md5(data).hexdigest()

 for known in getKnownFiles():
  if hash == known['hash']:
   print('%s is a known file: %s from %s version %s' % (input.name, known['file'], known['model'], known['version']))
   print('Writing symbols to %s' % output.name)
   writeSymbols(data, known.get('arch', 'arm'), known['segments'], known['symbols'], output)
   print('Done')
   return
 print('Unknown file')

def main():
 parser = argparse.ArgumentParser(description='Tries to add symbols to a binary file')
 parser.add_argument('input', type=argparse.FileType('rb'), help='input file from firmware')
 parser.add_argument('output', type=argparse.FileType('wb'), help='output .elf file')
 args = parser.parse_args()
 findSymbols(args.input, args.output)

if __name__ == '__main__':
 main()
