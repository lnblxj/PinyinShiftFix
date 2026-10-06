"""Print annotated AMD64 instructions from an explicit sample RVA; never write files."""
import argparse
import json
from pathlib import Path
import capstone
import pefile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dll', type=Path)
    parser.add_argument('--symbols', required=True, type=Path,
                        help='symbols.json emitted by analyze_sample.py')
    parser.add_argument('--rva', required=True, type=lambda x: int(x, 0))
    parser.add_argument('--length', default=256, type=int)
    args = parser.parse_args()
    if args.rva < 0 or not 1 <= args.length <= 65536:
        parser.error('RVA must be nonnegative and length must be 1..65536')
    pe = pefile.PE(str(args.dll))
    if pe.FILE_HEADER.Machine != 0x8664:
        parser.error('Only AMD64 images are supported')
    section = pe.get_section_by_rva(args.rva)
    if section is None or not section.Characteristics & 0x20000000:
        parser.error('RVA must belong to an executable section')
    limit = section.VirtualAddress + section.SizeOfRawData - args.rva
    if limit <= 0:
        parser.error('RVA has no on-disk section data')
    symbols = json.loads(args.symbols.read_text(encoding='utf-8'))
    by_rva = {}
    for name, values in symbols.items():
        for rva in values:
            by_rva.setdefault(rva, []).append(name)
    base = pe.OPTIONAL_HEADER.ImageBase
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    for ins in decoder.disasm(pe.get_data(args.rva, min(args.length, limit)), base + args.rva):
        annotations = []
        for operand in ins.operands:
            target = None
            if operand.type == capstone.x86.X86_OP_IMM:
                target = operand.imm - base
            elif operand.type == capstone.x86.X86_OP_MEM and operand.mem.base == capstone.x86.X86_REG_RIP:
                target = ins.address + ins.size + operand.mem.disp - base
            annotations.extend(by_rva.get(target, []))
        print(f'{ins.address - base:08X}  {ins.bytes.hex():24s} {ins.mnemonic:8s} {ins.op_str}',
              ' ; '.join(annotations))


if __name__ == '__main__':
    main()
