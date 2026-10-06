"""Read-only sample analysis; optional Microsoft symbol download and offline patch copy."""
import argparse
import hashlib
import json
import pathlib
import struct
import urllib.request
import uuid
import pefile

def require(ok, message):
    if not ok:
        raise ValueError(message)

def pdb_streams(data):
    require(data.startswith(b'Microsoft C/C++ MSF 7.00\r\n'), 'Unsupported PDB')
    bs, _, _, size, _, block_map = struct.unpack_from('<6I', data, 32)
    require(512 <= bs <= 65536 and 0 < size <= len(data), 'Invalid MSF header')
    def blocks(index, offset, length):
        require(0 <= length <= len(data), 'Invalid stream size')
        result = bytearray()
        for i in range((length + bs - 1) // bs):
            block = struct.unpack_from('<I', index, offset + i * 4)[0]
            chunk = data[block * bs:(block + 1) * bs]
            require(len(chunk) == bs, 'Truncated MSF block')
            result.extend(chunk)
        return bytes(result[:length])
    require((size + bs - 1) // bs * 4 <= bs, 'Unsupported large block map')
    directory = blocks(data, block_map * bs, size)
    count = struct.unpack_from('<I', directory)[0]
    require(count <= len(directory) // 4 - 1, 'Invalid stream count')
    sizes = struct.unpack_from('<' + 'I' * count, directory, 4)
    cursor = 4 + count * 4
    streams = []
    for length in sizes:
        if length == 0xffffffff:
            streams.append(b'')
            continue
        streams.append(blocks(directory, cursor, length))
        cursor += (length + bs - 1) // bs * 4
    return streams

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('dll', type=pathlib.Path)
    ap.add_argument('--pdb', type=pathlib.Path, help='Use local matching PDB')
    ap.add_argument('--download-symbols', action='store_true')
    ap.add_argument('--out', required=True, type=pathlib.Path, help='New output directory')
    ap.add_argument('--emit-patched-copy', action='store_true', help='Write an offline copy only')
    args = ap.parse_args()
    require(not args.out.exists(), 'Output directory must not already exist')
    raw = args.dll.read_bytes()
    pe = pefile.PE(data=raw)
    require(pe.FILE_HEADER.Machine == 0x8664 and pe.OPTIONAL_HEADER.Magic == 0x20b, 'AMD64 PE required')
    debug = [pe.get_data(e.struct.AddressOfRawData, e.struct.SizeOfData)
             for e in pe.DIRECTORY_ENTRY_DEBUG if e.struct.Type == 2]
    rsds = [d for d in debug if d.startswith(b'RSDS')]
    require(len(rsds) == 1, 'Expected unique RSDS record')
    guid, age = rsds[0][4:20], struct.unpack_from('<I', rsds[0], 20)[0]
    name = rsds[0][24:].split(b'\0')[0].decode().replace('\\', '/').split('/')[-1]
    require(name.lower() == 'inputservice.pdb', 'Unexpected PDB name')
    identity = uuid.UUID(bytes_le=guid).hex.upper() + format(age, 'X')
    url = f'https://msdl.microsoft.com/download/symbols/InputService.pdb/{identity}/InputService.pdb'
    if args.pdb:
        pdb = args.pdb.read_bytes()
    else:
        require(args.download_symbols, 'Provide --pdb or --download-symbols')
        with urllib.request.urlopen(url, timeout=60) as response:
            pdb = response.read(128 * 1024 * 1024 + 1)
        require(len(pdb) <= 128 * 1024 * 1024, 'PDB too large')
    streams = pdb_streams(pdb)
    require(streams[1][12:28] == guid, 'PDB GUID mismatch')
    require(struct.unpack_from('<I', streams[3], 8)[0] == age, 'DBI age mismatch')
    records = streams[struct.unpack_from('<H', streams[3], 20)[0]]
    symbols, pos = {}, 0
    while pos < len(records):
        length, kind = struct.unpack_from('<HH', records, pos)
        end = pos + length + 2
        require(length >= 2 and end <= len(records), 'Malformed symbol record')
        if kind == 0x110e:
            flags, offset, segment = struct.unpack_from('<IIH', records, pos + 4)
            name = records[pos + 14:end].split(b'\0')[0].decode('ascii')
            if 1 <= segment <= len(pe.sections):
                symbols.setdefault(name, set()).add(pe.sections[segment - 1].VirtualAddress + offset)
        pos = end
    def symbol(name):
        values = symbols.get(name, set())
        require(len(values) == 1, f'Missing or ambiguous symbol: {name}')
        return next(iter(values))
    table = symbol('?cmds_HwKbdDn_Pinyin_Shift@ChxIME@@3QBUVKeyCommandEntry@1@B')
    toggle, insert = symbol('ImeCommandID_ToggleShape'), symbol('ImeCommandID_InsertSymbol')
    for rva in (table, toggle, insert):
        section = pe.get_section_by_rva(rva)
        require(section is not None and not section.Characteristics & 0xa0000000, 'Expected read-only non-code section')
    require(pe.get_data(toggle, 16).hex() == 'db61c6e17a3dc04fb09a94036132fb65', 'Toggle GUID changed')
    require(pe.get_data(insert, 16).hex() == '2c2a80ef9c111d4d85dac00836478f4c', 'Insert GUID changed')
    slot = table + 8
    require(pe.get_data(table, 8).hex() == '2000200000000000', 'Key record changed')
    require(struct.unpack('<Q', pe.get_data(table + 16, 8))[0] == 2, 'Record flags changed')
    relocations = [e.type for block in pe.DIRECTORY_ENTRY_BASERELOC for e in block.entries if e.rva == slot]
    require(relocations == [10], 'Missing or ambiguous DIR64 relocation')
    base = pe.OPTIONAL_HEADER.ImageBase
    require(struct.unpack('<Q', pe.get_data(slot, 8))[0] == base + toggle, 'Supply an original, unpatched sample')
    offset = pe.get_offset_from_rva(slot)
    patched = bytearray(raw)
    struct.pack_into('<Q', patched, offset, base + insert)
    checksum_offset = pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum')
    checksum = pefile.PE(data=patched).generate_checksum()
    struct.pack_into('<I', patched, checksum_offset, checksum)
    changes = [i for i, (a, b) in enumerate(zip(raw, patched)) if a != b]
    require(all(offset <= i < offset + 8 or checksum_offset <= i < checksum_offset + 4 for i in changes), 'Unexpected diff')
    report = dict(source=str(args.dll.resolve()), original_sha256=hashlib.sha256(raw).hexdigest().upper(),
                  patched_sha256=hashlib.sha256(patched).hexdigest().upper(), pdb_url=url,
                  pdb_sha256=hashlib.sha256(pdb).hexdigest(), table_rva=hex(table), pointer_file_offset=hex(offset),
                  toggle_rva=hex(toggle), insert_rva=hex(insert), changed_offsets=[hex(i) for i in changes],
                  static_validation='passed', runtime_validation='NOT PERFORMED')
    args.out.mkdir(parents=True)
    (args.out / 'analysis.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    (args.out / 'symbols.json').write_text(json.dumps({k: sorted(v) for k, v in symbols.items()}, indent=2), encoding='utf-8')
    if args.download_symbols and not args.pdb:
        (args.out / 'InputService.pdb').write_bytes(pdb)
    if args.emit_patched_copy:
        (args.out / 'InputService.offline-patched.dll').write_bytes(patched)
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
