from dataclasses import dataclass
from datetime import datetime
import sys
from typing import Self

from hexdump import hexdump
from parse import parse_int, parse_c_string
from pe import CoffHeader, OptionalHeaderStandard, OptionalHeaderWindows, DataDirectories
from mz import MzHeader


SECTION_CHARACTERISTICS = [
    (0x00000000, "RESERVED"),
    (0x00000001, "RESERVED"),
    (0x00000002, "RESERVED"),
    (0x00000004, "RESERVED"),
    (0x00000008, "TYPE_NO_PAD"),
    (0x00000010, "RESERVED"),
    (0x00000020, "CNT_CODE"),
    (0x00000040, "CNT_INITIALIZED_DATA"),
    (0x00000080, "CNT_UNINITIALIZED_DATA"),
    (0x00000100, "LNK_OTHER"),
    (0x00000200, "LNK_INFO"),
    (0x00000400, "RESERVED"),
    (0x00000800, "LNK_REMOVE"),
    (0x00001000, "LNK_COMDAT"),
    (0x00008000, "GPREL"),
    (0x00020000, "MEM_PURGEABLE"),
    (0x00020000, "MEM_16BIT"),
    (0x00040000, "MEM_LOCKED"),
    (0x00080000, "MEM_PRELOAD"),
    (0x00100000, "ALIGN_1BYTES"),
    (0x00200000, "ALIGN_2BYTES"),
    (0x00300000, "ALIGN_4BYTES"),
    (0x00400000, "ALIGN_8BYTES"),
    (0x00500000, "ALIGN_16BYTES"),
    (0x00600000, "ALIGN_32BYTES"),
    (0x00700000, "ALIGN_64BYTES"),
    (0x00800000, "ALIGN_128BYTES"),
    (0x00900000, "ALIGN_256BYTES"),
    (0x00A00000, "ALIGN_512BYTES"),
    (0x00B00000, "ALIGN_1024BYTES"),
    (0x00C00000, "ALIGN_2048BYTES"),
    (0x00D00000, "ALIGN_4096BYTES"),
    (0x00E00000, "ALIGN_8192BYTES"),
    (0x01000000, "LNK_NRELOC_OVFL"),
    (0x02000000, "MEM_DISCARDABLE"),
    (0x04000000, "MEM_NOT_CACHED"),
    (0x08000000, "MEM_NOT_PAGED"),
    (0x10000000, "MEM_SHARED"),
    (0x20000000, "MEM_EXECUTE"),
    (0x40000000, "MEM_READ"),
    (0x80000000, "MEM_WRITE"),
]


@dataclass
class SectionHeader:
    name: str
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    pointer_to_relocations: int
    pointer_to_line_numbers: int
    number_of_relocations: int
    number_of_line_numbers: int
    characteristics: int

    def print_characteristics(self) -> str:
        selected = []
        for flag, name in SECTION_CHARACTERISTICS:
            if self.characteristics & flag:
                selected.append(name)
        return " | ".join(selected)

    @staticmethod
    def parse(data: bytes) -> Self:
        assert len(data) == 40
        return SectionHeader(
            name=data[0:8].decode(),
            virtual_size=parse_int(data[8:12]),
            virtual_address=parse_int(data[12:16]),
            size_of_raw_data=parse_int(data[16:20]),
            pointer_to_raw_data=parse_int(data[20:24]),
            pointer_to_relocations=parse_int(data[24:28]),
            pointer_to_line_numbers=parse_int(data[28:32]),
            number_of_relocations=parse_int(data[32:34]),
            number_of_line_numbers=parse_int(data[34:36]),
            characteristics=parse_int(data[36:40]),
        )

    def __str__(self):
        return f"""Name: {self.name}
Virtual addresses: {self.virtual_address:08x}-{self.virtual_address+self.virtual_size:08x} ({self.virtual_size})
Raw data: {self.pointer_to_raw_data:08x}-{self.pointer_to_raw_data+self.size_of_raw_data:08x} ({self.size_of_raw_data})
Relocations: {self.pointer_to_relocations:08x} ({self.number_of_relocations})
Line numbers: {self.pointer_to_line_numbers:08x} ({self.number_of_line_numbers})
Characteristicts: {self.characteristics:08x} {self.print_characteristics()}
"""


@dataclass
class ImportDirectoryEntry:
    lookup_table_rva: int
    timestamp: int
    forwarder_chain: int
    name_rva: int
    address_table_rva: int

    @staticmethod
    def parse(data: bytes) -> Self:
        assert len(data) == 20
        return ImportDirectoryEntry(
            lookup_table_rva=parse_int(data[0:4]),
            timestamp=parse_int(data[4:8]),
            forwarder_chain=parse_int(data[8:12]),
            name_rva=parse_int(data[12:16]),
            address_table_rva=parse_int(data[16:20]),
        )

    def __str__(self):
        return f"""Import Lookup Table RVA: {self.lookup_table_rva:08x}
TimeStamp: {self.timestamp:08x} ({datetime.fromtimestamp(self.timestamp)})
Forwarder Chain: {self.forwarder_chain}
Name RVA: {self.name_rva:08x}
Import Address Table RVA: {self.address_table_rva:08x}
"""

    def empty(self):
        return (
            self.lookup_table_rva == 0
            and self.timestamp == 0
            and self.forwarder_chain == 0
            and self.name_rva == 0
            and self.address_table_rva == 0
        )


@dataclass
class ImportHint:
    def __init__(self, hint: int, name: str | None):
        self.hint = hint
        self.name = name

    @staticmethod
    def parse(memory: bytes, offset: int) -> Self:
        # hexdump(memory, offset, 32)
        # print()
        hint = parse_int(memory[offset:offset+2])
        name = parse_c_string(memory, offset+2)
        return ImportHint(hint, name)

    def __str__(self):
        if self.name:
            return f"{self.name}@{self.hint}"
        else:
            return str(self.hint)


class DllLookupTable:
    def __init__(self, directory_entry: ImportDirectoryEntry, name: str):
        self.directory_entry = directory_entry
        self.name = name
        self.imports: list[ImportHint] = []

    @staticmethod
    def parse(entry_data: bytes, memory: bytes):
        entry = ImportDirectoryEntry.parse(entry_data)
        if entry.empty():
            return None
        name = parse_c_string(memory, entry.name_rva)
        table = DllLookupTable(entry, name)

        lookup_rva = entry.lookup_table_rva
        while True:
            lookup_entry = parse_int(memory[lookup_rva:lookup_rva+8])
            if lookup_entry == 0:
                break
            if lookup_entry & 0x8000000000000000:
                ordinal = lookup_entry & 0xFFFF
                table.imports.append(ImportHint(ordinal, None))
            else:
                rva = lookup_entry & 0x7FFFFFFF
                table.imports.append(ImportHint.parse(memory, rva))

            lookup_rva += 8

        return table

    def __str__(self):
        s = self.name + "\n"  # + str(self.directory_entry)
        s += f"IAT: {self.directory_entry.address_table_rva:08x}\n\n"
        for item in self.imports:
            s += str(item) + "\n"

        return s


RELOCATION_TYPES = {
0: "IMAGE_REL_BASED_ABSOLUTE",
1: "IMAGE_REL_BASED_HIGH",
2: "IMAGE_REL_BASED_LOW",
3: "IMAGE_REL_BASED_HIGHLOW",
4: "IMAGE_REL_BASED_HIGHADJ",
5: "IMAGE_REL_BASED_ARM_MOV32",
6: "RESERVED",
10: "IMAGE_REL_BASED_DIR64",
}


class RelocationBlock:
    def __init__(self, page_rva: int):
        self.page_rva = page_rva
        self.entries = []

    @staticmethod
    def parse(data: bytes) -> Self:
        page_rva = parse_int(data[0:4])
        block = RelocationBlock(page_rva)
        for offset in range(8, len(data), 2):
            block.entries.append(parse_int(data[offset:offset+2]))
        return block

    def __str__(self):
        s = f"Block RVA {self.page_rva:08x}:"
        for i, entry in enumerate(self.entries):
            if i >= 4:
                s += "\n. . ."
                break
            offset = entry & 0x0fff
            relocation_type = entry // 2**12
            s += f"\n{offset:04x}  {RELOCATION_TYPES[relocation_type]}"
        s += "\n"
        return s


class Relocations:
    def __init__(self):
        self.blocks: list[RelocationBlock] = []

    @staticmethod
    def parse(data: bytes) -> Self:
        relocations = Relocations()
        offset = 0
        while offset < len(data):
            block_len = parse_int(data[offset+4:offset+8])
            block_data = data[offset:offset+block_len]
            relocations.blocks.append(RelocationBlock.parse(block_data))
            offset += block_len
        return relocations

    def __str__(self) -> str:
        s = "\n".join(str(b) for b in self.blocks)
        return s + "\n"


def load_sections(sections: list[SectionHeader], bin: bytes) -> bytes:
    """Emulate loading the application into memory by following section headers."""
    max_memory = max(s.virtual_address + s.virtual_size for s in sections)
    memory = bytearray(max_memory)
    for section in sections:
        size = min(section.virtual_size, section.size_of_raw_data)
        memory[section.virtual_address : section.virtual_address + size] = bin[
            section.pointer_to_raw_data : section.pointer_to_raw_data + size
        ]
    return bytes(memory)


def dump_pe32(bin: bytes):
    pe_offset = parse_int(bin[0x3C:0x40])
    print(f"PE offset ({pe_offset:08x}):")
    hexdump(bin, 0x3C, 4)
    print()

    print("MS-DOS Stub:")
    hexdump(bin, 0, pe_offset)
    print()

    print("Signature (expected: 50 45 00 00):")
    hexdump(bin, pe_offset, 4)
    print()

    print("COFF File Header:")
    hexdump(bin, pe_offset + 4, 20)
    print()

    coff = CoffHeader.parse(bin[pe_offset + 4 : pe_offset + 24])
    print(coff)
    print()
    assert coff.to_bytes() == bin[pe_offset + 4 : pe_offset + 24]

    optional_header_offset = pe_offset + 24
    optional_standard = OptionalHeaderStandard.parse(bin[optional_header_offset:optional_header_offset+28])
    
    print("Optional Header Standard Fields:")
    hexdump(bin, optional_header_offset, optional_standard.size)
    print()
    print(optional_standard)

    
    if optional_standard.version != 2:
        print(f"PE version unsupported")
        exit(0)

    optional_windows = OptionalHeaderWindows.parse(
        bin[optional_header_offset+24:optional_header_offset+112])


    print("Optional Header Windows-Specific Fields:")
    hexdump(bin, optional_header_offset+24, 88)
    print()
    print(optional_windows)

    optional_data_offset = optional_header_offset + 112
    optional_data_length = coff.size_of_optional_header - 112

    assert optional_windows.number_of_rva_and_sizes * 8 == optional_data_length

    print("Optional Header Data Directories:")
    hexdump(bin, optional_data_offset, optional_data_length)
    print()
    directories = DataDirectories.parse(
        bin[optional_data_offset : optional_data_offset + optional_data_length]
    )
    print(directories)

    sections = []
    current_offset = optional_data_offset + optional_data_length
    for isection in range(0, coff.number_of_sections):
        section = SectionHeader.parse(bin[current_offset : current_offset + 40])
        sections.append(section)
        print(section.name, "header:")
        hexdump(bin, current_offset, 40)
        print()
        print(section)
        current_offset += 40

    memory = load_sections(sections, bin)
    print("Used memory:", len(memory))
    print()

    idata_addr = directories.find(".idata")
    print(".idata")
    hexdump(memory, idata_addr.virtual_address, idata_addr.size)
    print()

    imports_table = []

    for start in range(
        idata_addr.virtual_address, idata_addr.virtual_address + idata_addr.size, 20
    ):
        dll_table = DllLookupTable.parse(memory[start : start + 20], memory)
        if dll_table is None:
            break
        print(dll_table)
        imports_table.append(dll_table)


    # iat_addr = directories.find("IAT")
    # print("IAT")
    # hexdump(memory, iat_addr.virtual_address, iat_addr.size)
    # print()

    # iat_table = []

    # for start in range(
    #     iat_addr.virtual_address, iat_addr.virtual_address + iat_addr.size, 20
    # ):
    #     dll_table = DllLookupTable.parse(memory[start : start + 20], memory)
    #     if dll_table is None:
    #         break
    #     print(dll_table)
    #     iat_table.append(dll_table)


    pdata_addr = directories.find(".pdata")
    print(".pdata\n")
    # hexdump(memory, pdata_addr.virtual_address, pdata_addr.size)
    exceptions_table = []

    offset = pdata_addr.virtual_address
    print("begin     end       unwind")
    while offset < pdata_addr.virtual_address + pdata_addr.size:
        begin = parse_int(memory[offset:offset+4])
        end = parse_int(memory[offset+4:offset+8])
        unwind = parse_int(memory[offset+8:offset+12])
        print(f"{begin:08x}  {end:08x}  {unwind:08x}")
        offset += 12

        if offset - pdata_addr.virtual_address > 48:
            print(". . .")
            break

    print()

    reloc_addr = directories.find(".reloc")
    print(".reloc")
    # hexdump(memory, reloc_addr.virtual_address, reloc_addr.size)
    print()

    relocations = Relocations.parse(memory[reloc_addr.virtual_address: reloc_addr.virtual_address + reloc_addr.size])
    print(relocations)


def is_pe32(bin):
    if len(bin) < 0x40:
        return False
    pe_offset = parse_int(bin[0x3C:0x40])
    if len(bin) < pe_offset + 4:
        return False
    return bin[pe_offset:pe_offset+4] == b"PE\x00\x00"


def is_macho(bin):
    if len(bin) < 4:
        return False
    magic = parse_int(bin[:4])
    return magic == 0xfeedfacf


def dump_macho(bin: bytes):
    print("Header")
    hexdump(bin, 0, 0x20)


def is_mz(bin: bytes):
    return bin.startswith(b"MZ")


def dump_mz(bin: bytes):
    mz_header = MzHeader.parse(bin[:28])
    print("MZ Header")
    hexdump(bin, 0, 28)
    print(mz_header)

    print("Remainder of the header")
    hexdump(bin, 28, mz_header.header_size * 16 - 28)
    print()

    print("64 bytes after the header")
    hexdump(bin, mz_header.header_size * 16, 64)


with open(sys.argv[1], "rb") as f:
    bin = f.read()

print(f"Total length: {len(bin)}")
print()

if is_pe32(bin):
    dump_pe32(bin)
elif is_mz(bin):
    dump_mz(bin)
elif is_macho(bin):
    dump_macho(bin)
