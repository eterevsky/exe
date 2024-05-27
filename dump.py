from dataclasses import dataclass
from datetime import datetime
import sys
from typing import Self


def parse_int(data: bytes) -> int:
    return int.from_bytes(data, "little")


def hexdump(data: bytes, offset: int, length: int):
    p = (offset // 16) * 16
    lines = []
    while p < offset + length:
        s = f"{p:08x} "
        for i in range(0, 8):
            if offset <= p + i < offset + length:
                s += f" {data[p + i]:02x}"
            else:
                s += "   "
        s += " "
        for i in range(8, 16):
            if offset <= p + i < offset + length:
                s += f" {data[p + i]:02x}"
            else:
                s += "   "

        s += "  |"
        for i in range(16):
            if offset <= p + i < offset + length:
                b = data[p + i]
                if 0x20 <= b < 0x7F:
                    s += chr(b)
                else:
                    s += "."
            else:
                s += " "
        s += "|"

        lines.append(s)

        p += 16

    return "\n".join(lines)


CHARACTERISTICS = [
    (0x0001, "RELOCS_STRIPPED"),
    (0x0002, "EXECUTABLE_IMAGE"),
    (0x0004, "LINE_NUMS_STRIPPED"),
    (0x0008, "LOCAL_SYMS_STRIPPED"),
    (0x0010, "AGGRESSIVE_WS_TRIM"),
    (0x0020, "LARGE_ADDRESS_AWARE"),
    (0x0040, "RESERVED"),
    (0x0080, "BYTES_REVERSED_LO"),
    (0x0100, "32BIT_MACHINE"),
    (0x0200, "DEBUG_STRIPPED"),
    (0x0400, "REMOVABLE_RUN_FROM_SWAP"),
    (0x0800, "NET_RUN_FROM_SWAP"),
    (0x1000, "SYSTEM"),
    (0x2000, "DLL"),
    (0x4000, "UP_SYSTEM_ONLY"),
    (0x8000, "BYTES_REVERSED_HI"),
]

MACHINES = {
    0x0: "MACHINE_UNKNOWN",
    0x184: "MACHINE_ALPHA",
    0x284: "MACHINE_ALPHA64",
    0x1D3: "MACHINE_AM33",
    0x8664: "MACHINE_AMD64",
    0x1C0: "MACHINE_ARM",
    0xAA64: "MACHINE_ARM64",
    0x1C4: "MACHINE_ARMNT",
    0x284: "MACHINE_AXP64",
    0xEBC: "MACHINE_EBC",
    0x14C: "MACHINE_I386",
    0x200: "MACHINE_IA64",
    0x6232: "MACHINE_LOONGARCH32",
    0x6264: "MACHINE_LOONGARCH64",
    0x9041: "MACHINE_M32R",
    0x266: "MACHINE_MIPS16",
    0x366: "MACHINE_MIPSFPU",
    0x466: "MACHINE_MIPSFPU16",
    0x1F0: "MACHINE_POWERPC",
    0x1F1: "MACHINE_POWERPCFP",
    0x166: "MACHINE_R4000",
    0x5032: "MACHINE_RISCV32",
    0x5064: "MACHINE_RISCV64",
    0x5128: "MACHINE_RISCV128",
    0x1A2: "MACHINE_SH3",
    0x1A3: "MACHINE_SH3DSP",
    0x1A6: "MACHINE_SH4",
    0x1A8: "MACHINE_SH5",
    0x1C2: "MACHINE_THUMB",
    0x169: "MACHINE_WCEMIPSV2",
}


@dataclass
class CoffHeader:
    machine: int
    number_of_sections: int
    time_date_stamp: int
    pointer_to_symbol_table: int
    number_of_symbols: int
    size_of_optional_header: int
    characteristics: int

    @staticmethod
    def parse(data: bytes) -> Self:
        return CoffHeader(
            machine=parse_int(data[0:2]),
            number_of_sections=parse_int(data[2:4]),
            time_date_stamp=parse_int(data[4:8]),
            pointer_to_symbol_table=parse_int(data[8:12]),
            number_of_symbols=parse_int(data[12:16]),
            size_of_optional_header=parse_int(data[16:18]),
            characteristics=parse_int(data[18:20]),
        )

    def print_characteristics(self):
        selected = []
        for flag, name in CHARACTERISTICS:
            if self.characteristics & flag:
                selected.append(name)
        return " | ".join(selected)

    def __str__(self):
        return f"""Machine: 0x{self.machine:02x}  {MACHINES.get(self.machine)}
NumberOfSections: {self.number_of_sections}
TimeDateStamp: {datetime.fromtimestamp(self.time_date_stamp)}
PointerToSymbolTable: {self.pointer_to_symbol_table:08x}
NumberOfSymbols: {self.number_of_symbols}
SizeOfOptionalHeader: {self.size_of_optional_header:04x}
Characteristics: {self.characteristics:04x}  {self.print_characteristics()}"""


@dataclass
class OptionalStandard:
    magic: int
    major_linker_version: int
    minor_linker_version: int
    size_of_code: int
    size_of_initialized_data: int
    size_of_uninitialized_data: int
    address_of_entry_point: int
    base_of_code: int

    @staticmethod
    def parse(data: bytes) -> Self:
        return OptionalStandard(
            magic=parse_int(data[0:2]),
            major_linker_version=data[2],
            minor_linker_version=data[3],
            size_of_code=parse_int(data[4:8]),
            size_of_initialized_data=parse_int(data[8:12]),
            size_of_uninitialized_data=parse_int(data[12:16]),
            address_of_entry_point=parse_int(data[16:20]),
            base_of_code=parse_int(data[20:24]),
        )

    def __str__(self):
        return f"""Magic: {self.magic:02x}
Linker version: {self.major_linker_version}.{self.minor_linker_version}
SizeOfCode: {self.size_of_code:08x} ({self.size_of_code})
SizeOfInitializedData: {self.size_of_initialized_data:08x} ({self.size_of_initialized_data})
SizeOfUninitializedData: {self.size_of_uninitialized_data:08x} ({self.size_of_uninitialized_data})
AddressOfEntryPoint: {self.address_of_entry_point:08x}
BaseOfCode: {self.base_of_code:08x}
"""


SUBSYSTEMS = {
    0: "UNKNOWN",
    1: "NATIVE",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
    5: "OS2_CUI",
    7: "POSIX_CUI",
    8: "NATIVE_WINDOWS",
    9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER",
    13: "EFI_ROM",
    14: "XBOX",
    16: "WINDOWS_BOOT_APPLICATION",
}

DLL_CHARACTERISTICS = [
    (0x0001, "RESERVED"),
    (0x0002, "RESERVED"),
    (0x0004, "RESERVED"),
    (0x0008, "RESERVED"),
    (0x0020, "DLLCHARACTERISTICS_HIGH_ENTROPY_VA"),
    (0x0040, "DLLCHARACTERISTICS_DYNAMIC_BASE"),
    (0x0080, "DLLCHARACTERISTICS_FORCE_INTEGRITY"),
    (0x0100, "DLLCHARACTERISTICS_NX_COMPAT"),
    (0x0200, "DLLCHARACTERISTICS_NO_ISOLATION"),
    (0x0400, "DLLCHARACTERISTICS_NO_SEH"),
    (0x0800, "DLLCHARACTERISTICS_NO_BIND"),
    (0x1000, "DLLCHARACTERISTICS_APPCONTAINER"),
    (0x2000, "DLLCHARACTERISTICS_WDM_DRIVER"),
    (0x4000, "DLLCHARACTERISTICS_GUARD_CF"),
    (0x8000, "DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"),
]


@dataclass
class OptionalWindows:
    image_base: int
    section_alignment: int
    file_alignment: int
    major_operating_system_version: int
    minor_operating_system_version: int
    major_image_version: int
    minor_image_version: int
    major_subsystem_version: int
    minor_subsystem_version: int
    win32_version_value: int
    size_of_image: int
    size_of_headers: int
    check_sum: int
    subsystem: int
    dll_characteristics: int
    size_of_stack_reserve: int
    size_of_stack_commit: int
    size_of_heap_reserve: int
    size_of_heap_commit: int
    loader_flags: int
    number_of_rva_and_sizes: int

    def print_dll_characteristics(self) -> str:
        selected = []
        for flag, name in DLL_CHARACTERISTICS:
            if self.dll_characteristics & flag:
                selected.append(name)
        return " | ".join(selected)

    @staticmethod
    def parse(data: bytes) -> Self:
        assert len(data) == 88
        return OptionalWindows(
            image_base=parse_int(data[0:8]),
            section_alignment=parse_int(data[8:12]),
            file_alignment=parse_int(data[12:16]),
            major_operating_system_version=parse_int(data[16:18]),
            minor_operating_system_version=parse_int(data[18:20]),
            major_image_version=parse_int(data[20:22]),
            minor_image_version=parse_int(data[22:24]),
            major_subsystem_version=parse_int(data[24:26]),
            minor_subsystem_version=parse_int(data[26:28]),
            win32_version_value=parse_int(data[28:32]),
            size_of_image=parse_int(data[32:36]),
            size_of_headers=parse_int(data[36:40]),
            check_sum=parse_int(data[40:44]),
            subsystem=parse_int(data[44:46]),
            dll_characteristics=parse_int(data[46:48]),
            size_of_stack_reserve=parse_int(data[48:56]),
            size_of_stack_commit=parse_int(data[56:64]),
            size_of_heap_reserve=parse_int(data[64:72]),
            size_of_heap_commit=parse_int(data[72:80]),
            loader_flags=parse_int(data[80:84]),
            number_of_rva_and_sizes=parse_int(data[84:88]),
        )

    def __str__(self):
        return f"""ImageBase: {self.image_base:016x}
SectionAlignment: {self.section_alignment:08x}
FileAlignment: {self.file_alignment:08x}
OperatingSystemVersion: {self.major_operating_system_version}.{self.minor_operating_system_version}
ImageVersion: {self.major_image_version}.{self.minor_image_version}
SubsystemVersion: {self.major_subsystem_version}.{self.minor_subsystem_version}
Win32VersionValue (should be 0): {self.win32_version_value:08x}
SizeOfImage: {self.size_of_image:08x} ({self.size_of_image})
SizeOfHeaders: {self.size_of_headers:08x} ({self.size_of_headers})
CheckSum: {self.check_sum:08x}
Subsystem: {self.subsystem:04x}  {SUBSYSTEMS.get(self.subsystem)}
DllCharacteristics: {self.dll_characteristics:04x} {self.print_dll_characteristics()}
SizeOfStackReserve: {self.size_of_stack_reserve:016x} ({self.size_of_stack_reserve})
SizeOfStackCommit: {self.size_of_stack_commit:016x} ({self.size_of_stack_commit})
SizeOfHeapReserve: {self.size_of_heap_reserve:016x} ({self.size_of_heap_reserve})
SizeOfHeapCommit: {self.size_of_heap_commit:016x} ({self.size_of_heap_commit})
LoaderFlags (should be 0): {self.loader_flags:08x}
NumberOfRvaAndSizes: {self.number_of_rva_and_sizes}
"""


@dataclass
class ImageDataDirectory:
    name: str
    virtual_address: int
    size: int

    @staticmethod
    def parse(name: str, data: bytes) -> Self:
        assert len(data) == 8
        return ImageDataDirectory(
            name=name,
            virtual_address=parse_int(data[0:4]),
            size=parse_int(data[4:8]),
        )

    def __str__(self) -> str:
        return f"{self.name}  {self.virtual_address:08x}-{self.virtual_address+self.size:08x} ({self.size})"


DATA_DIRECTORIES = [
    ".edata",
    ".idata",
    ".rsrc",
    ".pdata",
    "Certificate",
    ".reloc",
    ".debug",
    "Reserved",
    "Global",
    ".tls",
    "Load Config",
    "Bound Import",
    "IAT",
    "Delay Import Descriptor",
    ".cormeta",
    "Reserved",
]


class DataDirectories:
    def __init__(self, directories: list[ImageDataDirectory]):
        self.directories = directories

    @staticmethod
    def parse(data: bytes) -> Self:
        n = len(data) // 8
        directories = []
        for i in range(n):
            name = DATA_DIRECTORIES[i]
            directories.append(ImageDataDirectory.parse(name, data[i * 8 : i * 8 + 8]))
        return DataDirectories(directories)

    def __str__(self):
        return "\n".join(str(d) for d in self.directories) + "\n"

    def find(self, name: str) -> ImageDataDirectory | None:
        for d in self.directories:
            if d.name == name:
                return d
        return None


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


def parse_c_string(data: bytes, start: int) -> str:
    end = data.index(0, start)
    return data[start:end].decode()


@dataclass
class ImportHint:
    def __init__(self, hint: int, name: str | None):
        self.hint = hint
        self.name = name
    
    @staticmethod
    def parse(memory: bytes, offset: int) -> Self:
        # print(hexdump(memory, offset, 32))
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


with open(sys.argv[1], "rb") as f:
    bin = f.read()

print(f"Total length: {len(bin)}")
print()

pe_offset = parse_int(bin[0x3C:0x40])
print(f"PE offset ({pe_offset:08x}):")
print(hexdump(bin, 0x3C, 4))
print()

print("MS-DOS Stub:")
print(hexdump(bin, 0, pe_offset))
print()

print("Signature (expected: 50 45 00 00):")
print(hexdump(bin, pe_offset, 4))
print()

print("COFF File Header:")
print(hexdump(bin, pe_offset + 4, 20))
print()

coff = CoffHeader.parse(bin[pe_offset + 4 : pe_offset + 24])
print(coff)
print()

optional_header_offset = pe_offset + 24
pe_magic = int.from_bytes(
    bin[optional_header_offset : optional_header_offset + 2], "little"
)
if pe_magic not in (0x10B, 0x20B):
    print(f"PE Magic Number: {pe_magic:04x} - unsupported")
    exit(0)
print(f"PE Magic Number: {pe_magic:04x}", "PE32" if pe_magic == 0x10B else "PE32+")
print()

if pe_magic == 0x10B:
    optional_standard_length = 28
    optional_windows_offset = optional_header_offset + 28
    optional_windows_length = 68
    optional_data_offset = optional_header_offset + 96
    optional_data_length = coff.size_of_optional_header - 96
else:
    optional_standard_length = 24
    optional_windows_offset = optional_header_offset + 24
    optional_windows_length = 88
    optional_data_offset = optional_header_offset + 112
    optional_data_length = coff.size_of_optional_header - 112

print("Optional Header Standard Fields:")
print(hexdump(bin, optional_header_offset, optional_standard_length))
print()
optional_standard = OptionalStandard.parse(
    bin[optional_header_offset : optional_header_offset + optional_standard_length]
)
print(optional_standard)

print("Optional Header Windows-Specific Fields:")
print(hexdump(bin, optional_windows_offset, optional_windows_length))
print()
optional_windows = OptionalWindows.parse(
    bin[optional_windows_offset : optional_windows_offset + optional_windows_length]
)
print(optional_windows)

assert optional_windows.number_of_rva_and_sizes * 8 == optional_data_length

print("Optional Header Data Directories:")
print(hexdump(bin, optional_data_offset, optional_data_length))
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
    print(hexdump(bin, current_offset, 40))
    print()
    print(section)
    current_offset += 40

memory = load_sections(sections, bin)
print("Used memory:", len(memory))
print()

idata_addr = directories.find(".idata")
print(".idata")
print(hexdump(memory, idata_addr.virtual_address, idata_addr.size))
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
# print(hexdump(memory, iat_addr.virtual_address, iat_addr.size))
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
# print(hexdump(memory, pdata_addr.virtual_address, pdata_addr.size))
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
# print(hexdump(memory, reloc_addr.virtual_address, reloc_addr.size))
print()

relocations = Relocations.parse(memory[reloc_addr.virtual_address: reloc_addr.virtual_address + reloc_addr.size])
print(relocations)
