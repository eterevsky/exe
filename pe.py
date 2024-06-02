from dataclasses import dataclass
from datetime import datetime
from enum import Enum, Flag
import struct
from typing import Self

from parse import parse_int


class MachineType(Enum):
    IMAGE_FILE_MACHINE_UNKNOWN = 0x0
    IMAGE_FILE_MACHINE_ALPHA = 0x184
    IMAGE_FILE_MACHINE_ALPHA64 = 0x284
    IMAGE_FILE_MACHINE_AM33 = 0x1D3
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    IMAGE_FILE_MACHINE_ARM = 0x1C0
    IMAGE_FILE_MACHINE_ARM64 = 0xAA64
    IMAGE_FILE_MACHINE_ARMNT = 0x1C4
    IMAGE_FILE_MACHINE_AXP64 = 0x284
    IMAGE_FILE_MACHINE_EBC = 0xEBC
    IMAGE_FILE_MACHINE_I386 = 0x14C
    IMAGE_FILE_MACHINE_IA64 = 0x200
    IMAGE_FILE_MACHINE_LOONGARCH32 = 0x6232
    IMAGE_FILE_MACHINE_LOONGARCH64 = 0x6264
    IMAGE_FILE_MACHINE_M32R = 0x9041
    IMAGE_FILE_MACHINE_MIPS16 = 0x266
    IMAGE_FILE_MACHINE_MIPSFPU = 0x366
    IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466
    IMAGE_FILE_MACHINE_POWERPC = 0x1F0
    IMAGE_FILE_MACHINE_POWERPCFP = 0x1F1
    IMAGE_FILE_MACHINE_R4000 = 0x166
    IMAGE_FILE_MACHINE_RISCV32 = 0x5032
    IMAGE_FILE_MACHINE_RISCV64 = 0x5064
    IMAGE_FILE_MACHINE_RISCV128 = 0x5128
    IMAGE_FILE_MACHINE_SH3 = 0x1A2
    IMAGE_FILE_MACHINE_SH3DSP = 0x1A3
    IMAGE_FILE_MACHINE_SH4 = 0x1A6
    IMAGE_FILE_MACHINE_SH5 = 0x1A8
    IMAGE_FILE_MACHINE_THUMB = 0x1C2
    IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169


class Characteristics(Flag):
    IMAGE_FILE_RELOCS_STRIPPED = 0x0001
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008
    IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
    IMAGE_FILE_BYTES_REVERSED_LO = 0x0080
    IMAGE_FILE_32BIT_MACHINE = 0x0100
    IMAGE_FILE_DEBUG_STRIPPED = 0x0200
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400
    IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800
    IMAGE_FILE_SYSTEM = 0x1000
    IMAGE_FILE_DLL = 0x2000
    IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000
    IMAGE_FILE_BYTES_REVERSED_HI = 0x8000


@dataclass
class CoffHeader:
    machine: MachineType = 0
    number_of_sections: int = 0
    time_date_stamp: datetime = datetime.fromtimestamp(0)
    pointer_to_symbol_table: int = 0
    number_of_symbols: int = 0
    size_of_optional_header: int = 0
    characteristics: Characteristics = 0

    @staticmethod
    def parse(data: bytes) -> Self:
        (
            machine,
            number_of_sections,
            time_date_stamp,
            pointer_to_symbol_table,
            number_of_symbols,
            size_of_optional_header,
            characteristics,
        ) = struct.unpack("HHIIIHH", data)
        return CoffHeader(
            machine=MachineType(machine),
            number_of_sections=number_of_sections,
            time_date_stamp=datetime.fromtimestamp(time_date_stamp),
            pointer_to_symbol_table=pointer_to_symbol_table,
            number_of_symbols=number_of_symbols,
            size_of_optional_header=size_of_optional_header,
            characteristics=Characteristics(characteristics),
        )

    def __str__(self):
        return f"""Machine: {self.machine}
NumberOfSections: {self.number_of_sections}
TimeDateStamp: {self.time_date_stamp}
PointerToSymbolTable: {self.pointer_to_symbol_table:08x}
NumberOfSymbols: {self.number_of_symbols}
SizeOfOptionalHeader: {self.size_of_optional_header:04x}
Characteristics: {self.characteristics}"""

    def to_bytes(self) -> bytes:
        try:
            timestamp = int(self.time_date_stamp.timestamp())
        except OSError:
            timestamp = int((self.time_date_stamp - datetime.fromtimestamp(0)).total_seconds())
        return struct.pack(
            "HHIIIHH",
            self.machine.value,
            self.number_of_sections,
            timestamp,
            self.pointer_to_symbol_table,
            self.number_of_symbols,
            self.size_of_optional_header,
            self.characteristics.value,
        )


@dataclass
class OptionalHeaderStandard:
    magic: int = 0x020B
    major_linker_version: int = 0
    minor_linker_version: int = 1
    size_of_code: int = 0
    size_of_initialized_data: int = 0
    size_of_uninitialized_data: int = 0
    address_of_entry_point: int = 0
    base_of_code: int = 0
    base_of_data: int | None = None

    @staticmethod
    def parse(data: bytes) -> Self:
        fields = list(struct.unpack("HBBIIIII", data[:24]))

        if fields[0] == 0x020B:
            fields.append(parse_int(data[24:28]))
        else:
            fields.append(None)

        return OptionalHeaderStandard(*fields)

    def __str__(self):
        return f"""Magic: {self.magic:04x}
Linker version: {self.major_linker_version}.{self.minor_linker_version}
SizeOfCode: {self.size_of_code:08x} ({self.size_of_code})
SizeOfInitializedData: {self.size_of_initialized_data:08x} ({self.size_of_initialized_data})
SizeOfUninitializedData: {self.size_of_uninitialized_data:08x} ({self.size_of_uninitialized_data})
AddressOfEntryPoint: {self.address_of_entry_point:08x}
BaseOfCode: {self.base_of_code:08x}
"""

    @property
    def version(self):
        return self.magic // 256

    @property
    def size(self):
        return 24 if self.magic == 0x020B else 28

    def to_bytes(self) -> bytes:
        assert self.magic == 0x020B
        return struct.pack(
            "HBBIIIII",
            self.magic,
            self.major_linker_version,
            self.minor_linker_version,
            self.size_of_code,
            self.size_of_initialized_data,
            self.size_of_uninitialized_data,
            self.address_of_entry_point,
            self.base_of_code,
        )


class WindowsSubsystem(Enum):
    IMAGE_SUBSYSTEM_UNKNOWN = 0
    IMAGE_SUBSYSTEM_NATIVE = 1
    IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
    IMAGE_SUBSYSTEM_OS2_CUI = 5
    IMAGE_SUBSYSTEM_POSIX_CUI = 7
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9
    IMAGE_SUBSYSTEM_EFI_APPLICATION = 10
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12
    IMAGE_SUBSYSTEM_EFI_ROM = 13
    IMAGE_SUBSYSTEM_XBOX = 14
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16


class DllCharacteristics(Flag):
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
    IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000
    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000


@dataclass
class OptionalHeaderWindows:
    image_base: int = 0x00400000
    section_alignment: int = 4096
    file_alignment: int = 512
    major_operating_system_version: int = 6
    minor_operating_system_version: int = 0
    major_image_version: int = 0
    minor_image_version: int = 0
    major_subsystem_version: int = 6
    minor_subsystem_version: int = 0
    win32_version_value: int = 0
    size_of_image: int = 0
    size_of_headers: int = 0
    check_sum: int = 0
    subsystem: WindowsSubsystem = WindowsSubsystem.IMAGE_SUBSYSTEM_WINDOWS_CUI
    dll_characteristics: DllCharacteristics = DllCharacteristics(0)
    size_of_stack_reserve: int = 2**20
    size_of_stack_commit: int = 4096
    size_of_heap_reserve: int = 0
    size_of_heap_commit: int = 0
    loader_flags: int = 0
    number_of_rva_and_sizes: int = 0

    @staticmethod
    def parse(data: bytes) -> Self:
        assert len(data) == 88

        fields = list(struct.unpack("QIIHHHHHHIIIIHHQQQQII", data))
        fields[13] = WindowsSubsystem(fields[13])
        fields[14] = DllCharacteristics(fields[14])

        return OptionalHeaderWindows(*fields)

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
Subsystem: {self.subsystem}
DllCharacteristics: {self.dll_characteristics}
SizeOfStackReserve: {self.size_of_stack_reserve:016x} ({self.size_of_stack_reserve})
SizeOfStackCommit: {self.size_of_stack_commit:016x} ({self.size_of_stack_commit})
SizeOfHeapReserve: {self.size_of_heap_reserve:016x} ({self.size_of_heap_reserve})
SizeOfHeapCommit: {self.size_of_heap_commit:016x} ({self.size_of_heap_commit})
LoaderFlags (should be 0): {self.loader_flags:08x}
NumberOfRvaAndSizes: {self.number_of_rva_and_sizes}
"""

    def to_bytes(self):
        return struct.pack(
            "QIIHHHHHHIIIIHHQQQQII",
            self.image_base,
            self.section_alignment,
            self.file_alignment,
            self.major_operating_system_version,
            self.minor_operating_system_version,
            self.major_image_version,
            self.minor_image_version,
            self.major_subsystem_version,
            self.minor_subsystem_version,
            self.win32_version_value,
            self.size_of_image,
            self.size_of_headers,
            self.check_sum,
            self.subsystem.value,
            self.dll_characteristics.value,
            self.size_of_stack_reserve,
            self.size_of_stack_commit,
            self.size_of_heap_reserve,
            self.size_of_heap_commit,
            self.loader_flags,
            self.number_of_rva_and_sizes,
        )


@dataclass
class ImageDataDirectory:
    name: str
    virtual_address: int
    size: int

    @staticmethod
    def parse(name: str, data: bytes) -> Self:
        assert len(data) == 8
        virtual_address, size = struct.unpack("II", data)
        return ImageDataDirectory(name, virtual_address, size)

    def __str__(self) -> str:
        return f"{self.name}  {self.virtual_address:08x}-{self.virtual_address+self.size:08x} ({self.size})"

    def to_bytes(self) -> bytes:
        return struct.pack("II", self.virtual_address, self.size)


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

    def add_directory(self, name: str, virtual_address: int, size: int):
        for i, dir_name in enumerate(DATA_DIRECTORIES):
            if i >= len(self.directories):
                self.directories.append(ImageDataDirectory(dir_name, 0, 0))
            if name == dir_name:
                directory = self.directories[i]
                assert directory.virtual_address == 0
                assert directory.size == 0
                directory.virtual_address = virtual_address
                directory.size = size
                return
        raise ValueError("Wrong directory name: " + name)

    def to_bytes(self) -> bytes:
        return b"".join(d.to_bytes() for d in self.directories)

    def num_dirs(self) -> int:
        return len(self.directories)


class SectionFlags(Flag):
    IMAGE_SCN_TYPE_NO_PAD = 0x00000008
    IMAGE_SCN_CNT_CODE = 0x00000020
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
    IMAGE_SCN_LNK_OTHER = 0x00000100
    IMAGE_SCN_LNK_INFO = 0x00000200
    IMAGE_SCN_LNK_REMOVE = 0x00000800
    IMAGE_SCN_LNK_COMDAT = 0x00001000
    IMAGE_SCN_GPREL = 0x00008000
    IMAGE_SCN_MEM_PURGEABLE = 0x00020000
    IMAGE_SCN_MEM_16BIT = 0x00020000
    IMAGE_SCN_MEM_LOCKED = 0x00040000
    IMAGE_SCN_MEM_PRELOAD = 0x00080000
    IMAGE_SCN_ALIGN_1BYTES = 0x00100000
    IMAGE_SCN_ALIGN_2BYTES = 0x00200000
    IMAGE_SCN_ALIGN_4BYTES = 0x00300000
    IMAGE_SCN_ALIGN_8BYTES = 0x00400000
    IMAGE_SCN_ALIGN_16BYTES = 0x00500000
    IMAGE_SCN_ALIGN_32BYTES = 0x00600000
    IMAGE_SCN_ALIGN_64BYTES = 0x00700000
    IMAGE_SCN_ALIGN_128BYTES = 0x00800000
    IMAGE_SCN_ALIGN_256BYTES = 0x00900000
    IMAGE_SCN_ALIGN_512BYTES = 0x00A00000
    IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000
    IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000
    IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000
    IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
    IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
    IMAGE_SCN_MEM_NOT_PAGED = 0x08000000
    IMAGE_SCN_MEM_SHARED = 0x10000000
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000


@dataclass
class SectionHeader:
    name: str
    virtual_size: int = 0
    virtual_address: int = 0
    size_of_raw_data: int = 0
    pointer_to_raw_data: int = 0
    pointer_to_relocations: int = 0
    pointer_to_line_numbers: int = 0
    number_of_relocations: int = 0
    number_of_line_numbers: int = 0
    characteristics: SectionFlags = SectionFlags(0)

    @staticmethod
    def parse(data: bytes) -> Self:
        assert len(data) == 40

        fields = list(struct.unpack("8s6IHHI", data))
        fields[0] = fields[0].decode()
        fields[-1] = SectionFlags(fields[-1])
        return SectionHeader(*fields)

    def __str__(self):
        return f"""Name: {self.name}
Virtual addresses: {self.virtual_address:08x}-{self.virtual_address+self.virtual_size:08x} ({self.virtual_size})
Raw data: {self.pointer_to_raw_data:08x}-{self.pointer_to_raw_data+self.size_of_raw_data:08x} ({self.size_of_raw_data})
Relocations: {self.pointer_to_relocations:08x} ({self.number_of_relocations})
Line numbers: {self.pointer_to_line_numbers:08x} ({self.number_of_line_numbers})
Characteristicts: {self.characteristics}
"""

    def to_bytes(self) -> bytes:
        name = self.name.encode()
        name += b"\x00" * (8 - len(name))
        return struct.pack(
            "8s6IHHI",
            name,
            self.virtual_size,
            self.virtual_address,
            self.size_of_raw_data,
            self.pointer_to_raw_data,
            self.pointer_to_relocations,
            self.pointer_to_line_numbers,
            self.number_of_relocations,
            self.number_of_line_numbers,
            self.characteristics.value,
        )


class Section:
    def __init__(self, name: str):
        self.header = SectionHeader(name)
        self.data = bytearray()

    def header_to_bytes(self) -> bytes:
        self.header.virtual_size = len(self.data)
        self.header.size_of_raw_data = (len(self.data) + 511) // 512 * 512
        return self.header.to_bytes()
