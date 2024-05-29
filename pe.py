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
        return struct.pack(
            "HHIIIHH",
            self.machine.value,
            self.number_of_sections,
            int(self.time_date_stamp.timestamp()),
            self.pointer_to_symbol_table,
            self.number_of_symbols,
            self.size_of_optional_header,
            self.characteristics.value,
        )


@dataclass
class OptionalHeaderStandard:
    start_offset: int = 0
    magic: int = 0x020B
    major_linker_version: int = 0
    minor_linker_version: int = 1
    size_of_code: int = 0
    size_of_initialized_data: int = 0
    size_of_uninitialized_data: int = 0
    address_of_entry_point: int = 0
    base_of_code: int = 0

    @staticmethod
    def parse(bin: bytes, offset: int) -> Self:
        (
            magic,
            major_linker_version,
            minor_linker_version,
            size_of_code,
            size_of_initialized_data,
            size_of_uninitialized_data,
            address_of_entry_point,
            base_of_code,
        ) = struct.unpack("HBBIIIII", bin[offset : offset + 24])

        return OptionalHeaderStandard(
            start_offset=offset,
            magic=magic,
            major_linker_version=major_linker_version,
            minor_linker_version=minor_linker_version,
            size_of_code=size_of_code,
            size_of_initialized_data=size_of_initialized_data,
            size_of_uninitialized_data=size_of_uninitialized_data,
            address_of_entry_point=address_of_entry_point,
            base_of_code=base_of_code,
        )

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
