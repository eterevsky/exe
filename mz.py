from dataclasses import dataclass
import struct
from typing import Self


@dataclass
class MzHeader:
    signature: int = 0x5A4D
    extra_bytes: int = 0
    pages: int = 0
    relocation_items: int = 0
    header_size: int = 0
    minimum_allocation: int = 0
    maximum_allocation: int = 0
    initial_ss: int = 0
    initial_sp: int = 0
    checksum: int = 0
    initial_ip: int = 0
    initial_cs: int = 0
    relocation_table: int = 0
    overlay: int = 0

    @staticmethod
    def parse(data: bytes) -> Self:
        fields = struct.unpack("14H", data)
        return MzHeader(*fields)
    
    def __str__(self) -> str:
        return f"""Signature: {self.signature}
Extra bytes: {self.extra_bytes}
Pages: {self.pages}
Relocation items: {self.relocation_items}
Header size (in paragraphs): {self.header_size}
Minimum allocation: {self.minimum_allocation}
Maximum allocation: {self.maximum_allocation}
Initial SS: {self.initial_ss:04x}
Initial SP: {self.initial_sp:04x}
Checksum: {self.checksum:04x}
Initial IP: {self.initial_ip:04x}
Initial CS: {self.initial_cs:04x}
Relocation table: {self.relocation_table:04x}
Overlay: {self.overlay}
"""
    
    def to_bytes(self) -> bytes:
        return struct.pack("14H",
            self.signature,
            self.extra_bytes,
            self.pages,
            self.relocation_items,
            self.header_size,
            self.minimum_allocation,
            self.maximum_allocation,
            self.initial_ss,
            self.initial_sp,
            self.checksum,
            self.initial_ip,
            self.initial_cs,
            self.relocation_table,
            self.overlay,
        )


class MzBinary:
    def __init__(self):
        self.header = MzHeader(header_size=2, initial_sp=0xb8)
        self.code = b""
    
    def set_code(self, code: bytes):
        self.code = code
    
    def to_bytes(self) -> bytes:
        bin = bytearray(self.header.to_bytes())
        self.header.header_size = (len(bin) + 15) // 16

        bin += b"\0" * (self.header.header_size * 16 - len(bin))

        bin += self.code

        self.header.pages = (len(bin) + 511) // 512
        self.header.extra_bytes = len(bin) % 512

        bin[0:28] = self.header.to_bytes()
        return bytes(bin)
    

def build_mz_stub() -> bytes:
    """Builds a valid MZ file stub in the beginning of PE32 file."""

    binary = MzBinary()
    binary.set_code(bytes([
        0x0e,              # push cs
        0x1f,              # pop ds
        0xba, 0x0e, 0x00,  # mov dx, 0x0e
        0xb4, 0x09,        # mov ah, 0x09
        0xcd, 0x21,        # int 0x21
        0xb8, 0x01, 0x4c,  # mov ax, 0x4c01
        0xcd, 0x21,        # int 0x20
    ]) + b"Can't DOS!\r\n$")

    bin = binary.to_bytes()
    bin += b"\0" * (60 - len(bin))
    bin += b"\x40\x00\x00\x00"

    assert len(bin) == 0x40
    return bin
