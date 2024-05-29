from hexdump import hexdump
import mz

binary = mz.MzBinary()
binary.set_code(bytes([
    0x0e,              # push cs
    0x1f,              # pop ds
    0xba, 0x0e, 0x00,  # mov dx, 0x0d
    0xb4, 0x09,        # mov ah, 0x09
    0xcd, 0x21,        # int 0x21
    0xb8, 0x00, 0x4c,  # mov ax, 0x4c00
    0xcd, 0x21,        # int 0x20
]) + b"Hello, world!$")

bin = binary.to_bytes()
hexdump(bin)

with open("hello_mz.exe", "wb") as f:
    f.write(bin)
