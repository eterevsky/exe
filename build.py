from datetime import datetime

from hexdump import hexdump
import pe

MZ_PREAMBLE = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\x8b\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L\xcd!This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00"

PE_SIGNATURE = b"PE\x00\x00"

# Need to populate `size_of_optional_header` later
coff = pe.CoffHeader(
    machine=pe.MachineType.IMAGE_FILE_MACHINE_AMD64,
    number_of_sections=1,
    time_date_stamp=datetime.now(),
    characteristics=pe.Characteristics.IMAGE_FILE_RELOCS_STRIPPED
    | pe.Characteristics.IMAGE_FILE_EXECUTABLE_IMAGE
    | pe.Characteristics.IMAGE_FILE_LARGE_ADDRESS_AWARE,
)

optional_standard = pe.OptionalHeaderStandard()
optional_windows = pe.OptionalHeaderWindows()

bin = bytearray(MZ_PREAMBLE)
pe_signature_offset = len(bin)
bin += PE_SIGNATURE
coff_offset = len(bin)
bin += coff.to_bytes()
optional_standard_offset = len(bin)
bin += optional_standard.to_bytes()
optional_windows_offset = len(bin)
bin += optional_windows.to_bytes()
pad_offset = len(bin)
padded_header_size = (len(bin) + 511) // 512 * 512
bin += b"\0" * (padded_header_size - len(bin))

optional_windows.size_of_headers = len(bin)
optional_windows_bytes = optional_windows.to_bytes()
bin[
    optional_standard_offset : optional_standard_offset + len(optional_windows_bytes)
] = optional_windows_bytes

print("MS-DOS stub")
print(hexdump(bin, 0, pe_signature_offset))
print()

print("PE signature")
print(hexdump(bin, pe_signature_offset, coff_offset - pe_signature_offset))
print()

print("COFF")
print(hexdump(bin, coff_offset, optional_standard_offset - coff_offset))
print()

print("Optional Header Standard Fields")
print(
    hexdump(
        bin,
        optional_standard_offset,
        optional_windows_offset - optional_standard_offset,
    )
)
print()

print("Optional Header Windows Fields")
print(hexdump(bin, optional_windows_offset, pad_offset - optional_windows_offset))

print()
print("Everything:")
print(hexdump(bin))
