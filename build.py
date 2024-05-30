from datetime import datetime

from hexdump import hexdump
import mz
import pe

mz_preamble = mz.build_mz_stub()

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
data_directories = pe.DataDirectories([])
optional_windows.number_of_rva_and_sizes = data_directories.num_dirs()

text_section = pe.Section(".text")
text_section.header.characteristics = (
    pe.SectionFlags.IMAGE_SCN_CNT_CODE
    | pe.SectionFlags.IMAGE_SCN_CNT_INITIALIZED_DATA
    | pe.SectionFlags.IMAGE_SCN_MEM_EXECUTE
    | pe.SectionFlags.IMAGE_SCN_MEM_READ
    | pe.SectionFlags.IMAGE_SCN_MEM_WRITE
)

# By this point the objects for different headers are prepared and the only
# parts to be updated are

bin = bytearray(mz_preamble)
pe_signature_offset = len(bin)
bin += PE_SIGNATURE
coff_offset = len(bin)
bin += coff.to_bytes()
optional_standard_offset = len(bin)
bin += optional_standard.to_bytes()
optional_windows_offset = len(bin)
bin += optional_windows.to_bytes()
data_directories_offset = len(bin)
bin += data_directories.to_bytes()

pad_offset = len(bin)
padded_header_size = (len(bin) + 511) // 512 * 512
bin += b"\0" * (padded_header_size - len(bin))

optional_windows.size_of_headers = len(bin)
optional_windows_bytes = optional_windows.to_bytes()
bin[optional_windows_offset : optional_windows_offset + len(optional_windows_bytes)] = (
    optional_windows_bytes
)

print("MS-DOS stub")
hexdump(bin, 0, pe_signature_offset)
print()

print("PE signature")
hexdump(bin, pe_signature_offset, coff_offset - pe_signature_offset)
print()

print("COFF")
hexdump(bin, coff_offset, optional_standard_offset - coff_offset)
print()

print("Optional Header Standard Fields")
hexdump(
    bin,
    optional_standard_offset,
    optional_windows_offset - optional_standard_offset,
)
print()

print("Optional Header Windows Fields")
hexdump(bin, optional_windows_offset, data_directories_offset - optional_windows_offset)
print()

print("Optional Header Data Directories")
hexdump(bin, data_directories_offset, pad_offset - data_directories_offset)


print()
print("Everything:")
hexdump(bin)
