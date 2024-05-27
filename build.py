from datetime import datetime

from hexdump import hexdump
import pe

MZ_PREAMBLE = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\x8b\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L\xcd!This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00"

PE_SIGNATURE = b"PE\x00\x00"

coff = pe.CoffHeader(
    machine=pe.MachineType.IMAGE_FILE_MACHINE_AMD64,
    number_of_sections=1,
    time_date_stamp=datetime.now(),
    characteristics=pe.Characteristics.IMAGE_FILE_RELOCS_STRIPPED
    | pe.Characteristics.IMAGE_FILE_EXECUTABLE_IMAGE
    | pe.Characteristics.IMAGE_FILE_LARGE_ADDRESS_AWARE,
)

bin = MZ_PREAMBLE + PE_SIGNATURE + coff.to_bytes()

print(hexdump(bin, 0, len(bin)))
