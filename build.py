from datetime import datetime
import struct

import iced_x86 as ic

from hexdump import hexdump
import mz
import pe

IMAGE_BASE = 0x00400000

label_id: int = 1


def create_label() -> int:
    global label_id
    idd = label_id
    label_id += 1
    return idd


def add_label(id: int, instruction: ic.Instruction) -> ic.Instruction:
    instruction.ip = id
    return instruction


def build_code():
    address_GetStdHandle = create_label()
    address_WriteFile = create_label()
    address_ExitProcess = create_label()

    instructions = []
    instructions.append(
        ic.Instruction.create_reg_u64(ic.Code.SUB_RM64_IMM8, ic.Register.RSP, 0x38)
    )
    instructions.append(
        ic.Instruction.create_mem_u32(
            ic.Code.MOV_RM32_IMM32, ic.MemoryOperand(ic.Register.RSP, displ=0x34), 0
        )
    )
    instructions.append(
        ic.Instruction.create_reg_i32(ic.Code.MOV_R32_IMM32, ic.Register.ECX, -11)
    )
    instructions.append(
        ic.Instruction.create_mem(
            ic.Code.CALL_RM64,
            ic.MemoryOperand(ic.Register.RIP, displ=address_GetStdHandle),
        )
    )
    instructions.append(
        ic.Instruction.create_mem_reg(
            ic.Code.MOV_RM64_R64,
            ic.MemoryOperand(ic.Register.RSP, displ=0x28),
            ic.Register.RAX,
        )
    )
    instructions.append(
        ic.Instruction.create_reg_mem(
            ic.Code.MOV_R64_RM64,
            ic.Register.RCX,
            ic.MemoryOperand(ic.Register.RSP, displ=0x28),
        )
    )
    hello_world = create_label()
    instructions.append(
        ic.Instruction.create_reg_mem(
            ic.Code.LEA_R64_M,
            ic.Register.RDX,
            ic.MemoryOperand(ic.Register.RIP, displ=hello_world),
        )
    )
    instructions.append(
        ic.Instruction.create_reg_u64(ic.Code.MOV_R32_IMM32, ic.Register.R8D, 14)
    )
    instructions.append(
        ic.Instruction.create_reg_mem(
            ic.Code.LEA_R64_M,
            ic.Register.R9,
            ic.MemoryOperand(ic.Register.RSP, displ=0x30),
        )
    )
    instructions.append(
        ic.Instruction.create_reg_reg(
            ic.Code.XOR_RM32_R32, ic.Register.EAX, ic.Register.EAX
        )
    )
    instructions.append(
        ic.Instruction.create_mem_u32(
            ic.Code.MOV_RM32_IMM32, ic.MemoryOperand(ic.Register.RSP, displ=0x20), 0
        )
    )
    instructions.append(
        ic.Instruction.create_mem(
            ic.Code.CALL_RM64,
            ic.MemoryOperand(ic.Register.RIP, displ=address_WriteFile),
        )
    )
    instructions.append(
        ic.Instruction.create_reg_reg(
            ic.Code.XOR_RM32_R32, ic.Register.ECX, ic.Register.ECX
        )
    )
    instructions.append(
        ic.Instruction.create_mem(
            ic.Code.CALL_RM64,
            ic.MemoryOperand(ic.Register.RIP, displ=address_ExitProcess),
        )
    )

    instructions.append(
        add_label(hello_world, ic.Instruction.create_declare_byte(b"Hello world!\r\n"))
    )

    encoder = ic.BlockEncoder(64)
    encoder.add_many(instructions)

    partial = encoder.encode(IMAGE_BASE)
    len_so_far = len(partial)

    pad_bytes = 8 - (len_so_far % 8)
    if pad_bytes < 8:
        encoder.add(ic.Instruction.create_declare_byte(b"\00" * pad_bytes))
        len_so_far += pad_bytes

    iat_rva = len_so_far
    encoder.add(
        add_label(
            address_GetStdHandle,
            ic.Instruction.create_declare_byte(b"\x00\x00\x00\x00\x00\x00\x00\x00"),
        )
    )
    encoder.add(
        add_label(
            address_WriteFile,
            ic.Instruction.create_declare_byte(b"\x00\x00\x00\x00\x00\x00\x00\x00"),
        )
    )
    encoder.add(
        add_label(
            address_ExitProcess,
            ic.Instruction.create_declare_byte(b"\x00\x00\x00\x00\x00\x00\x00\x00"),
        )
    )
    # IAT final NULL
    encoder.add(
        ic.Instruction.create_declare_byte(b"\x00\x00\x00\x00\x00\x00\x00\x00"),
    )
    return bytearray(encoder.encode(IMAGE_BASE)), iat_rva


def build_idata(imports, idata_rva, iat_start_rva):
    # (lookup table offset, name offset)
    dlls = []

    names = b""
    import_tables = b""

    hints = b""
    total_functions = sum(len(v) for v in imports.values())
    hints_start = (
        idata_rva + (len(imports) + 1) * 20 + (total_functions + len(imports)) * 8
    )

    for dll_name, functions in imports.items():
        dlls.append((len(import_tables), len(names)))
        names += dll_name.encode() + b"\x00"

        table = b""
        for name, ordinal in functions:
            hint = struct.pack("H", ordinal) + name.encode() + b"\x00"
            hint_rva = hints_start + len(hints)
            hints += hint
            table += struct.pack("Q", hint_rva)
        table += b"\x00\x00\x00\x00\x00\x00\x00\x00"

        import_tables += table

    # Start after the Import Lookup Table
    import_tables_start = idata_rva + (len(imports) + 1) * 20
    names_start = hints_start + len(hints)

    directory_table = b""
    for table_offset, name_offset in dlls:
        table_rva = import_tables_start + table_offset
        iat_rva = iat_start_rva + table_offset
        name_rva = names_start + name_offset
        directory_table += struct.pack("IIIII", table_rva, 0, 0, name_rva, iat_rva)
    directory_table += b"\x00" * 20

    assert idata_rva + len(directory_table + import_tables) == hints_start

    idata = directory_table + import_tables + hints + names
    return idata, import_tables


mz_preamble = mz.build_mz_stub()

PE_SIGNATURE = b"PE\x00\x00"

# Need to populate `size_of_optional_header` later
coff = pe.CoffHeader(
    machine=pe.MachineType.IMAGE_FILE_MACHINE_AMD64,
    time_date_stamp=datetime.now(),
    characteristics=pe.Characteristics.IMAGE_FILE_RELOCS_STRIPPED
    | pe.Characteristics.IMAGE_FILE_EXECUTABLE_IMAGE
    | pe.Characteristics.IMAGE_FILE_LARGE_ADDRESS_AWARE,
)

optional_standard = pe.OptionalHeaderStandard(major_linker_version=3, minor_linker_version=0)
optional_windows = pe.OptionalHeaderWindows(
    image_base=IMAGE_BASE,
    size_of_image=512,
    dll_characteristics=pe.DllCharacteristics.IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    | pe.DllCharacteristics.IMAGE_DLLCHARACTERISTICS_NO_SEH
    | pe.DllCharacteristics.IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,
)
data_directories = pe.DataDirectories([])
optional_windows.number_of_rva_and_sizes = data_directories.num_dirs()

text_section = pe.Section(".text")
text_section.header.characteristics = (
    pe.SectionFlags.IMAGE_SCN_CNT_CODE
    # | pe.SectionFlags.IMAGE_SCN_CNT_INITIALIZED_DATA
    | pe.SectionFlags.IMAGE_SCN_MEM_EXECUTE
    | pe.SectionFlags.IMAGE_SCN_MEM_READ
)
text_section.header.pointer_to_raw_data = 512
text_section.data, iat_rva = build_code()
# idata_rva = len(text_section.data)
# idata, iat = build_idata(
#     {
#         "kernel32.dll": [
#             ("GetStdHandle", 732),
#             ("WriteFile", 1573),
#             ("ExitProcess", 359),
#         ]
#     },
#     idata_rva,
#     iat_rva,
# )
# text_section.data[iat_rva : iat_rva + len(iat)] = iat
# text_section.data += idata

# data_directories.add_directory(".idata", idata_rva, 20 * (1 + 1))
# data_directories.add_directory("IAT", iat_rva, len(iat))
# optional_windows.number_of_rva_and_sizes = len(data_directories.directories)

sections = [text_section]
coff.number_of_sections = len(sections)
optional_standard.size_of_code = (len(sections[0].data) + 511) // 512 * 512

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

coff.size_of_optional_header = len(bin) - optional_standard_offset
bin[coff_offset:optional_standard_offset] = coff.to_bytes()

sections_offset = len(bin)
for section in sections:
    bin += section.header_to_bytes()

pad_offset = len(bin)
padded_header_size = (len(bin) + 511) // 512 * 512
bin += b"\0" * (padded_header_size - len(bin))

optional_windows.size_of_headers = len(bin)
optional_windows_bytes = optional_windows.to_bytes()
bin[optional_windows_offset : optional_windows_offset + len(optional_windows_bytes)] = (
    optional_windows_bytes
)

for section in sections:
    bin += section.data
    padded_size = (len(bin) + 511) // 512 * 512
    bin += b"\0" * (padded_size - len(bin))

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
hexdump(bin, data_directories_offset, sections_offset - data_directories_offset)
print()

print("Section headers")
hexdump(bin, sections_offset, pad_offset - sections_offset)

print()
print("Everything:")
hexdump(bin)

with open("out.exe", "wb") as f:
    f.write(bin)
