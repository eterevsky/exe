def parse_int(data: bytes) -> int:
    return int.from_bytes(data, "little")


def parse_c_string(data: bytes, start: int) -> str:
    end = data.index(0, start)
    return data[start:end].decode()
