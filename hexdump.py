def hexdump(data: bytes, offset: int = 0, length: int = None, memory_offset: int = 0):
    assert memory_offset % 16 == 0
    if length is None:
        length = len(data) - offset
    p = (offset // 16) * 16
    lines = []
    while p < offset + length:
        s = f"{p+memory_offset:08x} "
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

        print(s)

        p += 16
