# parser/dofus_retro_framing.py
# Dofus Retro (1.x) ASCII line-based framing with TCP reassembly.
# Messages are typically ASCII lines ending with \n (sometimes \r\n or \x00).
# Examples: "HC...", "AS...", "GA300|...", "Af...", etc.

from typing import Dict, Tuple, List

DELIMS = (b'\n', b'\x00')  # handle \n and \x00; we’ll also strip trailing \r


class RetroStream:
    __slots__ = ("buf",)

    def __init__(self):
        self.buf = bytearray()

    def _find_next_delim(self) -> int:
        # Return index of first delimiter occurrence, or -1
        if not self.buf:
            return -1
        # Find the earliest of \n or \x00
        i_n = self.buf.find(b'\n')
        i_0 = self.buf.find(b'\x00')
        idxs = [i for i in (i_n, i_0) if i != -1]
        return min(idxs) if idxs else -1

    def feed(self, data: bytes) -> List[dict]:
        if data:
            self.buf.extend(data)

        frames = []
        while True:
            idx = self._find_next_delim()
            if idx < 0:
                break

            line = bytes(self.buf[:idx])  # exclude delimiter
            # consume including the delimiter
            del self.buf[:idx+1]

            # strip trailing \r if present
            if line.endswith(b'\r'):
                line = line[:-1]

            if not line:
                continue

            # Parse opcode: contiguous [A-Za-z]+ optionally followed by digits
            # e.g., GA300 -> opcode="GA300"; often there is a '|' separating fields
            op = []
            for i, b in enumerate(line):
                if 65 <= b <= 90 or 97 <= b <= 122 or 48 <= b <= 57:  # A-Z a-z 0-9
                    op.append(b)
                    continue
                break
            opcode = bytes(op).decode(errors="replace")
            rest = line[len(op):].decode(errors="replace")

            frames.append({
                "opcode": opcode,
                "raw": line,        # bytes without delimiter
                "text": rest,       # remainder as text (may start with '|' or other separators)
            })

        return frames


class RetroReassembler:
    """
    Keyed by TCP 4-tuple (src, sport, dst, dport).
    Feed raw TCP payload bytes per direction to extract ASCII lines (frames).
    """

    def __init__(self):
        self._streams: Dict[Tuple[str, int, str, int], RetroStream] = {}

    def _get(self, k: Tuple[str, int, str, int]) -> RetroStream:
        s = self._streams.get(k)
        if s is None:
            s = RetroStream()
            self._streams[k] = s
        return s

    def feed(self, four_tuple: Tuple[str, int, str, int], data: bytes) -> List[dict]:
        if not data:
            return []
        return self._get(four_tuple).feed(data)
