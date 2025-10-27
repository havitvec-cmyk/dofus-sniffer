# parser/dofus_retro_framing.py
from typing import Dict, Tuple, List

DELIMS = (b'\n', b'\x00')

class RetroStream:
    __slots__ = ("buf",)

    def __init__(self):
        self.buf = bytearray()

    def _find_next_delim(self) -> int:
        if not self.buf:
            return -1
        idxs = [i for d in DELIMS if (i := self.buf.find(d)) != -1]
        return min(idxs) if idxs else -1

    def _extract_opcode(self, line: bytes) -> str:
        i = 0
        n = len(line)
        while i < n and (line[i:i+1].isalnum()):
            i += 1
        return line[:i].decode(errors="replace")

    def feed(self, data: bytes) -> List[dict]:
        if data:
            self.buf.extend(data)

        frames = []
        while True:
            idx = self._find_next_delim()
            if idx < 0:
                break

            line = bytes(self.buf[:idx])
            del self.buf[:idx+1]
            line = line.rstrip(b"\r ").lstrip()
            if not line:
                continue

            opcode = self._extract_opcode(line)
            rest = line[len(opcode):].decode(errors="replace")

            if not opcode and len(line) < 2:
                continue

            frames.append({
                "opcode": opcode,
                "raw": line,
                "text": rest,
            })

        return frames


class RetroReassembler:
    def __init__(self):
        self._streams: Dict[Tuple[str,int,str,int], RetroStream] = {}

    def _get(self, k: Tuple[str,int,str,int]) -> RetroStream:
        st = self._streams.get(k)
        if st is None:
            st = RetroStream()
            self._streams[k] = st
        return st

    def feed(self, four_tuple: Tuple[str,int,str,int], data: bytes) -> List[dict]:
        if not data:
            return []
        return self._get(four_tuple).feed(data)
