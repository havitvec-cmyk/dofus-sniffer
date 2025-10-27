from typing import Dict, Callable

Handler = Callable[[str], str]


def _handle_GA(text: str) -> str:
    parts = text.split('|')
    return f"GA parts={parts}"


def _handle_HC(text: str) -> str:
    return f"HC text={text[:80]!r}"


REGISTRY: Dict[str, Handler] = {
    "GA": _handle_GA,
    "HC": _handle_HC,
}


def dispatch(opcode: str, text: str) -> str:
    for i in range(len(opcode), 0, -1):
        key = opcode[:i]
        if key in REGISTRY:
            return REGISTRY[key](text)
    return f"{opcode or '?'} text={text[:120]!r}"
