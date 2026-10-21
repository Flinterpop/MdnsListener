"""NASA/JPL Power of 10 measurements for MDNS Listener (see docs/POWER_OF_10.md).

Run from anywhere:  python tools/p10.py [ROOT ...]
With no arguments it measures src/core (in scope) and src/gui (measured, out
of scope), each on its own. It reads text, not an AST, so check every hit by
hand: a definition starts at column 0 (either brace style) and runs to the
next '}' at column 0, so inline functions in headers are not counted, and the
rule 7 list is a pattern over statement starts.
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_ROOTS = [REPO / "src" / "core", REPO / "src" / "gui"]
MAX_LINES = 60
MAX_SIGNATURE_LINES = 64
ASSERT = re.compile(r"\bassert\s*\(")
NOT_FUNCTION = re.compile(r"\s*(class|struct|namespace|enum|union|extern|//|#)")
IGNORED = re.compile(r"^\s*(recv|send|sendall|WSAStartup|WSACleanup|setsockopt|bind|listen|"
                     r"ioctlsocket|closesocket|CloseHandle|fread|fwrite|fseek)\s*\(")
POINTERS = re.compile(r"\w+\s*\*\s*\*|\(\s*\*\s*\w+\s*\)\s*\(")
BRANCH = re.compile(r"\bgoto\b|\bsetjmp\b|\blongjmp\b")
FOREVER = re.compile(r"\bwhile\s*\(\s*(true|1)\s*\)|\bfor\s*\(\s*;\s*;")
GUARD = re.compile(r"^#ifndef\s+(\w+)\s*\n#define\s+\1\b", re.MULTILINE)
DEFINE = re.compile(r"^#define\s+(\w+)", re.MULTILINE)
CONDITIONAL = re.compile(r"^#if", re.MULTILINE)


class Function:
    def __init__(self, file: str, name: str, start: int, body: list[str]) -> None:
        self.file = file
        self.name = name
        self.start = start
        self.length = len(body)
        self.asserts = sum(len(ASSERT.findall(x)) for x in body)


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").split("\n")


def signature_start(ls: list[str], i: int) -> int | None:
    """Index of the line a definition's signature starts on, if line i opens a body."""
    s = ls[i].rstrip()
    if not s or s[0].isspace() or not s.endswith("{"):
        return None
    k = i
    if s == "{":
        k = i - 1
        for _ in range(MAX_SIGNATURE_LINES):   # back over indented continuation lines
            if k < 0 or (ls[k].strip() and not ls[k][0].isspace()):
                break
            k -= 1
        if k < 0 or ls[k].rstrip().endswith((";", "}")):
            return None
    head = " ".join(x.strip() for x in ls[k:i + 1])
    if NOT_FUNCTION.match(ls[k]) or "(" not in head:
        return None
    return k


def functions(path: Path) -> list[Function]:
    ls = read_lines(path)
    out: list[Function] = []
    i = 0
    while i < len(ls):
        k = signature_start(ls, i)
        if k is not None:
            j = i + 1
            while j < len(ls) and not ls[j].startswith("}"):
                j += 1
            name = re.sub(r"\s*\{.*$", "", ls[k]).strip()
            out.append(Function(path.name, name, k + 1, ls[k:j + 1]))
            i = j
        i += 1
    return out


def grep(files: list[Path], pattern: re.Pattern[str]) -> None:
    for p in files:
        for n, line in enumerate(read_lines(p), 1):
            if pattern.search(line):
                print(f"  {p.name}:{n} {line.strip()[:78]}")


def preprocessor(files: list[Path]) -> None:
    for p in files:
        body = "\n".join(read_lines(p))
        guards = set(GUARD.findall(body))
        defs = [d for d in DEFINE.findall(body) if d not in guards]
        ifs = len(CONDITIONAL.findall(body)) - len(guards)
        if defs or ifs:
            print(f"  {p.name:<22} {len(defs)} #define {defs[:4]}, {ifs} #if")


def measure(root: Path) -> None:
    files = sorted(x for x in root.iterdir() if x.suffix in (".cpp", ".h"))
    fns = [f for p in files for f in functions(p)]
    lines = sum(len([x for x in read_lines(p) if x.strip()]) for p in files)
    print(f"==== {root.relative_to(REPO)}: {len(files)} files, {lines} non-blank lines, {len(fns)} functions")
    print("== Rule 1: goto, setjmp, longjmp (recursion: inspect by hand) ==")
    grep(files, BRANCH)
    print("== Rule 2: loops with no bound in their header ==")
    grep(files, FOREVER)
    long_fns = sorted((f for f in fns if f.length > MAX_LINES), key=lambda f: f.length, reverse=True)
    print(f"== Rule 4: {len(long_fns)} of {len(fns)} functions over {MAX_LINES} lines ==")
    for f in long_fns:
        print(f"  {f.length:4} lines  {f.file}:{f.start}  {f.name[:60]}")
    few = [f for f in fns if f.asserts < 2]
    total = sum(f.asserts for f in fns)
    print(f"== Rule 5: {total} asserts in functions, {len(few)} of {len(fns)} functions with fewer than two ==")
    counts: dict[str, int] = {}
    for f in few:
        counts[f.file] = counts.get(f.file, 0) + 1
    for name, n in sorted(counts.items()):
        print(f"  {name:<20} {n}")
    print("== Rule 7: statement-start calls whose result is not used ==")
    grep(files, IGNORED)
    print("== Rule 8: preprocessor beyond include guards ==")
    preprocessor(files)
    print("== Rule 9: multi-level pointers and function pointers ==")
    grep(files, POINTERS)


def main(argv: list[str]) -> int:
    roots = [Path(a).resolve() for a in argv] if argv else DEFAULT_ROOTS
    for r in roots:
        if not r.is_dir():
            print(f"not a directory: {r}")
            return 2
        measure(r)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
