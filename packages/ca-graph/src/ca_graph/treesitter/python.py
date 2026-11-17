"""Estrattore Python (G-02, ADR-0020): import dei file `.py` e loro risoluzione.

Mai inventare: un import il cui argomento non è una stringa letterale non produce archi e si
conta. Una cartella è un pacchetto anche senza `__init__.py` (V-07: 4 e 10 casi sui pilota), ma in
quel caso l'arco ha `confidence` `dedotto`. I moduli della libreria standard non sono nodi.
"""

import posixpath
import sys
from collections.abc import Iterable

import tree_sitter as ts
import tree_sitter_python as tsp

from ca_graph.treesitter.refs import FileImports, ImportRef

LANGUAGE = ts.Language(tsp.language())
STDLIB = frozenset(sys.stdlib_module_names)
PROJECT_FILES = frozenset({"pyproject.toml", "setup.py", "setup.cfg"})
DYNAMIC_CALLS = frozenset({"import_module", "__import__"})
MAX_DEPTH = 5_000  # profondità dell'albero: oltre, il file si conta come parziale (S2-M2)


def _text(node: ts.Node) -> str:
    return (node.text or b"").decode("utf-8", "replace")


def _is_type_checking(condition: ts.Node | None) -> bool:
    if condition is None:
        return False
    if condition.type == "identifier":
        return _text(condition) == "TYPE_CHECKING"
    if condition.type == "attribute":
        attribute = condition.child_by_field_name("attribute")
        return attribute is not None and _text(attribute) == "TYPE_CHECKING"
    return False


def _literal(node: ts.Node) -> str | None:
    """Testo di una stringa semplice; `None` per f-string, concatenazioni e il resto."""
    if node.type != "string":
        return None
    if any(c.type == "interpolation" for c in node.children):
        return None
    text = _text(node)
    prefix = text[: len(text) - len(text.lstrip("rRbBuUfF"))]
    if "f" in prefix.lower() or "b" in prefix.lower():
        return None
    return "".join(_text(c) for c in node.children if c.type == "string_content")


def _dotted(node: ts.Node) -> str:
    return _text(node)


def _import_from(node: ts.Node, type_only: bool) -> ImportRef | None:
    module = node.child_by_field_name("module_name")
    if module is None:
        return None
    if module.type == "relative_import":
        prefix = next((c for c in module.children if c.type == "import_prefix"), None)
        dots = _text(prefix).count(".") if prefix is not None else 0
        name = next((c for c in module.children if c.type == "dotted_name"), None)
        spec = "." * dots + (_dotted(name) if name is not None else "")
    else:
        spec = _dotted(module)
    names: list[str] = []
    for child in node.children_by_field_name("name"):
        target = child.child_by_field_name("name") if child.type == "aliased_import" else child
        if target is not None and target.type == "dotted_name":
            names.append(_dotted(target))
    return ImportRef(spec=spec, names=tuple(names), type_only=type_only)


def _call(node: ts.Node, type_only: bool) -> tuple[ImportRef | None, bool]:
    """(riferimento, calcolato) per `importlib.import_module(...)` e `__import__(...)`."""
    function = node.child_by_field_name("function")
    if function is None:
        return None, False
    name = function
    if function.type == "attribute":
        name = function.child_by_field_name("attribute") or function
    if name.type != "identifier" or _text(name) not in DYNAMIC_CALLS:
        return None, False
    arguments = node.child_by_field_name("arguments")
    first = next(
        (c for c in (arguments.named_children if arguments else []) if c.type != "comment"), None
    )
    value = _literal(first) if first is not None else None
    if value is None:
        return None, True
    return ImportRef(spec=value, dynamic=True, type_only=type_only), False


def extract_imports(source: bytes) -> FileImports:
    """Import di un file Python. Visita iterativa: nessuna ricorsione sul contenuto (S2-M2)."""
    parser = ts.Parser(LANGUAGE)
    tree = parser.parse(source)
    result = FileImports(refs=[], partial=tree.root_node.has_error)
    stack: list[tuple[ts.Node, bool, int]] = [(tree.root_node, False, 0)]
    while stack:
        node, type_only, depth = stack.pop()
        if depth > MAX_DEPTH:
            result.partial = True
            continue
        kind = node.type
        if kind == "import_statement":
            for child in node.children_by_field_name("name"):
                target = (
                    child.child_by_field_name("name") if child.type == "aliased_import" else child
                )
                if target is not None and target.type == "dotted_name":
                    result.refs.append(ImportRef(spec=_dotted(target), type_only=type_only))
            continue
        if kind == "import_from_statement":
            ref = _import_from(node, type_only)
            if ref is not None:
                result.refs.append(ref)
            continue
        if kind == "call":
            ref, computed = _call(node, type_only)
            if ref is not None:
                result.refs.append(ref)
            result.computed += computed
        children = list(node.children)
        if kind == "if_statement" and _is_type_checking(node.child_by_field_name("condition")):
            consequence = node.child_by_field_name("consequence")
            for child in reversed(children):
                stack.append((child, type_only or child == consequence, depth + 1))
            continue
        stack.extend((child, type_only, depth + 1) for child in reversed(children))
    return result


# --- risoluzione ------------------------------------------------------------------------------

DECLARED, INFERRED = "dichiarato", "dedotto"


class Resolver:
    """Risolve gli import di Python su un insieme noto di file del workspace."""

    def __init__(self, files: Iterable[str], configs: Iterable[str] = ()) -> None:
        files = list(files)
        self.files = {f for f in files if f.endswith(".py")}
        self.dirs = {posixpath.dirname(f) for f in self.files}
        # Una cartella con file Python, e ogni suo padre, è un pacchetto (anche implicito).
        self.packages = set()
        for directory in self.dirs:
            while directory:
                self.packages.add(directory)
                directory = posixpath.dirname(directory)
        self.roots = self._source_roots([*files, *configs])

    def _source_roots(self, files: Iterable[str]) -> list[str]:
        """Radici degli import assoluti: workspace, `src` e cartelle di progetto."""
        roots = {""}
        for path in files:
            directory, name = posixpath.split(path)
            if name in PROJECT_FILES:
                roots.add(directory)
                roots.add(posixpath.join(directory, "src") if directory else "src")
        roots.add("src")
        known = self.dirs | self.packages
        return sorted(r for r in roots if r == "" or r in known)

    def _roots_for(self, importer: str) -> list[str]:
        """Radici: prima quelle che contengono il file (la più specifica), poi le altre."""
        directory = posixpath.dirname(importer)
        containing = [
            r for r in self.roots if r == "" or directory == r or directory.startswith(r + "/")
        ]
        others = [r for r in self.roots if r not in containing]
        return sorted(containing, key=len, reverse=True) + others

    def _module(self, base: str, parts: list[str]) -> tuple[str | None, bool]:
        """(file del modulo, pacchetto senza `__init__`) per `base/parts`."""
        path = posixpath.join(base, *parts) if base else posixpath.join(*parts) if parts else base
        if path in self.files or f"{path}.py" in self.files:
            return (path if path in self.files else f"{path}.py"), False
        init = posixpath.join(path, "__init__.py") if path else "__init__.py"
        if init in self.files:
            return init, False
        return None, path in self.packages

    def resolve(self, importer: str, ref: ImportRef) -> list[tuple[str, str]] | str | None:
        """Elenco di (percorso, confidence), `"stdlib"`, `"ext:<nome>"` o `None`."""
        if ref.spec.startswith("."):
            return self._relative(importer, ref)
        parts = ref.spec.split(".")
        for root in self._roots_for(importer):
            hits = self._absolute(root, parts, ref)
            if hits is not None:
                return hits
        top = parts[0]
        if top in STDLIB:
            return "stdlib"
        return f"ext:{top}"

    def _absolute(
        self, root: str, parts: list[str], ref: ImportRef
    ) -> list[tuple[str, str]] | None:
        base_confidence = DECLARED if root == "" else INFERRED
        for end in range(len(parts), 0, -1):
            module, implicit = self._module(root, parts[:end])
            if module is not None:
                confidence = (
                    base_confidence if self._has_inits(root, parts[: end - 1]) else INFERRED
                )
                return self._with_names(root, parts[:end], module, ref, confidence)
            if implicit and end == len(parts):
                # pacchetto senza `__init__`: i nomi importati possono essere moduli
                sub = self._submodules(root, parts, ref, INFERRED)
                if sub:
                    return sub
                return []
        return None

    def _has_inits(self, root: str, parts: list[str]) -> bool:
        """Ogni cartella intermedia ha `__init__.py`: altrimenti il pacchetto è implicito."""
        for end in range(1, len(parts) + 1):
            init = (
                posixpath.join(root, *parts[:end], "__init__.py")
                if root
                else posixpath.join(*parts[:end], "__init__.py")
            )
            if init not in self.files:
                return False
        return True

    def _relative(self, importer: str, ref: ImportRef) -> list[tuple[str, str]] | None:
        dots = len(ref.spec) - len(ref.spec.lstrip("."))
        rest = [p for p in ref.spec[dots:].split(".") if p]
        base = posixpath.dirname(importer)
        for _ in range(dots - 1):
            if not base:
                return None  # esce dalla radice del workspace
            base = posixpath.dirname(base)
        if rest:
            module, implicit = self._module(base, rest)
            if module is not None:
                return self._with_names(base, rest, module, ref, DECLARED)
            return (self._submodules(base, rest, ref, INFERRED) or []) if implicit else None
        sub = self._submodules(base, [], ref, DECLARED)
        init, _ = self._module(base, [])
        if sub:
            return sub
        return [(init, DECLARED)] if init and init != importer else []

    def _with_names(
        self, base: str, parts: list[str], module: str, ref: ImportRef, confidence: str
    ) -> list[tuple[str, str]]:
        """Il modulo, o i suoi sotto-moduli se `from pkg import sub` nomina file esistenti."""
        if module.endswith("__init__.py") and ref.names:
            sub = self._submodules(base, parts, ref, confidence)
            if sub:
                return sub
        return [(module, confidence)]

    def _submodules(
        self, base: str, parts: list[str], ref: ImportRef, confidence: str
    ) -> list[tuple[str, str]]:
        found = []
        for name in ref.names:
            if name == "*":
                continue
            module, _ = self._module(base, [*parts, name])
            if module is not None and module.endswith(".py"):
                found.append((module, confidence))
        return found
