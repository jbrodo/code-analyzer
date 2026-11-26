"""G-03: estrattore JS, TS e TSX, con alias di `tsconfig` letti come dati (V-07)."""

import json
from pathlib import Path

import pytest
from graph_builders import edges, graph

pytest.importorskip("tree_sitter")

from ca_graph.treesitter import javascript as js  # noqa: E402


def refs(source: str, language: str = "typescript") -> list[tuple[str, bool, bool]]:
    return [
        (r.spec, r.dynamic, r.type_only) for r in js.extract_imports(source.encode(), language).refs
    ]


# --- estrazione --------------------------------------------------------------------------------


def test_every_import_form() -> None:
    found = refs(
        'import a from "./a";\nimport type { T } from "./t";\nimport "side";\n'
        'export { x } from "../x";\nexport type { Y } from "./y";\nexport * from "./z";\n'
        'import q = require("./q");\nconst r = require("./r");\nconst d = import("./d");\n'
        "const e = import(`./static`);\n"
    )
    assert found == [
        ("./a", False, False), ("./t", False, True), ("side", False, False),
        ("../x", False, False), ("./y", False, True), ("./z", False, False),
        ("./q", False, False), ("./r", False, False), ("./d", True, False), ("./static", True, False),
    ]  # fmt: skip


def test_computed_require_and_dynamic_import_are_counted_not_guessed() -> None:
    result = js.extract_imports(
        b"require(name);\nimport(`./l/${code}.json`);\nrequire('a' + b);\nimport(x);\nrequire('ok');\n",
        "javascript",
    )
    assert [r.spec for r in result.refs] == ["ok"] and result.computed == 4


def test_jsx_tsx_and_nested_calls() -> None:
    assert refs(
        "import x from './x';\nexport const V = () => <p>{require('./r')}</p>;\n", "tsx"
    ) == [
        ("./x", False, False),
        ("./r", False, False),
    ]
    assert refs("function f() { return import('./lazy'); }\n", "javascript") == [
        ("./lazy", True, False)
    ]


def test_syntax_error_keeps_the_imports_found_and_marks_partial() -> None:
    """V-07: `typeof import(...)` come argomento di tipo non è riconosciuto dalla grammatica 0.23."""
    result = js.extract_imports(
        b"import a from './a';\nconst x = ;;; {{{\nimport b from './b';\n", "typescript"
    )
    assert result.partial and {"./a"} <= {r.spec for r in result.refs}


def test_very_deep_nesting_does_not_crash() -> None:
    source = "const x = " + "[" * 30_000 + "]" * 30_000 + ";\nimport a from './a';\n"
    assert isinstance(js.extract_imports(source.encode(), "javascript").partial, bool)


def test_depth_limit_marks_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(js, "MAX_DEPTH", 4)
    assert js.extract_imports(b"x = [[[[[[[[1]]]]]]]];", "javascript").partial


# --- tsconfig e JSON tollerante -----------------------------------------------------------------


def test_lenient_json_handles_comments_trailing_commas_and_urls_in_strings() -> None:
    raw = b'\xef\xbb\xbf{ /* c */ "a": [1, 2,], // x\n "b": "http://no-comment", "c": "a/*b*/" }'
    assert js.parse_json_lenient(raw) == {"a": [1, 2], "b": "http://no-comment", "c": "a/*b*/"}
    for bad in (b"{", b"/* unterminated", b"\xff\xfe", b""):
        assert js.parse_json_lenient(bad) is None


# --- risoluzione -------------------------------------------------------------------------------


def test_relative_imports_extensions_index_and_the_js_to_ts_convention(tmp_path: Path) -> None:
    doc = graph(
        tmp_path,
        {
            "src/main.ts": "import a from './a';\nimport b from './b.js';\nimport c from './lib';\n"
            "import d from './d.js';\nimport e from '../other/e';\n",
            "src/a.ts": "",
            "src/b.ts": "",
            "src/lib/index.tsx": "",
            "src/d.js": "",
            "other/e.mjs": "",
        },
    )
    e = edges(doc)
    for target in ("src/a.ts", "src/b.ts", "src/lib/index.tsx", "src/d.js", "other/e.mjs"):
        assert ("src/main.ts", target) in e, target
    assert {x["confidence"] for x in e.values()} == {"dichiarato"}


def test_missing_relative_target_is_counted_and_never_becomes_an_external(tmp_path: Path) -> None:
    doc = graph(tmp_path, {"a.ts": "import x from './nope';\nimport y from '../../up';\n"})
    assert (
        doc["edges"] == [] and doc["externals"] == [] and doc["stats"]["unresolved"]["missing"] == 2
    )


def test_tsconfig_paths_and_base_url_resolve_aliases_as_inferred(tmp_path: Path) -> None:
    """V-07: senza `paths` più della metà degli import interni di un pilota risultava esterna."""
    doc = graph(
        tmp_path,
        {
            "frontend/tsconfig.json": '{ // commento\n "compilerOptions": { "baseUrl": ".", "paths": {"@/*": ["./src/*"], "~lib": ["lib/index.ts"]}, },}',
            "frontend/src/app.ts": "import u from '@/utils/u';\nimport l from '~lib';\nimport c from 'shared/c';\n",
            "frontend/src/utils/u.ts": "",
            "frontend/lib/index.ts": "",
            "frontend/shared/c.ts": "",
        },
    )
    e = edges(doc)
    assert e[("frontend/src/app.ts", "frontend/src/utils/u.ts")]["confidence"] == "dedotto"
    assert ("frontend/src/app.ts", "frontend/lib/index.ts") in e
    assert ("frontend/src/app.ts", "frontend/shared/c.ts") in e  # baseUrl
    assert doc["externals"] == []


def test_alias_that_matches_but_has_no_file_is_missing_not_external(tmp_path: Path) -> None:
    doc = graph(
        tmp_path,
        {
            "tsconfig.json": '{"compilerOptions": {"paths": {"@app/*": ["src/*"]}}}',
            "a.ts": "import x from '@app/gone';\n",
        },
    )
    assert doc["externals"] == [] and doc["stats"]["unresolved"]["missing"] == 1


def test_the_longest_alias_prefix_wins(tmp_path: Path) -> None:
    config = {"compilerOptions": {"paths": {"@/*": ["generic/*"], "@/ui/*": ["ui/*"]}}}
    doc = graph(
        tmp_path,
        {
            "tsconfig.json": json.dumps(config),
            "a.ts": "import b from '@/ui/b';\n",
            "ui/b.ts": "",
            "generic/ui/b.ts": "",
        },
    )
    assert ("a.ts", "ui/b.ts") in edges(doc)


def test_extends_inside_the_workspace_is_followed_and_package_extends_is_counted(
    tmp_path: Path,
) -> None:
    doc = graph(
        tmp_path,
        {
            "tsconfig.base.json": '{"compilerOptions": {"baseUrl": ".", "paths": {"@x/*": ["packages/x/src/*"]}}}',
            "app/tsconfig.json": '{"extends": ["../tsconfig.base.json", "@tsconfig/node20/tsconfig.json"]}',
            "app/main.ts": "import y from '@x/y';\n",
            "packages/x/src/y.ts": "",
        },
    )
    assert ("app/main.ts", "packages/x/src/y.ts") in edges(doc)
    assert doc["stats"]["unresolved"]["config_extends"] == 1


def test_extends_cycles_and_escapes_are_bounded(tmp_path: Path) -> None:
    doc = graph(
        tmp_path,
        {
            "a/tsconfig.json": '{"extends": "./b.json"}',
            "a/b.json": '{"extends": "./tsconfig.json"}',
            "c/tsconfig.json": '{"extends": "../../../etc/passwd"}',
            "a/x.ts": "import y from './y';\nimport z from 'zzz';\n",
            "a/y.ts": "",
            "c/z.ts": "",
        },
    )
    assert ("a/x.ts", "a/y.ts") in edges(doc)
    assert doc["stats"]["unresolved"]["config_extends"] >= 1


def test_alias_that_points_outside_the_workspace_gives_no_edge(tmp_path: Path) -> None:
    doc = graph(
        tmp_path,
        {
            "tsconfig.json": '{"compilerOptions": {"baseUrl": "../..", "paths": {"@o/*": ["../../*"]}}}',
            "a.ts": "import x from '@o/etc/passwd';\n",
        },
    )
    assert doc["edges"] == [] and doc["externals"] == []


def test_workspace_packages_resolve_by_their_package_json_name(tmp_path: Path) -> None:
    doc = graph(
        tmp_path,
        {
            "packages/core/package.json": '{"name": "@acme/core", "main": "dist/index.js", "module": "src/index.ts"}',
            "packages/core/src/index.ts": "",
            "packages/core/src/util.ts": "",
            "packages/ui/package.json": '{"name": "ui", "exports": {".": {"import": "./lib/main.ts"}}}',
            "packages/ui/lib/main.ts": "",
            "app/main.ts": "import a from '@acme/core';\nimport b from '@acme/core/util';\nimport c from 'ui';\n",
        },
    )
    e = edges(doc)
    assert ("app/main.ts", "packages/core/src/index.ts") in e
    assert ("app/main.ts", "packages/core/src/util.ts") in e
    assert ("app/main.ts", "packages/ui/lib/main.ts") in e
    assert {x["confidence"] for x in e.values()} == {"dedotto"} and doc["externals"] == []


def test_bare_specifiers_are_external_npm_packages_with_scope_and_builtins_are_skipped(
    tmp_path: Path,
) -> None:
    doc = graph(
        tmp_path,
        {
            "a.ts": "import r from 'react';\nimport s from '@scope/pkg/deep/file';\nimport f from 'fs';\nimport p from 'node:path';\nimport l from 'lodash/get';\n"
        },
    )
    assert doc["externals"] == [
        {"name": "@scope/pkg", "ecosystem": "npm"},
        {"name": "lodash", "ecosystem": "npm"},
        {"name": "react", "ecosystem": "npm"},
    ]
    assert all(e["external"] for e in doc["edges"])


def test_odd_specifiers_are_counted(tmp_path: Path) -> None:
    doc = graph(
        tmp_path,
        {
            "a.ts": "import a from '/abs/path';\nimport b from 'https://cdn.example/x.js';\nimport c from 'bad name';\nimport d from '';\n"
        },
    )
    unresolved = doc["stats"]["unresolved"]
    assert (
        unresolved["outside_workspace"] == 1 and unresolved["missing"] == 3 and doc["edges"] == []
    )


def test_type_only_and_dynamic_edges_are_flagged_and_merged(tmp_path: Path) -> None:
    doc = graph(
        tmp_path,
        {
            "a.ts": "import type { T } from './t';\nimport type { U } from './t';\nconst m = import('./m');\nimport { v } from './v';\nimport type { W } from './v';\n",
            "t.ts": "",
            "m.ts": "",
            "v.ts": "",
        },
    )
    e = edges(doc)
    assert e[("a.ts", "t.ts")]["type_only"] is True and e[("a.ts", "t.ts")]["imports"] == 2
    assert e[("a.ts", "m.ts")]["dynamic"] is True
    assert e[("a.ts", "v.ts")]["type_only"] is False  # un solo import di valore basta


def test_declaration_files_and_node_modules_are_not_modules(tmp_path: Path) -> None:
    doc = graph(
        tmp_path,
        {
            "a.ts": "import t from './types';\n",
            "types.d.ts": "",
            "node_modules/p/index.js": "",
            "dist/o.js": "",
        },
    )
    assert [m["path"] for m in doc["modules"]] == ["a.ts"] and doc["edges"] == []
