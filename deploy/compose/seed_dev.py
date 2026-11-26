"""Dati di prova per il server di sviluppo (I-05, U-05): quattro scansioni di un repository finto.

Serve a guardare la UI con qualcosa dentro: livelli e categorie diversi, una dipendenza con la sua
catena, una licenza, un segreto, punteggi A e B con il ripiego della B, passi di correzione, una
eccezione del repository valida, un titolo con markup ostile (deve apparire come
testo), finding risolti e nuovi tra una scansione e l'altra, una scansione di PR con la sua
baseline e, per ultima, una scansione parziale (un plugin fallito).

Parla con l'IdP finto del compose (`/github/token`) e con l'API; mai fuori dal loopback.

    docker compose -f deploy/compose/server-dev.yaml up -d --wait
    CA_UPLOAD_ALLOW_LOOPBACK_HTTP=1 uv run python deploy/compose/seed_dev.py
"""

import argparse
import json
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from ca_core.fingerprint import compute_fingerprint
from ca_core.models.finding import (
    BaselineState,
    Category,
    Finding,
    ImpactFactors,
    Level,
    Location,
    Remediation,
    RemediationSource,
    VariantScore,
)
from ca_core.models.scan_report import ScanReport

DIGEST = "sha256:" + "d" * 64
HOSTILE = '<img src=x onerror="alert(1)"> **non grassetto** [link](http://evil.example)'


def fingerprint(key: str) -> str:
    return compute_fingerprint("code", key, "seed", key, "")


def scores(
    g: float, p: float, e: float, c: float, *, b_fallback: bool = False
) -> list[VariantScore]:
    evidence = {
        "g": {"rule": "severity", "source": "cvss"},
        "p": {"rule": "epss", "epss": 0.12},
        "e": {"rule": "reach", "reach": "raggiungibile"},
        "c": {"rule": "tier", "tier": 2, "source": "service-context"},
    }
    value = round(100 * g * p * e * c, 2)
    level = (
        Level.CRITICAL
        if value >= 70
        else Level.HIGH
        if value >= 40
        else Level.MEDIUM
        if value >= 15
        else Level.LOW
    )
    out = []
    for variant in ("A", "B"):
        b_only = variant == "B" and b_fallback
        extra = {"fallbacks": ["variante-b-non-configurata"]} if b_only else {}
        out.append(
            VariantScore(
                variant=variant,  # type: ignore[arg-type]
                score=value,
                level=level,
                impact=ImpactFactors(
                    g=g, p=p, e=e, c=c, variant=variant, evidence={**evidence, **extra}
                ),
            )
        )
    return out


def build(now: datetime) -> dict[str, Finding]:
    def f(
        key: str,
        level: Level,
        category: Category,
        tool: str,
        path: str | None,
        title: str,
        rule: str,
        **extra: Any,
    ) -> Finding:
        fp = fingerprint(key)
        location = extra.pop(
            "location", Location(repository="shop", path=path, start_line=12 if path else None)
        )
        return Finding(
            id=fp,
            fingerprint=fp,
            category=category,
            rule_id=rule,
            tool=tool,
            tools=[tool],
            title=title,
            message=title,
            location=location,
            evidence={tool: {}},
            level=level,
            first_seen=now,
            last_seen=now,
            **extra,
        )

    fix = Remediation(
        text=(
            "Usa una query parametrizzata invece di formattare la stringa.\n"
            "Verifica che nessun altro punto costruisca SQL a mano."
        ),
        source=RemediationSource.TOOL,
        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
    )
    return {
        "sql": f(
            "sql",
            Level.CRITICAL,
            Category.SAST,
            "semgrep",
            "app/db/queries.py",
            "Costruzione di una query SQL con una stringa formattata",
            "python.lang.security.audit.formatted-sql-query",
            remediation=fix,
            variant_scores=scores(1.0, 0.8, 1.0, 1.0),
        ),
        "jwt": f(
            "jwt",
            Level.CRITICAL,
            Category.SECRET,
            "gitleaks",
            "config/settings.py",
            "Chiave privata JWT nel codice",
            "generic-api-key",
        ),
        "pillow": f(
            "pillow",
            Level.HIGH,
            Category.DEPENDENCY,
            "osv-scanner",
            "requirements.txt",
            "pillow 9.5.0: lettura fuori dai limiti in ImageFont (CVE-2023-4863)",
            "CVE-2023-4863",
            cve=["CVE-2023-4863"],
            cwe=["CWE-787"],
            remediation=Remediation(
                text="Aggiorna pillow alla versione 10.0.1 o successiva.",
                source=RemediationSource.DERIVED,
            ),
            variant_scores=scores(0.75, 0.4, 0.6, 1.0),
            location=Location(
                repository="shop",
                path="requirements.txt",
                start_line=3,
                purl="pkg:pypi/pillow@9.5.0",
                dependency_path=["shop", "imaging-utils 2.1", "pillow 9.5.0"],
            ),
        ),
        "xss": f(
            "xss",
            Level.HIGH,
            Category.SAST,
            "semgrep",
            "app/web/views/profile.py",
            "Output non neutralizzato nel template del profilo",
            "python.django.security.xss",
        ),
        "yaml": f(
            "yaml",
            Level.MEDIUM,
            Category.SAST,
            "bandit",
            "app/importer/loader.py",
            "Uso di yaml.load senza Loader sicuro",
            "B506",
        ),
        "cc": f(
            "cc",
            Level.MEDIUM,
            Category.QUALITY,
            "ruff",
            "app/orders/pricing.py",
            "Funzione con complessità ciclomatica 31",
            "C901",
            variant_scores=scores(0.5, 1.0, 0.6, 0.75, b_fallback=True),
        ),
        "cycle": f(
            "cycle",
            Level.MEDIUM,
            Category.ARCHITECTURE,
            "ca-graph",
            "app/orders",
            "Ciclo di dipendenza tra orders e billing",
            "arch-cycle",
        ),
        "lic": f(
            "lic",
            Level.LOW,
            Category.LICENSE,
            "scancode",
            "vendor/lib/LICENSE",
            "Licenza non dichiarata nel pacchetto vendorizzato",
            "license-undeclared",
            license_spdx="LicenseRef-seed-unknown",
        ),
        "dates": f(
            "dates",
            Level.LOW,
            Category.QUALITY,
            "ruff",
            "app/utils/dates.py",
            "Variabile non usata",
            "F841",
        ),
        "assert": f(
            "assert",
            Level.LOW,
            Category.SAST,
            "bandit",
            "tests/helpers.py",
            "Uso di assert fuori dai test",
            "B101",
        ),
        "iac": f(
            "iac",
            Level.HIGH,
            Category.IAC,
            "checkov",
            "deploy/Dockerfile",
            "Il contenitore gira come root",
            "CKV_DOCKER_3",
        ),
        "hostile": f(
            "hostile",
            Level.MEDIUM,
            Category.SAST,
            "bandit",
            "app/render.py",
            HOSTILE,
            "seed.hostile-markup",
        ),
        "late1": f(
            "late1",
            Level.HIGH,
            Category.SAST,
            "semgrep",
            "app/api/upload.py",
            "Percorso di file costruito da input non fidato",
            "python.lang.security.path-traversal",
        ),
        "late2": f(
            "late2",
            Level.MEDIUM,
            Category.DEPENDENCY,
            "osv-scanner",
            "package-lock.json",
            "lodash 4.17.20: prototype pollution",
            "CVE-2021-23337",
            location=Location(
                repository="shop", path="package-lock.json", purl="pkg:npm/lodash@4.17.20"
            ),
        ),
    }


def report(
    findings: list[Finding],
    *,
    started: datetime,
    commit: str,
    status: str = "complete",
    failed: tuple[str, ...] = (),
    pr: int | None = None,
    base: str | None = None,
    exceptions: list[dict[str, str]] | None = None,
    baseline: dict[str, Any] | None = None,
) -> bytes:
    names = ["bandit", "ruff", "semgrep", "gitleaks", "osv-scanner", "checkov", "ca-graph"]
    plugins = [
        {
            "name": n,
            "version": "1.0.0",
            "digest": DIGEST,
            "signature": "verified",
            "isolation": "gvisor",
            "duration_seconds": 4.5,
            "outcome": "failed" if n in failed else "ok",
            **({"failure": "tempo scaduto"} if n in failed else {}),
        }
        for n in names
    ]
    data: dict[str, Any] = {
        "version": 1,
        "status": status,
        "started_at": started,
        "duration_seconds": 83.0,
        "repository": {"name": "shop", "commit": commit, "history": "full"},
        "gate": {
            "mode": "new-findings-only" if pr else "all",
            "effective_mode": "new-findings-only" if pr else "all",
        },
        "plugins": plugins,
        "findings": findings,
        "warnings": [{"code": "feeds-stale", "message": "I feed EPSS e KEV hanno più di un giorno"}]
        if status == "partial"
        else [],
        "exceptions": exceptions or [],
    }
    if pr:
        data["scan"] = {"kind": "pr", "base_commit": base, "pull_request": pr}
        data["baseline"] = baseline
    return ScanReport.model_validate(data).model_dump_json().encode()


def multipart(report_bytes: bytes) -> tuple[bytes, str]:
    boundary = "seed-" + secrets.token_hex(12)
    body = (
        (
            f'--{boundary}\r\nContent-Disposition: form-data; name="report"; '
            'filename="report.json"\r\n'
            f"Content-Type: application/json\r\n\r\n"
        ).encode()
        + report_bytes
        + f"\r\n--{boundary}--\r\n".encode()
    )
    return body, f"multipart/form-data; boundary={boundary}"


def loopback(url: str) -> str:
    if urlsplit(url).hostname not in ("127.0.0.1", "localhost", "::1"):
        sys.exit("solo loopback: questo script carica dati di prova nel server di sviluppo")
    return url.rstrip("/")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--server", default="http://127.0.0.1:8000")
    parser.add_argument("--idp", default="http://127.0.0.1:9000")
    parser.add_argument("--repository", default="acme/shop")
    parser.add_argument("--repository-id", default="9001")
    parser.add_argument("--owner-id", default="4242")
    args = parser.parse_args()
    server, idp = loopback(args.server), loopback(args.idp)
    now = datetime.now(UTC).replace(microsecond=0)
    pool = build(now)
    pick = lambda *keys: [pool[k] for k in keys]  # noqa: E731
    sha = lambda n: format(n, "x").rjust(40, "0")  # noqa: E731

    first = pick(
        "sql",
        "jwt",
        "pillow",
        "xss",
        "yaml",
        "cc",
        "cycle",
        "lic",
        "dates",
        "assert",
        "iac",
        "hostile",
    )
    second = pick(
        "sql", "jwt", "pillow", "xss", "cc", "cycle", "lic", "iac", "hostile", "late1", "late2"
    )
    repo_exceptions = [
        {
            "fingerprint": pool["lic"].fingerprint,
            "reason": "Licenza verificata a mano",
            "expires": "2999-01-01",
            "approved_by": "Chiunque",
        },
        {
            "fingerprint": pool["iac"].fingerprint,
            "reason": "Eccezione scaduta",
            "expires": "2020-01-01",
            "approved_by": "Chiunque",
        },
    ]
    plan: list[tuple[str, bytes]] = [
        (
            "refs/heads/main",
            report(
                first, started=now - timedelta(days=9), commit=sha(1), exceptions=repo_exceptions
            ),
        ),
        (
            "refs/heads/main",
            report(
                second, started=now - timedelta(days=2), commit=sha(2), exceptions=repo_exceptions
            ),
        ),
        (
            "refs/pull/7/merge",
            report(
                [
                    *(
                        x.model_copy(update={"baseline_state": BaselineState.EXISTING})
                        for x in second
                    ),
                    pool["yaml"].model_copy(update={"baseline_state": BaselineState.NEW}),
                ],
                started=now - timedelta(days=1),
                commit=sha(3),
                pr=7,
                base=sha(2),
                baseline={
                    "status": "valid",
                    "commit": sha(2),
                    "source": "ci-artifact",
                    "new": 1,
                    "existing": len(second),
                    "resolved": [],
                    "not_evaluated": 0,
                },
            ),
        ),
        (
            "refs/heads/main",
            report(
                pick("sql", "jwt", "pillow", "cc", "cycle", "late2", "hostile"),
                started=now - timedelta(hours=1),
                commit=sha(4),
                status="partial",
                failed=("semgrep",),
                exceptions=repo_exceptions,
            ),
        ),
    ]
    for ref, data in plan:
        query = urllib.parse.urlencode(
            {
                "repository": args.repository,
                "repository_id": args.repository_id,
                "owner_id": args.owner_id,
                "ref": ref,
            }
        )
        request = urllib.request.Request(f"{idp}/github/token?{query}", data=b"", method="POST")
        token = json.load(urllib.request.urlopen(request, timeout=10))["token"]  # noqa: S310
        body, content_type = multipart(data)
        upload = urllib.request.Request(
            f"{server}/v1/scans",
            data=body,
            method="POST",
            headers={"Authorization": f"Bearer {token}", "Content-Type": content_type},
        )
        try:
            reply = urllib.request.urlopen(upload, timeout=30)  # noqa: S310
            print(f"{ref}: {reply.status} {json.load(reply)['id']}")
        except urllib.error.HTTPError as error:
            print(f"{ref}: {error.code} {error.read().decode()[:200]}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
