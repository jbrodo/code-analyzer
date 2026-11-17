# GitLab: componente e report nativi

Decisioni: ADR-0027. Codice: `integrations/gitlab-component/` e `code-analyzer export`.

**Stato.** Il componente **non è mai stato eseguito su GitLab**: non c'è un'istanza di prova (D2-12). È provato come struttura e con lo script eseguito con un `docker` finto; i report sono provati contro gli schemi di GitLab fissati e con dati veri in un E2E locale. Non esiste un'immagine pubblicata (D2-16).

## `export`

```bash
code-analyzer export --format gitlab --report code-analyzer.report.json \
  [--sbom sbom.cdx.json] --output-dir gl
```

Scrive `gl-sast-report.json`, `gl-dependency-scanning-report.json`, `gl-code-quality-report.json` e, con `--sbom`, `gl-sbom-code-analyzer.cdx.json`.

| Report | Finding esportati | Richiede |
| --- | --- | --- |
| `sast` | `sast` | un percorso |
| `dependency_scanning` | `dependency` | percorso del file e versione (dal purl) |
| `codequality` | `quality` | percorso e riga |
| `cyclonedx` | l'SBOM di `sbom` | CycloneDX 1.7, riportato alla 1.6 |

- Ogni file è validato contro lo schema fissato **prima** di scrivere: se uno non è valido non se ne scrive nessuno (exit 2).
- **Segreti, licenze, IaC, architettura, test e salute non hanno posto in questi formati.** Restano nel report e nel SARIF, da conservare come artefatti; `export` stampa quanti sono.
- Un finding senza il dato richiesto non si esporta e si conta: non si inventa un valore.
- GitLab accetta CycloneDX 1.4, 1.5 e 1.6, non 1.7. L'export cambia solo la dichiarazione di versione e valida contro lo schema 1.6; se l'SBOM usa qualcosa di esclusivo della 1.7 non si scrive. Il report `cyclonedx` è del livello Ultimate di GitLab.
- `export` non decide: l'esito è di `gate`.

## Il componente

`templates/code-analyzer.yml`: controlla il daemon, in una merge request analizza il commit base come baseline, poi `scan --pr`, SBOM, `export` e `gate` per ultimo; il job fallisce secondo il gate e gli artefatti restano anche allora. Ingressi, requisiti e limiti: `integrations/gitlab-component/README.md`.

Da sapere:

- **Serve un runner con un daemon di container** e la directory di build allo stesso percorso per il job e per il daemon (socket e `/builds` montati alla pari). Un `DOCKER_HOST` remoto non è supportato e il solo Docker-in-Docker non basta. Il socket dà al job lo stesso potere di `root` sull'host: runner effimeri o fidati.
- **Nessun commento sulla merge request**: il token del job non può scriverlo.
- La baseline è sempre la scansione del base; quella da artefatto del branch principale non c'è.
- Le merge request da fork e le «merged results pipelines» non sono provate.
