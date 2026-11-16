# iac-app (fixture F-02 della Fase 2)

Dockerfile, manifest Kubernetes e file Terraform con problemi noti per checkov, hadolint e trivy.
**Non va costruito ne' applicato.** I nomi di immagini e risorse sono inventati.

I problemi attesi sono in `expected-findings.yaml`. Dove due o tre strumenti segnalano lo stesso
problema, le voci portano lo stesso valore di `correlation`: e' il caso di prova per il gruppo di
correlazione di ADR-0026 (K-21).

| Percorso | Problemi messi di proposito |
| --- | --- |
| `Dockerfile` | Tag `latest`, `ADD`, `sudo`, `cd` in `RUN`, pacchetti non fissati, nessun utente, nessun `HEALTHCHECK`, `CMD` in forma di shell |
| `k8s/pod.yaml` | Container privilegiato, tag `latest` |
| `terraform/main.tf` | SSH aperto a tutti, bucket senza blocco dell'accesso pubblico |

Gli strumenti riportano molti altri controlli su questi file (risorse non limitate, cifratura,
log): non sono tra gli attesi, e i test di rilevamento non devono pretendere un elenco chiuso.
