# Plugin finto (T-02): prova il runner reale senza scanner. ADR-0004, ADR-0005, ADR-0007.
# Contesto di build: questa directory. Build locale, mai pubblicata.
# Il digest e' quello dell'immagine base I-01 (deploy/docker/plugin-base/Dockerfile).
FROM python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

USER root
COPY --chmod=0755 fake_plugin.py /opt/fake-plugin/fake_plugin.py
USER 65534:65534

ENTRYPOINT ["python", "/opt/fake-plugin/fake_plugin.py"]
