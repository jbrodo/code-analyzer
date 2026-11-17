# Immagine di SVILUPPO del server (I-05). Non e' l'immagine di rilascio (I-03): niente licenze di
# terzi, SBOM ne' firma, e non si distribuisce. ADR-0016, ADR-0030.
# Contesto di build: la cartella preparata da build-dev-image.sh (wheel e requirements con hash).
FROM python:3.14-slim-trixie@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt /requirements.txt
COPY dist/ /dist/
# Dipendenze di terzi dal lock del repository, con hash: mai risolte durante la build.
RUN pip install --no-cache-dir --require-hashes --no-deps -r /requirements.txt \
 && pip install --no-cache-dir --no-deps /dist/*.whl \
 && rm -rf /dist /requirements.txt \
 && mkdir -p /var/lib/ca/artifacts && chown 65532:65532 /var/lib/ca/artifacts && chmod 700 /var/lib/ca/artifacts

USER 65532:65532
EXPOSE 8000
ENV CA_API_ARTIFACTS_DIR=/var/lib/ca/artifacts
ENTRYPOINT ["python", "-m", "uvicorn", "ca_api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
