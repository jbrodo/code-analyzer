"""Dipendenze FastAPI: l'identità autenticata della richiesta (B-04, ADR-0019)."""

from typing import Annotated

from fastapi import Depends, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ca_api.auth.verify import AuthError, Identity
from ca_api.problem import ApiProblem, ProblemCode

bearer = HTTPBearer(
    scheme_name="oidc",
    bearerFormat="JWT",
    auto_error=False,
    description=(
        "Token di accesso OIDC (ADR-0019): un JWT firmato da un emittente configurato, di un "
        "utente o di una pipeline. Il server non emette token."
    ),
)
Credentials = Annotated[HTTPAuthorizationCredentials | None, Security(bearer)]
CHALLENGE = {"WWW-Authenticate": 'Bearer error="invalid_token"'}


def authenticate(request: Request, credentials: Credentials) -> Identity:
    """L'identità del token. 401 senza token o se non è valido; 403 se non è ammesso."""
    verifier = request.app.state.verifier
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise ApiProblem(401, ProblemCode.UNAUTHENTICATED, headers={"WWW-Authenticate": "Bearer"})
    if verifier is None:
        raise ApiProblem(401, ProblemCode.UNAUTHENTICATED, headers=CHALLENGE)
    try:
        return verifier.verify(credentials.credentials)  # type: ignore[no-any-return]
    except AuthError as exc:
        if exc.forbidden:
            raise ApiProblem(403, ProblemCode.FORBIDDEN, detail=f"codice: {exc.code}") from None
        raise ApiProblem(
            401, ProblemCode.UNAUTHENTICATED, detail=f"codice: {exc.code}", headers=CHALLENGE
        ) from None


CurrentIdentity = Annotated[Identity, Depends(authenticate)]
