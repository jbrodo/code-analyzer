"""Limiti all'ingestione per repository e per tenant (S1-A2 di `sicurezza-fase-2.md`, ADR-0016).

Una pipeline compromessa, o un tenant, non deve poter esaurire disco, database o costo dell'archivio
con una raffica di ingestioni. Due tetti, entrambi in configurazione (0 li spegne):

- **per repository nell'ora:** ogni tentativo conta, anche se poi si rifiuta, perché un report
  invalido costa comunque lettura e validazione. Finestra mobile di un'ora.
- **in parallelo per tenant:** le ingestioni che girano insieme, per non saturare il pool del
  database e la memoria (ogni parte arriva a decine di MiB).

Oltre il tetto: 429 `rate-limited` con `Retry-After`. Lo stato sta nel processo: con più repliche il
tetto vale per replica (limite dichiarato). La quota di byte per tenant non c'è ancora.
"""

import threading
from collections import defaultdict, deque
from collections.abc import Generator, Hashable
from contextlib import contextmanager
from datetime import datetime

from ca_api.problem import ApiProblem, ProblemCode

WINDOW_SECONDS = 3600
BUSY_RETRY_SECONDS = 5


class IngestThrottle:
    def __init__(self, *, per_hour: int, concurrent: int) -> None:
        self._per_hour, self._concurrent = per_hour, concurrent
        self._lock = threading.Lock()
        self._attempts: defaultdict[Hashable, deque[float]] = defaultdict(deque)
        self._running: defaultdict[str, int] = defaultdict(int)

    def admit(self, repository: Hashable, now: datetime) -> None:
        """Conta un tentativo del repository o rifiuta con 429 se la finestra è piena."""
        if self._per_hour <= 0:
            return
        moment = now.timestamp()
        with self._lock:
            window = self._attempts[repository]
            while window and window[0] <= moment - WINDOW_SECONDS:
                window.popleft()
            if len(window) >= self._per_hour:
                wait = max(1, int(window[0] + WINDOW_SECONDS - moment) + 1)
                raise ApiProblem(
                    429,
                    ProblemCode.RATE_LIMITED,
                    detail="troppe ingestioni per questo repository nell'ultima ora",
                    headers={"Retry-After": str(wait)},
                )
            window.append(moment)

    @contextmanager
    def slot(self, tenant: str) -> Generator[None]:
        """Un posto tra le ingestioni in parallelo del tenant, sempre rilasciato."""
        if self._concurrent > 0:
            with self._lock:
                if self._running[tenant] >= self._concurrent:
                    raise ApiProblem(
                        429,
                        ProblemCode.RATE_LIMITED,
                        detail="troppe ingestioni in corso per questo tenant",
                        headers={"Retry-After": str(BUSY_RETRY_SECONDS)},
                    )
                self._running[tenant] += 1
        try:
            yield
        finally:
            if self._concurrent > 0:
                with self._lock:
                    self._running[tenant] -= 1
