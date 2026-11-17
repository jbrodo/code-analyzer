"""`EnrichmentFeeds` su tabelle già lette e validate (E-01, ADR-0024). Nessun I/O."""

from ca_core.ports import EpssAnswer, FeedSnapshot, FeedStatus, KevAnswer, validate_cve
from ca_core.scoring.feeds.parse import EpssTable, KevTable


class SnapshotFeeds:
    """Una tabella assente (snapshot non disponibile) risponde `snapshot-absent`, che non si
    confonde con `not-listed`: lo snapshot c'è e la CVE non è nell'elenco."""

    def __init__(
        self,
        epss: EpssTable | None = None,
        kev: KevTable | None = None,
        snapshots: list[FeedSnapshot] | None = None,
    ) -> None:
        self._epss, self._kev = epss, kev
        self._snapshots = sorted(snapshots or [], key=lambda s: s.feed)

    def epss(self, cve: str) -> EpssAnswer:
        validate_cve(cve)
        if self._epss is None:
            return EpssAnswer(status=FeedStatus.SNAPSHOT_ABSENT)
        found = self._epss.entries.get(cve)
        if found is None:
            return EpssAnswer(status=FeedStatus.NOT_LISTED)
        return EpssAnswer(status=FeedStatus.FOUND, score=found[0], percentile=found[1])

    def kev(self, cve: str) -> KevAnswer:
        validate_cve(cve)
        if self._kev is None:
            return KevAnswer(status=FeedStatus.SNAPSHOT_ABSENT)
        found = self._kev.entries.get(cve)
        if found is None:
            return KevAnswer(status=FeedStatus.NOT_LISTED)
        added, ransomware = found
        use = "Known" if ransomware == "Known" else "Unknown" if ransomware == "Unknown" else None
        return KevAnswer(status=FeedStatus.FOUND, date_added=added, ransomware_use=use)

    def snapshots(self) -> list[FeedSnapshot]:
        return list(self._snapshots)
