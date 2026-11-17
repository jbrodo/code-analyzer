"""Integrazione con GitHub (N-02, ADR-0027): commento sulla PR e check run."""

from ca_integrations.github.client import CommentResult, GitHubClient, GitHubError
from ca_integrations.github.transport import Response, Transport, TransportError, UrllibTransport

__all__ = [
    "CommentResult",
    "GitHubClient",
    "GitHubError",
    "Response",
    "Transport",
    "TransportError",
    "UrllibTransport",
]
