# SPDX-License-Identifier: AGPL-3.0-only
"""Utilita' copiata da un progetto terzo: la licenza rende il file soggetto a policy."""


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(value, high))
