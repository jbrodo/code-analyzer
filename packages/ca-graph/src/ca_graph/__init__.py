"""Grafo dei moduli, metriche e smell architetturali (ADR-0020).

L'estrazione con tree-sitter (`ca_graph.treesitter`, G-02/G-03) gira solo nell'immagine firmata
del plugin; il resto del pacchetto lavora sul grafo come dato e importa solo `ca_core`.
"""
