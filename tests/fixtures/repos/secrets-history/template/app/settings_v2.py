"""Impostazioni di esempio della fixture secrets-history (seconda versione)."""

import os

DEBUG = False
GITHUB_TOKEN = "@@SECRET_PAT@@"  # spostato nelle impostazioni v2
REGION = os.environ.get("REGION", "eu-west-1")
