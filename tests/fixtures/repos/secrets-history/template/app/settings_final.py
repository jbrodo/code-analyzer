"""Versione finale: il token GitLab non c'e' piu', quello GitHub resta."""

import os

DEBUG = False
GITHUB_TOKEN = "@@SECRET_PAT@@"  # spostato nelle impostazioni v2
GITLAB_TOKEN = os.environ.get("GITLAB_TOKEN", "")
