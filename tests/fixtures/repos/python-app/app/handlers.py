"""Gestori con problemi SAST noti. Non eseguire."""

import hashlib
import pickle
import subprocess

import requests
import yaml


def run_report(name: str) -> int:
    return subprocess.call(f"report --name {name}", shell=True)


def load_session(blob: bytes) -> object:
    return pickle.loads(blob)


def load_settings(text: str) -> object:
    return yaml.load(text, Loader=yaml.Loader)


def digest(value: str) -> str:
    return hashlib.md5(value.encode()).hexdigest()


def fetch(url: str) -> bytes:
    return requests.get(url, verify=False, timeout=5).content


def calculate(expression: str) -> object:
    return eval(expression)
