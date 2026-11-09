# ruff: noqa
# Casi di prova delle regole Semgrep (dati, non codice da eseguire né da controllare con mypy).
import hashlib
import os
import pickle
import subprocess

import requests
import yaml


def shell(name, cur):
    # ruleid: ca-py-subprocess-shell
    subprocess.call(f"report --name {name}", shell=True)
    # ruleid: ca-py-subprocess-shell
    subprocess.run(name, shell=True)
    # ok: ca-py-subprocess-shell
    subprocess.call(["report", "--name", name])
    # ok: ca-py-subprocess-shell
    subprocess.call("ls -l", shell=True)


def oss(cmd):
    # ruleid: ca-py-os-system
    os.system("ls " + cmd)
    # ok: ca-py-os-system
    os.system("ls -l")


def ev(expression):
    # ruleid: ca-py-eval-dynamic
    eval(expression)
    # ruleid: ca-py-eval-dynamic
    exec(expression)
    # ok: ca-py-eval-dynamic
    eval("1 + 1")


def load(blob, text):
    # ruleid: ca-py-pickle-load
    pickle.loads(blob)
    # ok: ca-py-pickle-load
    pickle.dumps(blob)
    # ruleid: ca-py-yaml-unsafe-load
    yaml.load(text, Loader=yaml.Loader)
    # ruleid: ca-py-yaml-unsafe-load
    yaml.load(text)
    # ok: ca-py-yaml-unsafe-load
    yaml.load(text, Loader=yaml.SafeLoader)
    # ok: ca-py-yaml-unsafe-load
    yaml.safe_load(text)


def digest(value):
    # ruleid: ca-py-weak-hash
    hashlib.md5(value.encode())
    # ruleid: ca-py-weak-hash
    hashlib.sha1(value.encode())
    # ok: ca-py-weak-hash
    hashlib.sha256(value.encode())


def fetch(url):
    # ruleid: ca-py-tls-verify-disabled
    requests.get(url, verify=False, timeout=5)
    # ok: ca-py-tls-verify-disabled
    requests.get(url, timeout=5)
    # ok: ca-py-tls-verify-disabled
    requests.get(url, verify=True, timeout=5)


def find(cursor, name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    # ruleid: ca-py-sql-string-building
    cursor.execute(query)
    # ruleid: ca-py-sql-string-building
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    # ruleid: ca-py-sql-string-building
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
    # ok: ca-py-sql-string-building
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
    # ok: ca-py-sql-string-building
    cursor.execute("SELECT 1")
