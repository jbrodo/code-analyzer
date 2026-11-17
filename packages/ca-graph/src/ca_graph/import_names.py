"""Corrispondenza tra nomi di import Python e distribuzioni (ADR-0022, "Uso di una dipendenza").

Per npm il nome del pacchetto è il nome usato nell'import; per Python no. Si confrontano i nomi
normalizzati (PEP 503) più questa tabella di corrispondenze note. È incompleta per natura: una
dipendenza senza corrispondenza resta `ignota`, mai «non usata». Dato versionato: cambiarlo cambia
il risultato, quindi si alza `TABLE_VERSION`.
"""

import re

TABLE_VERSION = 1
_PEP503 = re.compile(r"[-_.]+")

# nome di import di primo livello -> distribuzioni (normalizzate) che lo forniscono
KNOWN: dict[str, frozenset[str]] = {
    "yaml": frozenset({"pyyaml"}),
    "PIL": frozenset({"pillow"}),
    "cv2": frozenset({"opencv-python", "opencv-python-headless", "opencv-contrib-python"}),
    "sklearn": frozenset({"scikit-learn"}),
    "skimage": frozenset({"scikit-image"}),
    "bs4": frozenset({"beautifulsoup4"}),
    "dateutil": frozenset({"python-dateutil"}),
    "attr": frozenset({"attrs"}),
    "attrs": frozenset({"attrs"}),
    "jwt": frozenset({"pyjwt"}),
    "OpenSSL": frozenset({"pyopenssl"}),
    "Crypto": frozenset({"pycryptodome"}),
    "Cryptodome": frozenset({"pycryptodomex"}),
    "serial": frozenset({"pyserial"}),
    "MySQLdb": frozenset({"mysqlclient"}),
    "psycopg2": frozenset({"psycopg2", "psycopg2-binary"}),
    "docx": frozenset({"python-docx"}),
    "dotenv": frozenset({"python-dotenv"}),
    "magic": frozenset({"python-magic"}),
    "git": frozenset({"gitpython"}),
    "zmq": frozenset({"pyzmq"}),
    "usb": frozenset({"pyusb"}),
    "ldap": frozenset({"python-ldap"}),
    "jose": frozenset({"python-jose"}),
    "slugify": frozenset({"python-slugify"}),
    "rest_framework": frozenset({"djangorestframework"}),
    "flask_cors": frozenset({"flask-cors"}),
    "markdown": frozenset({"markdown"}),
    "mpl_toolkits": frozenset({"matplotlib"}),
    "pkg_resources": frozenset({"setuptools"}),
    "tomllib": frozenset(),  # libreria standard, nessuna distribuzione
}


def normalize(name: str) -> str:
    return _PEP503.sub("-", name).lower()


def matches(ecosystem: str, import_name: str, package: str) -> bool:
    """Il nome di import `import_name` appartiene al pacchetto `package`?"""
    if ecosystem == "npm":
        return import_name == package
    if ecosystem != "pypi":
        return False
    wanted = normalize(package)
    if normalize(import_name) == wanted:
        return True
    return wanted in KNOWN.get(import_name, frozenset())
