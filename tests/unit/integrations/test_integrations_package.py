"""N-01: il pacchetto è nel workspace e importabile (ADR-0027)."""

import ca_integrations


def test_package_imports() -> None:
    assert ca_integrations.__doc__
