"""The campaign tests share the outside tests' scripted transport, clock and lookup service."""

from tests.integration.cases.conftest import people  # noqa: F401 - fixture
from tests.integration.outside.conftest import clock, make_outside  # noqa: F401 - fixtures
