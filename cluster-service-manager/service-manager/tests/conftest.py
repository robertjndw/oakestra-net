import json
import os
from pathlib import Path

import pytest
from oakestra_messaging import InMemoryBus

from interfaces import workerlink

# service-manager/tests/conftest.py -> parents[3] is the oakestra-net repo root.
CONTRACT_DIR = Path(__file__).resolve().parents[3] / "testdata" / "mqtt_contract"

# workerlink.bus_from_env() reads these unconditionally; unit tests never
# actually dial a broker, but anything that imports the module chain
# shouldn't blow up on a missing env var.
os.environ.setdefault("MQTT_BROKER_URL", "127.0.0.1")
os.environ.setdefault("MQTT_BROKER_PORT", "1883")


# Snapshotted once at collection time, before any test body runs, so this is
# guaranteed to be the real, unpatched function objects.
_PRISTINE_WORKERLINK_ATTRS = {
    name: getattr(workerlink, name)
    for name in (
        "deployment_status_report",
        "deployment_address_update",
        "notify_service_change",
        "publish_tablequery_result",
        "publish_subnetwork_result",
        "root_service_manager_get_subnet",
        "mongo_find_node_by_id_and_update_subnetwork",
    )
}


@pytest.fixture(autouse=True)
def _restore_workerlink_collaborators(monkeypatch):
    """Undo cross-test leakage before every test runs.

    A couple of the pre-existing tests (instance_deployment_and_undeployment_test.py)
    permanently reassign module-level interfaces.workerlink attributes (e.g.
    `notify_service_change = MagicMock()`) without ever restoring them, since
    they don't use monkeypatch. Left alone, that MagicMock stays in place for
    every test that runs afterwards in the same session. Reset the known
    leak-prone names before each test so results don't depend on file/test
    collection order.
    """
    for name, original in _PRISTINE_WORKERLINK_ATTRS.items():
        monkeypatch.setattr(workerlink, name, original)


@pytest.fixture
def bus():
    """A real Dispatcher wired to workerlink's handlers, without any transport.

    Production code reaches the bus only through the
    `interfaces.workerlink._bus` module global, never a parameter - tests
    deliver and inspect messages through this instance instead.
    """
    in_memory_bus = InMemoryBus()
    workerlink.start(in_memory_bus)
    yield in_memory_bus
    workerlink._bus = None


@pytest.fixture
def contract():
    """Load a golden fixture by name from testdata/mqtt_contract/<name>.json."""

    def _load(name):
        return json.loads((CONTRACT_DIR / f"{name}.json").read_text())

    return _load
