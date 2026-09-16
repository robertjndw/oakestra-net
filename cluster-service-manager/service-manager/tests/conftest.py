import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from interfaces import mqtt_client

# service-manager/tests/conftest.py -> parents[3] is the oakestra-net repo root.
CONTRACT_DIR = Path(__file__).resolve().parents[3] / "testdata" / "mqtt_contract"

# mqtt_init() reads these unconditionally; unit tests never actually dial a
# broker, but anything that imports the module chain shouldn't blow up on a
# missing env var.
os.environ.setdefault("MQTT_BROKER_URL", "127.0.0.1")
os.environ.setdefault("MQTT_BROKER_PORT", "1883")


# Snapshotted once at collection time, before any test body runs, so this is
# guaranteed to be the real, unpatched function objects.
_PRISTINE_MQTT_CLIENT_ATTRS = {
    name: getattr(mqtt_client, name)
    for name in (
        "deployment_status_report",
        "deployment_address_update",
        "mqtt_notify_service_change",
        "mqtt_publish_tablequery_result",
        "mqtt_publish_subnetwork_result",
        "root_service_manager_get_subnet",
        "mongo_find_node_by_id_and_update_subnetwork",
    )
}


@pytest.fixture(autouse=True)
def _restore_mqtt_client_collaborators(monkeypatch):
    """Undo cross-test leakage before every test runs.

    A couple of the pre-existing tests (instance_deployment_and_undeployment_test.py)
    permanently reassign module-level interfaces.mqtt_client attributes (e.g.
    `mqtt_notify_service_change = MagicMock()`) without ever restoring them, since
    they don't use monkeypatch. Left alone, that MagicMock stays in place for
    every test that runs afterwards in the same session. Reset the known
    leak-prone names before each test so results don't depend on file/test
    collection order.
    """
    for name, original in _PRISTINE_MQTT_CLIENT_ATTRS.items():
        monkeypatch.setattr(mqtt_client, name, original)


@pytest.fixture
def mqtt_mock(monkeypatch):
    """Stand in for the module-level `mqtt` client.

    Production code always reaches the client through the `interfaces.mqtt_client.mqtt`
    global (never a parameter), so tests patch that global directly rather than
    passing a client around.
    """
    client = MagicMock()
    monkeypatch.setattr(mqtt_client, "mqtt", client)
    return client


@pytest.fixture
def make_message():
    """Build a fake paho MQTTMessage for feeding into handle_mqtt_message()."""

    def _make(topic, payload):
        raw = payload if isinstance(payload, (bytes, str)) else json.dumps(payload)
        message = MagicMock()
        message.topic = topic
        message.payload = raw.encode() if isinstance(raw, str) else raw
        return message

    return _make


@pytest.fixture
def contract():
    """Load a golden fixture by name from testdata/mqtt_contract/<name>.json."""

    def _load(name):
        return json.loads((CONTRACT_DIR / f"{name}.json").read_text())

    return _load
