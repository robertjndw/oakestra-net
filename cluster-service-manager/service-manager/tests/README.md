# cluster_service_manager tests

Characterization tests for the MQTT link between `cluster_service_manager`
(CSM) and `NetManager` (NM): they lock in the current behavior (including
quirks) so a future migration off Mosquitto can be checked against them.

## Setup

```bash
cd cluster-service-manager/service-manager
uv venv --python 3.10 .venv
source .venv/bin/activate
uv pip install -r requirements-test.txt
```

## Running

```bash
pytest                                            # unit tests; integration tests skip
OAKESTRA_TEST_MQTT_ADDR=127.0.0.1:11883 pytest -m integration -v
```

Unit tests never touch a network. Integration tests
(`tests/integration/`) need a real MQTT broker and read its address from
`OAKESTRA_TEST_MQTT_ADDR` (`host:port`); with the variable unset they
`pytest.skip()` rather than fail.

Start a broker for local runs, matching the `mqtt` service's config in
`cluster_orchestrator/docker-compose.yml` (main oakestra repo):

```bash
docker run -d --rm --name oakestra-test-mqtt -p 11883:10003 eclipse-mosquitto:2.0
export OAKESTRA_TEST_MQTT_ADDR=127.0.0.1:11883
```

Nothing in `tests/integration/` is Mosquitto-specific. A future step can
re-point `OAKESTRA_TEST_MQTT_ADDR` at a `nats-server` container running in
MQTT-compatibility mode without changing these tests.

## Fixtures

`tests/conftest.py` provides:
- `mqtt_mock`: patches the module-level `interfaces.mqtt_client.mqtt`
  client (production code always reaches it through that global, never a
  parameter).
- `make_message`: builds a fake paho `MQTTMessage` for
  `handle_mqtt_message()`.
- `contract`: loads a golden payload from
  `../../../testdata/mqtt_contract/<name>.json` (see that directory's
  README for the full topic/payload table).

`tests/integration/conftest.py` additionally provides `broker_addr`,
`node_id` (fresh per test), `csm_client` (a real, connected CSM MQTT
client), `peer` (a real paho client standing in for a worker's NetManager,
subscribed to `nodes/<node_id>/net/#`), and `wait_until` (a small polling
helper for assertions that can't be tied to a wire message).

## The star-import caveat

`interfaces/mqtt_client.py` has no `import os` or `import json` of its
own. Both arrive transitively through `from network.deployment import *`.
Don't "fix" that while patching things in this module; it's part of the
characterized behavior, not an oversight to clean up.

## `tests/__init__.py`

Stubs `interfaces.mongodb_requests` in `sys.modules` *before* any other
test module is collected/imported, so importing `interfaces.mqtt_client`
(which does `from interfaces.mongodb_requests import
mongo_find_node_by_id_and_update_subnetwork`) never touches a real Mongo
connection. Never import `service_manager.py` in a test, it calls
`mqtt_init()`/`mongo_init()` at import time.
