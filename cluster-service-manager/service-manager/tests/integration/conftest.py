"""Fixtures for broker-backed CSM MQTT tests.

These tests need a real MQTT broker reachable at OAKESTRA_TEST_MQTT_ADDR
(host:port). Nothing here is Mosquitto-specific, so a future step can
re-point the env var at a NATS server running its MQTT-compatibility mode
without touching this file.
"""

import json
import os
import threading
import time
import uuid

import paho.mqtt.client as paho_mqtt
import pytest

from interfaces import mqtt_client

SUBACK_TIMEOUT = 5


@pytest.fixture
def broker_addr():
    addr = os.environ.get("OAKESTRA_TEST_MQTT_ADDR")
    if not addr:
        pytest.skip("OAKESTRA_TEST_MQTT_ADDR not set; skipping broker-backed test")
    host, _, port = addr.partition(":")
    return host, int(port)


@pytest.fixture
def node_id():
    # Fresh id per test: topics are node-scoped, so this keeps tests from
    # seeing each other's messages on a shared broker.
    return "it-" + uuid.uuid4().hex[:12]


@pytest.fixture
def wait_until():
    def _wait(predicate, timeout=5, interval=0.05):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(interval)
        return predicate()

    return _wait


@pytest.fixture
def csm_client(broker_addr, monkeypatch):
    """Run the real mqtt_init() against the test broker.

    Waits for the SUBACK on `nodes/+/net/#` before handing control back, by
    monkeypatching handle_connect itself (patched before mqtt_init() is
    called, so mqtt_init's `mqtt.on_connect = handle_connect` picks up the
    wrapped version) rather than racing to attach on_subscribe after the
    fact.
    """
    host, port = broker_addr
    monkeypatch.setenv("MQTT_BROKER_URL", host)
    monkeypatch.setenv("MQTT_BROKER_PORT", str(port))
    monkeypatch.delenv("MQTT_CERT", raising=False)

    subscribed = threading.Event()
    original_handle_connect = mqtt_client.handle_connect

    def handle_connect_and_signal(client, userdata, flags, rc):
        client.on_subscribe = lambda *a, **kw: subscribed.set()
        original_handle_connect(client, userdata, flags, rc)

    monkeypatch.setattr(mqtt_client, "handle_connect", handle_connect_and_signal)

    mqtt_client.mqtt_init(None)
    if not subscribed.wait(timeout=SUBACK_TIMEOUT):
        pytest.fail("CSM client never received a SUBACK for nodes/+/net/#")

    yield mqtt_client.mqtt

    mqtt_client.mqtt.loop_stop()
    mqtt_client.mqtt.disconnect()
    mqtt_client.mqtt = None


class Peer:
    """A plain paho client standing in for a NetManager worker node."""

    def __init__(self, host, port):
        self._connected = threading.Event()
        self._sub_events = {}
        self._lock = threading.Lock()
        self._messages = []
        self._messages_lock = threading.Lock()
        self._messages_cv = threading.Condition(self._messages_lock)

        self._client = paho_mqtt.Client()
        self._client.on_connect = self._on_connect
        self._client.on_subscribe = self._on_subscribe
        self._client.on_message = self._on_message
        self._client.connect(host, port, keepalive=5)
        self._client.loop_start()
        if not self._connected.wait(timeout=5):
            raise TimeoutError("peer never connected to the test broker")

    def _on_connect(self, client, userdata, flags, rc):
        self._connected.set()

    def _on_subscribe(self, client, userdata, mid, granted_qos, properties=None):
        with self._lock:
            event = self._sub_events.pop(mid, None)
        if event is not None:
            event.set()

    def _on_message(self, client, userdata, message):
        with self._messages_cv:
            self._messages.append((message.topic, message.payload, message.qos))
            self._messages_cv.notify_all()

    def subscribe(self, topic, qos=1, timeout=5):
        event = threading.Event()
        _, mid = self._client.subscribe(topic, qos=qos)
        with self._lock:
            self._sub_events[mid] = event
        if not event.wait(timeout=timeout):
            raise TimeoutError(f"no SUBACK for {topic!r} within {timeout}s")

    def publish_json(self, topic, payload, qos=1):
        self._client.publish(topic, json.dumps(payload), qos=qos)

    def publish_raw(self, topic, raw, qos=1):
        self._client.publish(topic, raw, qos=qos)

    def wait_for(self, topic, timeout=5):
        """Return (parsed_json_payload, qos) for the first message seen on
        `topic`, leaving any other buffered messages in place for later
        wait_for() calls.
        """
        deadline = time.monotonic() + timeout
        with self._messages_cv:
            while True:
                for i, (got_topic, payload, qos) in enumerate(self._messages):
                    if got_topic == topic:
                        del self._messages[i]
                        return json.loads(payload.decode()), qos
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"no message on {topic!r} within {timeout}s")
                self._messages_cv.wait(timeout=remaining)

    def stop(self):
        self._client.loop_stop()
        self._client.disconnect()


@pytest.fixture
def peer(broker_addr, node_id):
    host, port = broker_addr
    p = Peer(host, port)
    p.subscribe(f"nodes/{node_id}/net/#", qos=1)

    yield p

    p.stop()
