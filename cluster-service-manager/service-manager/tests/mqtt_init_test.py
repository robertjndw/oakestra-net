from unittest.mock import MagicMock, patch

import pytest

from interfaces import mqtt_client
from interfaces.mqtt_client import handle_connect, handle_mqtt_message, mqtt_init


@patch("interfaces.mqtt_client.paho_mqtt.Client")
def test_mqtt_init_constructs_client_with_no_arguments(client_cls):
    mqtt_init(None)

    client_cls.assert_called_once_with()


@patch("interfaces.mqtt_client.paho_mqtt.Client")
def test_mqtt_init_sets_app_global(client_cls):
    flask_app = object()

    mqtt_init(flask_app)

    assert mqtt_client.app is flask_app


@patch("interfaces.mqtt_client.paho_mqtt.Client")
def test_mqtt_init_wires_callbacks(client_cls):
    client = client_cls.return_value

    mqtt_init(None)

    assert client.on_connect is handle_connect
    assert client.on_message is handle_mqtt_message


@patch("interfaces.mqtt_client.paho_mqtt.Client")
def test_mqtt_init_configures_reconnect_and_queue(client_cls):
    client = client_cls.return_value

    mqtt_init(None)

    client.reconnect_delay_set.assert_called_once_with(min_delay=1, max_delay=120)
    client.max_queued_messages_set.assert_called_once_with(1000)


@patch("interfaces.mqtt_client.paho_mqtt.Client")
def test_mqtt_init_connects_and_starts_loop(client_cls, monkeypatch):
    monkeypatch.setenv("MQTT_BROKER_URL", "10.0.0.5")
    monkeypatch.setenv("MQTT_BROKER_PORT", "10003")
    client = client_cls.return_value

    mqtt_init(None)

    client.connect.assert_called_once_with("10.0.0.5", 10003, keepalive=5)
    client.loop_start.assert_called_once_with()


@patch("interfaces.mqtt_client.paho_mqtt.Client")
def test_mqtt_init_strips_brackets_from_ipv6_broker_url(client_cls, monkeypatch):
    monkeypatch.setenv("MQTT_BROKER_URL", "[fc00::1]")
    monkeypatch.setenv("MQTT_BROKER_PORT", "10003")
    client = client_cls.return_value

    mqtt_init(None)

    client.connect.assert_called_once_with("fc00::1", 10003, keepalive=5)


@patch("interfaces.mqtt_client.paho_mqtt.Client")
def test_mqtt_init_skips_tls_without_mqtt_cert_env(client_cls, monkeypatch):
    monkeypatch.delenv("MQTT_CERT", raising=False)
    client = client_cls.return_value

    mqtt_init(None)

    client.tls_set.assert_not_called()


@patch("interfaces.mqtt_client.paho_mqtt.Client")
def test_mqtt_init_configures_tls_with_csm_cert_filenames(client_cls, monkeypatch):
    monkeypatch.setenv("MQTT_CERT", "/etc/oakestra/certs")
    monkeypatch.setenv("CLUSTER_SERVICE_KEYFILE_PASSWORD", "s3cret")
    client = client_cls.return_value

    mqtt_init(None)

    client.tls_set.assert_called_once_with(
        ca_certs="/etc/oakestra/certs/ca.crt",
        certfile="/etc/oakestra/certs/cluster_net.crt",
        keyfile="/etc/oakestra/certs/cluster_net.key",
        keyfile_password="s3cret",
    )


@patch("interfaces.mqtt_client.paho_mqtt.Client")
def test_mqtt_init_swallows_missing_cert_files(client_cls, monkeypatch):
    monkeypatch.setenv("MQTT_CERT", "/does/not/exist")
    client = client_cls.return_value
    client.tls_set.side_effect = FileNotFoundError("no such file")

    mqtt_init(None)  # must not raise

    client.connect.assert_called_once()  # setup continues past the TLS failure


# --------------------------------------------------------------------------- #
# The one test that leaves paho unpatched: how does the real 2.1.0 client behave
# when constructed exactly the way mqtt_init() constructs it?
# --------------------------------------------------------------------------- #


def test_real_paho_client_constructs_without_arguments():
    # requirements.txt pins paho-mqtt==2.1.0, whose Client() signature adds a
    # mandatory-looking `callback_api_version` parameter, but mqtt_init() still
    # calls `paho_mqtt.Client()` with no arguments and assigns v1-style callbacks
    # (four positional args, no `reason_code`/`properties`).
    #
    # It works anyway: `callback_api_version` defaults to
    # CallbackAPIVersion.VERSION1, which keeps the v1 callback signatures alive
    # but emits a DeprecationWarning at construction time. It does not raise.
    # See interfaces/mqtt_client.py mqtt_init()/handle_connect().
    with pytest.warns(DeprecationWarning):
        client = mqtt_client.paho_mqtt.Client()

    assert client is not None

    # Assigning the v1-signature handler must not raise at assignment time
    # either (paho only inspects the signature when it's actually invoked).
    client.on_connect = handle_connect
