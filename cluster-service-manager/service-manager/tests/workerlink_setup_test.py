import oakestra_messaging.mqtt as messaging_mqtt
import pytest
from oakestra_messaging import MqttBus

from interfaces import workerlink


def test_bus_from_env_returns_mqtt_bus_qos_1(monkeypatch):
    monkeypatch.setenv("MQTT_BROKER_URL", "127.0.0.1")
    monkeypatch.setenv("MQTT_BROKER_PORT", "1883")
    monkeypatch.delenv("MQTT_CERT", raising=False)

    bus = workerlink.bus_from_env()

    assert isinstance(bus, MqttBus)
    assert bus.qos == 1


def test_bus_from_env_configures_tls_with_csm_cert_filenames(monkeypatch):
    # tls_set() runs eagerly in MqttBus.__init__ against a real paho client;
    # stub it out so this doesn't need real cert files on disk.
    monkeypatch.setattr(
        messaging_mqtt.paho.Client, "tls_set", lambda self, **kwargs: None
    )
    monkeypatch.setenv("MQTT_BROKER_URL", "127.0.0.1")
    monkeypatch.setenv("MQTT_BROKER_PORT", "1883")
    monkeypatch.setenv("MQTT_CERT", "/certs")
    monkeypatch.setenv("CLUSTER_SERVICE_KEYFILE_PASSWORD", "s3cret")

    bus = workerlink.bus_from_env()

    assert bus.tls.ca_certs == "/certs/ca.crt"
    assert bus.tls.certfile == "/certs/cluster_net.crt"
    assert bus.tls.keyfile == "/certs/cluster_net.key"
    assert bus.tls.keyfile_password == "s3cret"


def test_bus_from_env_unsupported_backend_raises_value_error(monkeypatch):
    monkeypatch.setenv("MESSAGING_BACKEND", "nats")
    monkeypatch.setenv("MQTT_BROKER_URL", "127.0.0.1")
    monkeypatch.setenv("MQTT_BROKER_PORT", "1883")

    with pytest.raises(ValueError):
        workerlink.bus_from_env()
