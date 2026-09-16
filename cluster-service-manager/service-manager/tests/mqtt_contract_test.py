"""Feed the shared testdata/mqtt_contract fixtures through the real dispatch
and publish code paths, so a change to either the fixtures or the wire
format shows up as a failure here rather than only in the synthetic-payload
tests in mqtt_client_test.py.
"""

import json
from unittest.mock import MagicMock

import pytest

from interfaces import mqtt_client
from interfaces.mqtt_client import (
    handle_mqtt_message,
    mqtt_notify_service_change,
    mqtt_publish_subnetwork_result,
    mqtt_publish_tablequery_result,
)

NODE_ID = "node1"


@pytest.mark.parametrize(
    ("fixture", "topic_suffix", "handler_name"),
    [
        ("service_deployed", "net/service/deployed", "_deployment_handler"),
        (
            "service_address_changed",
            "net/service/address-changed",
            "_address_handler",
        ),
        ("interest_remove", "net/interest/remove", "_interest_remove_handler"),
        ("subnet_request", "net/subnet", "_subnet_handler"),
        (
            "tablequery_request_by_sip",
            "net/tablequery/request",
            "_tablequery_handler",
        ),
        (
            "tablequery_request_by_name",
            "net/tablequery/request",
            "_tablequery_handler",
        ),
    ],
)
def test_incoming_fixture_reaches_expected_handler(
    make_message, contract, monkeypatch, fixture, topic_suffix, handler_name
):
    handler = MagicMock()
    monkeypatch.setattr(mqtt_client, handler_name, handler)
    payload = contract(fixture)

    message = make_message(f"nodes/{NODE_ID}/{topic_suffix}", payload)
    handle_mqtt_message(MagicMock(), MagicMock(), message)

    handler.assert_called_once_with(NODE_ID, payload)


def test_tablequery_result_matches_fixture_on_the_wire(mqtt_mock, contract):
    result = contract("tablequery_result")

    mqtt_publish_tablequery_result(NODE_ID, result)

    topic, payload = mqtt_mock.publish.call_args.args
    assert topic == f"nodes/{NODE_ID}/net/tablequery/result"
    assert json.loads(payload) == result


def test_tablequery_result_csm_shape_matches_fixture_on_the_wire(mqtt_mock, contract):
    # This is the shape CSM actually emits on the echo path (host_port as a
    # string, plus the mongo-native worker_id/instance_ip* keys), as opposed to
    # tablequery_result.json, which is NM's own idealized shape. NM fails to
    # unmarshal it; that side is covered in the NM suite.
    result = contract("tablequery_result_csm_shape")

    mqtt_publish_tablequery_result(NODE_ID, result)

    topic, payload = mqtt_mock.publish.call_args.args
    assert topic == f"nodes/{NODE_ID}/net/tablequery/result"
    assert json.loads(payload) == result


def test_subnetwork_result_matches_fixture_on_the_wire(mqtt_mock, contract):
    result = contract("subnetwork_result")

    mqtt_publish_subnetwork_result(NODE_ID, result)

    topic, payload = mqtt_mock.publish.call_args.args
    assert topic == f"nodes/{NODE_ID}/net/subnetwork/result"
    assert json.loads(payload) == result


def test_updates_available_matches_fixture_on_the_wire(mqtt_mock, contract):
    job_name = "app.ns.svc.inst"
    expected = contract("updates_available")

    mqtt_notify_service_change(job_name, type=expected["type"])

    topic, payload = mqtt_mock.publish.call_args.args
    assert topic == f"jobs/{job_name}/updates_available"
    assert json.loads(payload) == expected
