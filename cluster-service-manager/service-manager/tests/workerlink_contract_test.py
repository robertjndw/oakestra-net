"""Feed the shared testdata/mqtt_contract fixtures through the real dispatch
and publish code paths, so a change to either the fixtures or the wire
format shows up as a failure here rather than only in the synthetic-payload
tests in workerlink_test.py.
"""

import json
from unittest.mock import MagicMock

import pytest
from oakestra_messaging import Message

from interfaces import workerlink
from interfaces.workerlink import (
    notify_service_change,
    publish_subnetwork_result,
    publish_tablequery_result,
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
    bus, contract, monkeypatch, fixture, topic_suffix, handler_name
):
    handler = MagicMock()
    monkeypatch.setattr(workerlink, handler_name, handler)
    payload = contract(fixture)

    bus.deliver(f"nodes/{NODE_ID}/{topic_suffix}", json.dumps(payload))

    handler.assert_called_once_with(NODE_ID, payload)


def test_tablequery_result_matches_fixture_on_the_wire(bus, contract):
    result = contract("tablequery_result")

    publish_tablequery_result(NODE_ID, result)

    assert bus.published[-1] == Message(
        f"nodes/{NODE_ID}/net/tablequery/result", json.dumps(result).encode()
    )


def test_tablequery_result_csm_shape_matches_fixture_on_the_wire(bus, contract):
    # This is the shape CSM actually emits on the echo path (host_port as a
    # string, plus the mongo-native worker_id/instance_ip* keys), as opposed to
    # tablequery_result.json, which is NM's own idealized shape. NM fails to
    # unmarshal it; that side is covered in the NM suite.
    result = contract("tablequery_result_csm_shape")

    publish_tablequery_result(NODE_ID, result)

    assert bus.published[-1] == Message(
        f"nodes/{NODE_ID}/net/tablequery/result", json.dumps(result).encode()
    )


def test_subnetwork_result_matches_fixture_on_the_wire(bus, contract):
    result = contract("subnetwork_result")

    publish_subnetwork_result(NODE_ID, result)

    assert bus.published[-1] == Message(
        f"nodes/{NODE_ID}/net/subnetwork/result", json.dumps(result).encode()
    )


def test_updates_available_matches_fixture_on_the_wire(bus, contract):
    job_name = "app.ns.svc.inst"
    expected = contract("updates_available")

    notify_service_change(job_name, type=expected["type"])

    assert bus.published[-1] == Message(
        f"jobs/{job_name}/updates_available", json.dumps(expected).encode()
    )
