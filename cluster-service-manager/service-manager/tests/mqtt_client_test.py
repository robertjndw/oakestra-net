import json
from unittest.mock import MagicMock

import pytest

from interfaces import mqtt_client
from interfaces.mqtt_client import (
    _address_handler,
    _deployment_handler,
    _interest_remove_handler,
    _subnet_handler,
    _tablequery_handler,
    _undeployment_handler,
    handle_connect,
    handle_mqtt_message,
    mqtt_notify_service_change,
    mqtt_publish_subnetwork_result,
    mqtt_publish_tablequery_result,
)

HANDLER_NAMES = [
    "_deployment_handler",
    "_undeployment_handler",
    "_address_handler",
    "_tablequery_handler",
    "_subnet_handler",
    "_interest_remove_handler",
]


@pytest.fixture
def all_handlers_mocked(monkeypatch):
    """Replace all six dispatch targets with MagicMocks and hand back the dict."""
    mocks = {}
    for name in HANDLER_NAMES:
        mock = MagicMock()
        monkeypatch.setattr(mqtt_client, name, mock)
        mocks[name] = mock
    return mocks


def _dispatch(make_message, topic, payload):
    handle_mqtt_message(MagicMock(), MagicMock(), make_message(topic, payload))


# --------------------------------------------------------------------------- #
# handle_connect
# --------------------------------------------------------------------------- #


def test_handle_connect_subscribes_net_wildcard_qos1(mqtt_mock):
    handle_connect(MagicMock(), None, {}, 0)

    mqtt_mock.subscribe.assert_called_once_with(topic="nodes/+/net/#", qos=1)


def test_handle_connect_ignores_its_client_argument(mqtt_mock):
    # handle_connect subscribes via the module-global `mqtt`, not the `client`
    # paho hands it. In production these are the same object; passing a distinct
    # object here shows the parameter is unused.
    unrelated_client = MagicMock()

    handle_connect(unrelated_client, None, {}, 0)

    unrelated_client.subscribe.assert_not_called()
    mqtt_mock.subscribe.assert_called_once_with(topic="nodes/+/net/#", qos=1)


# --------------------------------------------------------------------------- #
# handle_mqtt_message dispatch
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("topic", "handler_name"),
    [
        ("nodes/n1/net/service/deployed", "_deployment_handler"),
        ("nodes/n1/net/service/undeployed", "_undeployment_handler"),
        ("nodes/n1/net/service/address-changed", "_address_handler"),
        ("nodes/n1/net/tablequery/request", "_tablequery_handler"),
        ("nodes/n1/net/subnet", "_subnet_handler"),
        ("nodes/n1/net/interest/remove", "_interest_remove_handler"),
    ],
)
def test_dispatch_routes_topic_to_handler(
    make_message, all_handlers_mocked, topic, handler_name
):
    payload = {"some": "value"}

    _dispatch(make_message, topic, payload)

    all_handlers_mocked[handler_name].assert_called_once_with("n1", payload)
    for name, mock in all_handlers_mocked.items():
        if name != handler_name:
            mock.assert_not_called()


def test_subnetwork_result_echo_runs_subnet_handler(make_message, all_handlers_mocked):
    # The broker echoes CSM's own publishes back to it because of the
    # `nodes/+/net/#` wildcard subscription. `^nodes/.*/net/subnet` has no
    # trailing anchor, so it also matches ".../net/subnetwork/result".
    payload = {"address": "10.19.1.0", "addressv6": "fc00:1::"}

    _dispatch(make_message, "nodes/n1/net/subnetwork/result", payload)

    all_handlers_mocked["_subnet_handler"].assert_called_once_with("n1", payload)


def test_tablequery_result_echo_runs_no_handler(make_message, all_handlers_mocked):
    # Unlike the subnet echo above, the tablequery/result echo matches none of
    # the six regexes (none of them look for ".../net/tablequery/result").
    payload = {"app_name": "a", "instance_list": [], "query_key": "a"}

    _dispatch(make_message, "nodes/n1/net/tablequery/result", payload)

    for mock in all_handlers_mocked.values():
        mock.assert_not_called()


def test_main_repo_topics_run_no_handler(make_message, all_handlers_mocked):
    # CM/NE's own topics never contain "/net/", so they can't match any of
    # CSM's regexes even though both share one broker.
    for topic in ("nodes/n1/information", "nodes/n1/job", "nodes/n1/jobs/resources"):
        _dispatch(make_message, topic, {"anything": "goes"})

    for mock in all_handlers_mocked.values():
        mock.assert_not_called()


def test_client_id_is_second_segment(make_message, all_handlers_mocked):
    _dispatch(make_message, "nodes/abc-305/net/interest/remove", {"appname": "a"})

    all_handlers_mocked["_interest_remove_handler"].assert_called_once_with(
        "abc-305", {"appname": "a"}
    )


def test_extra_suffix_still_matches(make_message, all_handlers_mocked):
    # None of the six regexes anchor with `$`, so trailing path segments are
    # silently accepted.
    _dispatch(
        make_message, "nodes/n1/net/service/deployed/unexpected/suffix", {"a": 1}
    )

    all_handlers_mocked["_deployment_handler"].assert_called_once_with(
        "n1", {"a": 1}
    )


def test_non_json_payload_raises_before_dispatch(make_message, all_handlers_mocked):
    message = make_message("nodes/n1/net/subnet", "not-json")

    with pytest.raises(json.JSONDecodeError):
        handle_mqtt_message(MagicMock(), MagicMock(), message)

    for mock in all_handlers_mocked.values():
        mock.assert_not_called()


# --------------------------------------------------------------------------- #
# _deployment_handler
# --------------------------------------------------------------------------- #


def test_deployment_handler_forwards_fields_in_order(monkeypatch):
    recorder = MagicMock()
    monkeypatch.setattr(mqtt_client, "deployment_status_report", recorder)
    payload = {
        "appname": "app.ns.svc.inst",
        "status": "DEPLOYED",
        "nsip": "10.19.1.2",
        "nsipv6": "fc00::2",
        "instance_number": 0,
        "host_ip": "192.168.1.10",
        "host_port": "50103",
    }

    _deployment_handler("n1", payload)

    recorder.assert_called_once_with(
        "app.ns.svc.inst", "DEPLOYED", "10.19.1.2", "fc00::2", "n1", 0,
        "192.168.1.10", "50103",
    )


def test_deployment_handler_missing_keys_become_none(monkeypatch):
    recorder = MagicMock()
    monkeypatch.setattr(mqtt_client, "deployment_status_report", recorder)

    _deployment_handler("n1", {})

    recorder.assert_called_once_with(None, None, None, None, "n1", None, None, None)


def test_deployment_handler_swallows_exceptions(monkeypatch):
    monkeypatch.setattr(
        mqtt_client, "deployment_status_report", MagicMock(side_effect=RuntimeError)
    )

    _deployment_handler("n1", {"appname": "a"})  # must not raise


# --------------------------------------------------------------------------- #
# _undeployment_handler
# --------------------------------------------------------------------------- #


def test_undeployment_handler_is_noop():
    # Still a TODO in production. Asserting the no-op means a real implementation
    # shows up here as a deliberate change later.
    assert _undeployment_handler("n1", {"appname": "a"}) is None


# --------------------------------------------------------------------------- #
# _address_handler
# --------------------------------------------------------------------------- #


def test_address_handler_forwards_fields(monkeypatch):
    recorder = MagicMock()
    monkeypatch.setattr(mqtt_client, "deployment_address_update", recorder)
    payload = {
        "appname": "app.ns.svc.inst",
        "instance_number": 0,
        "host_ip": "192.168.1.11",
        "host_port": "50103",
    }

    _address_handler("n1", payload)

    recorder.assert_called_once_with(
        "app.ns.svc.inst", "n1", 0, "192.168.1.11", "50103"
    )


def test_address_handler_missing_keys_become_none(monkeypatch):
    recorder = MagicMock()
    monkeypatch.setattr(mqtt_client, "deployment_address_update", recorder)

    _address_handler("n1", {})

    recorder.assert_called_once_with(None, "n1", None, None, None)


def test_address_handler_swallows_exceptions(monkeypatch):
    monkeypatch.setattr(
        mqtt_client, "deployment_address_update", MagicMock(side_effect=RuntimeError)
    )

    _address_handler("n1", {"appname": "a"})  # must not raise


# --------------------------------------------------------------------------- #
# _interest_remove_handler
# --------------------------------------------------------------------------- #


def test_interest_remove_handler_calls_remove_interest(monkeypatch):
    remove_interest = MagicMock()
    monkeypatch.setattr(mqtt_client.interests, "remove_interest", remove_interest)

    _interest_remove_handler("n1", {"appname": "app.ns.svc.inst"})

    remove_interest.assert_called_once_with("app.ns.svc.inst", "n1")


def test_interest_remove_handler_missing_appname_passes_none(monkeypatch):
    remove_interest = MagicMock()
    monkeypatch.setattr(mqtt_client.interests, "remove_interest", remove_interest)

    _interest_remove_handler("n1", {})

    remove_interest.assert_called_once_with(None, "n1")


# --------------------------------------------------------------------------- #
# _tablequery_handler
# --------------------------------------------------------------------------- #


def test_tablequery_handler_sip_takes_precedence_over_sname(monkeypatch):
    add_interest = MagicMock()
    publish = MagicMock()
    monkeypatch.setattr(mqtt_client.interests, "add_interest", add_interest)
    monkeypatch.setattr(mqtt_client, "mqtt_publish_tablequery_result", publish)
    resolution_ip = MagicMock(return_value=("resolved.name", [], []))
    resolution_name = MagicMock()
    monkeypatch.setattr(mqtt_client.resolution, "service_resolution_ip", resolution_ip)
    monkeypatch.setattr(mqtt_client.resolution, "service_resolution", resolution_name)

    _tablequery_handler("n1", {"sname": "ignored.name", "sip": "10.30.0.1"})

    resolution_ip.assert_called_once_with("10.30.0.1")
    resolution_name.assert_not_called()
    # query_key is the sip, but app_name is whatever service_resolution_ip
    # resolved: it overwrites the "sname" from the payload.
    add_interest.assert_called_once_with("resolved.name", "n1")
    publish.assert_called_once_with(
        "n1",
        {"app_name": "resolved.name", "instance_list": [], "query_key": "10.30.0.1"},
    )


def test_tablequery_handler_resolution_exception_still_publishes(monkeypatch):
    add_interest = MagicMock()
    publish = MagicMock()
    monkeypatch.setattr(mqtt_client.interests, "add_interest", add_interest)
    monkeypatch.setattr(mqtt_client, "mqtt_publish_tablequery_result", publish)
    monkeypatch.setattr(
        mqtt_client.resolution,
        "service_resolution_ip",
        MagicMock(side_effect=RuntimeError("db down")),
    )

    _tablequery_handler("n1", {"sname": "app.ns.svc.inst", "sip": "10.30.0.1"})

    # serviceName keeps its pre-exception value (the sname from the payload,
    # never overwritten by the failed unpack), instance_list/siplist stay empty.
    add_interest.assert_called_once_with("app.ns.svc.inst", "n1")
    publish.assert_called_once_with(
        "n1",
        {
            "app_name": "app.ns.svc.inst",
            "instance_list": [],
            "query_key": "10.30.0.1",
        },
    )


def test_tablequery_handler_both_missing_publishes_none_app_name(monkeypatch):
    # Both keys absent (payload.get(...) -> None), not merely empty strings.
    # An empty-string "sname" is falsy the same way but stays "" rather than
    # becoming None, so the missing-key case is covered separately here.
    add_interest = MagicMock()
    publish = MagicMock()
    monkeypatch.setattr(mqtt_client.interests, "add_interest", add_interest)
    monkeypatch.setattr(mqtt_client, "mqtt_publish_tablequery_result", publish)

    _tablequery_handler("n1", {})

    add_interest.assert_called_once_with(None, "n1")
    publish.assert_called_once_with(
        "n1", {"app_name": None, "instance_list": [], "query_key": ""}
    )


def test_tablequery_handler_both_empty_strings_publishes_empty_app_name(monkeypatch):
    # Same code path as above, but "" is never reassigned, so it stays ""
    # instead of becoming None.
    add_interest = MagicMock()
    publish = MagicMock()
    monkeypatch.setattr(mqtt_client.interests, "add_interest", add_interest)
    monkeypatch.setattr(mqtt_client, "mqtt_publish_tablequery_result", publish)

    _tablequery_handler("n1", {"sname": "", "sip": ""})

    add_interest.assert_called_once_with("", "n1")
    publish.assert_called_once_with(
        "n1", {"app_name": "", "instance_list": [], "query_key": ""}
    )


def test_tablequery_handler_publishes_to_result_topic(monkeypatch, mqtt_mock):
    # Use the real mqtt_publish_tablequery_result here (not mocked) to check the
    # exact wire topic.
    monkeypatch.setattr(mqtt_client.interests, "add_interest", MagicMock())
    monkeypatch.setattr(
        mqtt_client.resolution,
        "service_resolution",
        MagicMock(return_value=([], [])),
    )

    _tablequery_handler("n1", {"sname": "app.ns.svc.inst", "sip": ""})

    topic, payload = mqtt_mock.publish.call_args.args
    assert topic == "nodes/n1/net/tablequery/result"
    assert json.loads(payload) == {
        "app_name": "app.ns.svc.inst",
        "instance_list": [],
        "query_key": "app.ns.svc.inst",
    }
    assert mqtt_mock.publish.call_args.kwargs == {"qos": 1}


# --------------------------------------------------------------------------- #
# _subnet_handler
# --------------------------------------------------------------------------- #


def test_subnet_handler_get_success(monkeypatch):
    monkeypatch.setattr(
        mqtt_client,
        "root_service_manager_get_subnet",
        MagicMock(return_value=["10.19.1.0", "fc00:1::"]),
    )
    mongo_update = MagicMock()
    monkeypatch.setattr(
        mqtt_client, "mongo_find_node_by_id_and_update_subnetwork", mongo_update
    )
    publish = MagicMock()
    monkeypatch.setattr(mqtt_client, "mqtt_publish_subnetwork_result", publish)

    _subnet_handler("n1", {"METHOD": "GET"})

    mongo_update.assert_called_once_with("n1", "10.19.1.0", "fc00:1::")
    publish.assert_called_once_with(
        "n1", {"address": "10.19.1.0", "addressv6": "fc00:1::"}
    )


def test_subnet_handler_get_with_none_subnet_skips_mongo_and_publish(monkeypatch):
    monkeypatch.setattr(
        mqtt_client, "root_service_manager_get_subnet", MagicMock(return_value=None)
    )
    mongo_update = MagicMock()
    publish = MagicMock()
    monkeypatch.setattr(
        mqtt_client, "mongo_find_node_by_id_and_update_subnetwork", mongo_update
    )
    monkeypatch.setattr(mqtt_client, "mqtt_publish_subnetwork_result", publish)

    _subnet_handler("n1", {"METHOD": "GET"})

    mongo_update.assert_not_called()
    publish.assert_not_called()


def test_subnet_handler_get_exception_swallowed(monkeypatch):
    monkeypatch.setattr(
        mqtt_client,
        "root_service_manager_get_subnet",
        MagicMock(side_effect=RuntimeError("boom")),
    )

    _subnet_handler("n1", {"METHOD": "GET"})  # must not raise


def test_subnet_handler_delete_is_noop(monkeypatch):
    get_subnet = MagicMock()
    monkeypatch.setattr(mqtt_client, "root_service_manager_get_subnet", get_subnet)

    _subnet_handler("n1", {"METHOD": "DELETE"})

    get_subnet.assert_not_called()


def test_subnet_handler_missing_method_is_noop(monkeypatch):
    get_subnet = MagicMock()
    monkeypatch.setattr(mqtt_client, "root_service_manager_get_subnet", get_subnet)

    _subnet_handler("n1", {})

    get_subnet.assert_not_called()


# --------------------------------------------------------------------------- #
# publish functions
# --------------------------------------------------------------------------- #


def test_mqtt_publish_tablequery_result(mqtt_mock):
    result = {"app_name": "a", "instance_list": [], "query_key": "a"}

    mqtt_publish_tablequery_result("n1", result)

    mqtt_mock.publish.assert_called_once_with(
        "nodes/n1/net/tablequery/result", json.dumps(result), qos=1
    )


def test_mqtt_publish_subnetwork_result(mqtt_mock):
    result = {"address": "10.19.1.0", "addressv6": "fc00:1::"}

    mqtt_publish_subnetwork_result("n1", result)

    mqtt_mock.publish.assert_called_once_with(
        "nodes/n1/net/subnetwork/result", json.dumps(result), qos=1
    )


def test_mqtt_notify_service_change_default_type_is_null(mqtt_mock):
    mqtt_notify_service_change("app.ns.svc.inst")

    mqtt_mock.publish.assert_called_once_with(
        "jobs/app.ns.svc.inst/updates_available", json.dumps({"type": None}), qos=1
    )


def test_mqtt_notify_service_change_with_type(mqtt_mock):
    mqtt_notify_service_change("app.ns.svc.inst", type="DEPLOYMENT")

    mqtt_mock.publish.assert_called_once_with(
        "jobs/app.ns.svc.inst/updates_available",
        json.dumps({"type": "DEPLOYMENT"}),
        qos=1,
    )


def test_mqtt_notify_service_change_job_name_can_be_an_ip(mqtt_mock):
    # `<job>` in jobs/<job>/updates_available may be a service IP string, not a
    # job name. The function has no notion of what a job name is, it just
    # interpolates whatever it's given.
    mqtt_notify_service_change("10.30.0.1", type="UNDEPLOYMENT")

    mqtt_mock.publish.assert_called_once_with(
        "jobs/10.30.0.1/updates_available",
        json.dumps({"type": "UNDEPLOYMENT"}),
        qos=1,
    )
