package clusterlink

import (
	"testing"
	"time"
)

func TestNotifyDeploymentStatus_MatchesContract(t *testing.T) {
	resetForTest(t)
	bus := installBus(t)

	err := NotifyDeploymentStatus("app.ns.svc.inst", "DEPLOYED", 0, "10.19.1.2", "fc00::2", "192.168.1.10", "50103")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := awaitPublish(t, bus, "nodes/node1/net/service/deployed", time.Second)
	assertJSONEqual(t, loadContract(t, "service_deployed.json"), msg.Payload)
}

func TestNotifyAddressChange_MatchesContract(t *testing.T) {
	resetForTest(t)
	bus := installBus(t)

	// NotifyAddressChange only sets appname/instance/hostip/hostport: status,
	// nsip and nsipv6 are left at their zero values ("").
	err := NotifyAddressChange("app.ns.svc.inst", 0, "192.168.1.11", "50103")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := awaitPublish(t, bus, "nodes/node1/net/service/address-changed", time.Second)
	assertJSONEqual(t, loadContract(t, "service_address_changed.json"), msg.Payload)
}
