package clusterlink

import (
	"errors"
	"testing"
	"time"

	"github.com/oakestra/oakestra/libraries/oakestra_messaging_go/memory"
	"gotest.tools/assert"
)

func TestInit_SubscribesResultTopicsAndConnects(t *testing.T) {
	resetForTest(t)
	bus := installBus(t)

	if !hasSubscription(bus, "nodes/node1/net/tablequery/result") {
		t.Fatal("missing tablequery/result subscription")
	}
	if !hasSubscription(bus, "nodes/node1/net/subnetwork/result") {
		t.Fatal("missing subnetwork/result subscription")
	}
	if !bus.Connected() {
		t.Fatal("expected Init to connect the bus")
	}
}

func TestInit_IsOnceOnly(t *testing.T) {
	resetForTest(t)
	bus1 := memory.New()
	bus2 := memory.New()

	err1 := Init(bus1, "node1")
	err2 := Init(bus2, "node2")

	assert.NilError(t, err1)
	assert.NilError(t, err2)

	// The second call's args are silently ignored: sync.Once already ran.
	if getBus() != bus1 {
		t.Fatal("expected the first bus to remain active")
	}
	if getNodeID() != "node1" {
		t.Fatal("expected the first node ID to remain active")
	}
}

func TestInit_ReturnsConnectError(t *testing.T) {
	resetForTest(t)
	bus := memory.New()
	connectErr := errors.New("boom")
	bus.SetConnectError(connectErr)

	err := Init(bus, "node1")
	if err == nil {
		t.Fatal("expected Init to return the bus's connect error")
	}
}

func TestPublish_PrefixesNodeNamespace(t *testing.T) {
	resetForTest(t)
	bus := installBus(t)

	err := publish("tablequery/request", `{"sname":"","sip":"10.30.0.1"}`)
	assert.NilError(t, err)

	msg := awaitPublish(t, bus, "nodes/node1/net/tablequery/request", time.Second)
	assert.Equal(t, string(msg.Payload), `{"sname":"","sip":"10.30.0.1"}`)
}

func TestPublish_ReturnsNilEvenOnBusError(t *testing.T) {
	// publish only logs a publish error, never surfaces it - nothing here
	// reacts to it anyway.
	resetForTest(t)
	bus := installBus(t)
	bus.SetPublishError(errors.New("broker rejected publish"))

	err := publish("subnet", `{"METHOD":"GET"}`)
	assert.NilError(t, err)
}

func TestPublish_BeforeInit_LogsAndReturnsNil(t *testing.T) {
	resetForTest(t)

	err := publish("subnet", `{"METHOD":"GET"}`)
	assert.NilError(t, err)
}

func TestDispatch_ExtraSuffixOrForeignPrefix_NotDelivered(t *testing.T) {
	resetForTest(t)
	bus := installBus(t)
	tableQueryTimeout = time.Second

	fixture := loadContract(t, "tablequery_result.json")

	// The Dispatcher matches segments exactly: an extra trailing segment or a
	// foreign leading prefix must not reach the tablequery/result handler.
	n := bus.Deliver("nodes/node1/net/tablequery/result/extra", fixture)
	assert.Equal(t, n, 0)
	n = bus.Deliver("prefix/nodes/node1/net/tablequery/result", fixture)
	assert.Equal(t, n, 0)
}
