package clusterlink

import (
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	messaging "github.com/oakestra/oakestra/libraries/oakestra_messaging_go"
	"gotest.tools/assert"
)

func TestRequestSubnetwork_PublishesGetContract(t *testing.T) {
	resetForTest(t)
	bus := installBus(t)
	subnetworkTimeout = 200 * time.Millisecond

	done := make(chan struct{})
	go func() {
		_, _ = RequestSubnetworkBlocking()
		close(done)
	}()

	msg := awaitPublish(t, bus, "nodes/node1/net/subnet", time.Second)
	assertJSONEqual(t, loadContract(t, "subnet_request.json"), msg.Payload)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the subnet request to finish")
	}
}

func TestRequestSubnetwork_ResolvesWithAddresses(t *testing.T) {
	resetForTest(t)
	bus := installBus(t)
	subnetworkTimeout = time.Second

	resultCh := make(chan SubnetworkResponse, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := RequestSubnetworkBlocking()
		resultCh <- resp
		errCh <- err
	}()

	awaitPublish(t, bus, "nodes/node1/net/subnet", time.Second)

	fixture := loadContract(t, "subnetwork_result.json")
	bus.Deliver("nodes/node1/net/subnetwork/result", fixture)

	select {
	case err := <-errCh:
		assert.NilError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the subnet result")
	}
	resp := <-resultCh
	var want SubnetworkResponse
	assert.NilError(t, json.Unmarshal(fixture, &want))
	assert.DeepEqual(t, resp, want)
}

func TestRequestSubnetwork_ResolvesWithOnlyV6(t *testing.T) {
	resetForTest(t)
	bus := installBus(t)
	subnetworkTimeout = time.Second

	resultCh := make(chan SubnetworkResponse, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := RequestSubnetworkBlocking()
		resultCh <- resp
		errCh <- err
	}()

	awaitPublish(t, bus, "nodes/node1/net/subnet", time.Second)
	bus.Deliver("nodes/node1/net/subnetwork/result", []byte(`{"address":"","addressv6":"fc00:2::"}`))

	select {
	case err := <-errCh:
		assert.NilError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the subnet result")
	}
	resp := <-resultCh
	assert.DeepEqual(t, resp, SubnetworkResponse{Address: "", Address_v6: "fc00:2::"})
}

func TestRequestSubnetwork_EmptyResponse_ReturnsInvalidImmediately(t *testing.T) {
	// The select case fires on an empty result too (channel delivered), but
	// the guard is false, so it falls through to the error instead of
	// waiting out the timeout.
	resetForTest(t)
	bus := installBus(t)
	subnetworkTimeout = 5 * time.Second

	start := time.Now()
	resultCh := make(chan SubnetworkResponse, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := RequestSubnetworkBlocking()
		resultCh <- resp
		errCh <- err
	}()

	awaitPublish(t, bus, "nodes/node1/net/subnet", time.Second)
	bus.Deliver("nodes/node1/net/subnetwork/result", []byte(`{"address":"","addressv6":""}`))

	select {
	case err := <-errCh:
		elapsed := time.Since(start)
		var unknownErr net.UnknownNetworkError
		if !errors.As(err, &unknownErr) {
			t.Fatalf("expected net.UnknownNetworkError, got %v", err)
		}
		if elapsed > time.Second {
			t.Fatalf("expected an immediate return well under the 5s timeout, took %s", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the immediate empty-response error")
	}
	<-resultCh
}

func TestRequestSubnetwork_Timeout(t *testing.T) {
	resetForTest(t)
	bus := installBus(t)
	subnetworkTimeout = 50 * time.Millisecond

	errCh := make(chan error, 1)
	go func() {
		_, err := RequestSubnetworkBlocking()
		errCh <- err
	}()

	awaitPublish(t, bus, "nodes/node1/net/subnet", time.Second)

	select {
	case err := <-errCh:
		var unknownErr net.UnknownNetworkError
		if !errors.As(err, &unknownErr) {
			t.Fatalf("expected net.UnknownNetworkError, got %T: %v", err, err)
		}
		assert.Equal(t, err.Error(), "unknown network Invalid Subnetwork received")
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the subnet request to time out")
	}
}

func TestSubnetHandler_MalformedJSON_PushesZeroValue(t *testing.T) {
	resetForTest(t)
	subnetworkResponseChannel = make(chan SubnetworkResponse, 1)

	handleSubnetworkResult(messaging.Message{Payload: []byte("not json")})

	select {
	case resp := <-subnetworkResponseChannel:
		assert.DeepEqual(t, resp, SubnetworkResponse{})
	case <-time.After(time.Second):
		t.Fatal("expected the handler to push a zero-value response on malformed JSON")
	}
}

func TestSubnetHandler_UnsolicitedResult_DoesNotBlockOrPanic(t *testing.T) {
	// No RequestSubnetworkBlocking call means subnetworkResponseChannel is nil;
	// a broker (or a slow test) delivering a subnetwork/result anyway must not
	// hang the dispatcher.
	resetForTest(t)
	bus := installBus(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		bus.Deliver("nodes/node1/net/subnetwork/result", loadContract(t, "subnetwork_result.json"))
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("unsolicited subnetwork/result blocked delivery")
	}
}
