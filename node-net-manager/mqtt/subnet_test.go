package mqtt

import (
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"gotest.tools/assert"
)

// subnetworkAssignmentMqttHandler sends on subnetworkResponseChannel
// unconditionally. If no RequestSubnetworkMqttBlocking call has set that
// channel (nil), the send blocks forever. That path is described in
// testdata/mqtt_contract/README.md and deliberately not exercised here, it
// would hang the test.

func TestRequestSubnetwork_PublishesGetContract(t *testing.T) {
	resetForTest(t)
	installFakeClient(nil)
	InitNetMqttClient("node1", "host", "1883", "", "")
	fc := netMqttClient.mainMqttClient.(*fakeClient)
	subnetworkTimeout = 200 * time.Millisecond

	done := make(chan struct{})
	go func() {
		_, _ = RequestSubnetworkMqttBlocking()
		close(done)
	}()

	call := awaitPublish(t, fc, "nodes/node1/net/subnet", time.Second)
	assertJSONEqual(t, loadContract(t, "subnet_request.json"), []byte(call.payload))
	assert.Equal(t, call.qos, byte(1))

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the subnet request to finish")
	}
}

func TestRequestSubnetwork_ResolvesWithAddresses(t *testing.T) {
	resetForTest(t)
	installFakeClient(nil)
	InitNetMqttClient("node1", "host", "1883", "", "")
	fc := netMqttClient.mainMqttClient.(*fakeClient)
	subnetworkTimeout = time.Second

	resultCh := make(chan mqttSubnetworkResponse, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := RequestSubnetworkMqttBlocking()
		resultCh <- resp
		errCh <- err
	}()

	// Synchronizing on the publish (mutex-guarded) rather than reading the
	// unsynchronized subnetworkResponseChannel global avoids racing with the
	// goroutine above that assigns it.
	awaitPublish(t, fc, "nodes/node1/net/subnet", time.Second)

	fixture := loadContract(t, "subnetwork_result.json")
	subnetworkAssignmentMqttHandler(nil, &fakeMessage{payload: fixture})

	select {
	case err := <-errCh:
		assert.NilError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the subnet result")
	}
	resp := <-resultCh
	var want mqttSubnetworkResponse
	assert.NilError(t, json.Unmarshal(fixture, &want))
	assert.DeepEqual(t, resp, want)
}

func TestRequestSubnetwork_ResolvesWithOnlyV6(t *testing.T) {
	resetForTest(t)
	installFakeClient(nil)
	InitNetMqttClient("node1", "host", "1883", "", "")
	fc := netMqttClient.mainMqttClient.(*fakeClient)
	subnetworkTimeout = time.Second

	resultCh := make(chan mqttSubnetworkResponse, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := RequestSubnetworkMqttBlocking()
		resultCh <- resp
		errCh <- err
	}()

	awaitPublish(t, fc, "nodes/node1/net/subnet", time.Second)
	subnetworkAssignmentMqttHandler(nil, &fakeMessage{payload: []byte(`{"address":"","addressv6":"fc00:2::"}`)})

	select {
	case err := <-errCh:
		assert.NilError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the subnet result")
	}
	resp := <-resultCh
	assert.DeepEqual(t, resp, mqttSubnetworkResponse{Address: "", Address_v6: "fc00:2::"})
}

func TestRequestSubnetwork_EmptyResponse_ReturnsInvalidImmediately(t *testing.T) {
	// The select's case branch also fires on an empty result (the channel
	// delivered), but the guard inside is false, so execution falls out of the
	// select and returns the error instead of waiting out the rest of the
	// timeout.
	resetForTest(t)
	installFakeClient(nil)
	InitNetMqttClient("node1", "host", "1883", "", "")
	fc := netMqttClient.mainMqttClient.(*fakeClient)
	subnetworkTimeout = 5 * time.Second

	start := time.Now()
	resultCh := make(chan mqttSubnetworkResponse, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := RequestSubnetworkMqttBlocking()
		resultCh <- resp
		errCh <- err
	}()

	awaitPublish(t, fc, "nodes/node1/net/subnet", time.Second)
	subnetworkAssignmentMqttHandler(nil, &fakeMessage{payload: []byte(`{"address":"","addressv6":""}`)})

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
	installFakeClient(nil)
	InitNetMqttClient("node1", "host", "1883", "", "")
	fc := netMqttClient.mainMqttClient.(*fakeClient)
	subnetworkTimeout = 50 * time.Millisecond

	errCh := make(chan error, 1)
	go func() {
		_, err := RequestSubnetworkMqttBlocking()
		errCh <- err
	}()

	// Synchronizing on the settled publish, rather than just calling
	// RequestSubnetworkMqttBlocking synchronously, avoids racing its
	// fire-and-forget publish goroutine against the next test's resetForTest.
	awaitPublish(t, fc, "nodes/node1/net/subnet", time.Second)

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
	subnetworkResponseChannel = make(chan mqttSubnetworkResponse, 1)

	subnetworkAssignmentMqttHandler(nil, &fakeMessage{payload: []byte("not json")})

	select {
	case resp := <-subnetworkResponseChannel:
		assert.DeepEqual(t, resp, mqttSubnetworkResponse{})
	case <-time.After(time.Second):
		t.Fatal("expected the handler to push a zero-value response on malformed JSON")
	}
}
