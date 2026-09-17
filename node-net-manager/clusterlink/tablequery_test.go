package clusterlink

import (
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	messaging "github.com/oakestra/oakestra/libraries/oakestra_messaging_go"
	"github.com/oakestra/oakestra/libraries/oakestra_messaging_go/memory"
	"gotest.tools/assert"
)

// waitForPendingQuery polls until a table query has registered its waiting
// channel under key, so a test can safely deliver a result without racing
// the goroutine that issues the request.
func waitForPendingQuery(t *testing.T, cache *TableQueryRequestCache, key string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		cache.requestadd.RLock()
		pending := cache.siprequests[key] != nil
		cache.requestadd.RUnlock()
		if pending {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for a pending table query on key %q", key)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestTableQueryBySip_PublishesRequestContract(t *testing.T) {
	resetForTest(t)
	bus := installBus(t)
	cache := GetTableQueryRequestCacheInstance()
	tableQueryTimeout = 200 * time.Millisecond

	done := make(chan struct{})
	go func() {
		_, _ = cache.TableQueryByIpRequestBlocking("10.30.0.1")
		close(done)
	}()

	msg := awaitPublish(t, bus, "nodes/node1/net/tablequery/request", time.Second)
	assertJSONEqual(t, loadContract(t, "tablequery_request_by_sip.json"), msg.Payload)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the table query to finish")
	}
}

func TestTableQueryByName_PublishesRequestContract(t *testing.T) {
	resetForTest(t)
	bus := installBus(t)
	cache := GetTableQueryRequestCacheInstance()
	tableQueryTimeout = 200 * time.Millisecond

	done := make(chan struct{})
	go func() {
		_, _ = cache.TableQueryByJobNameRequestBlocking("app.ns.svc.inst")
		close(done)
	}()

	msg := awaitPublish(t, bus, "nodes/node1/net/tablequery/request", time.Second)
	assertJSONEqual(t, loadContract(t, "tablequery_request_by_name.json"), msg.Payload)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the table query to finish")
	}
}

// deliverResult starts a blocking table query for reqname in the background,
// waits for it to register, feeds the fixture through the bus (exercising the
// same subscription Init registered) and returns what the query resolved to.
func deliverResult(t *testing.T, bus *memory.Bus, cache *TableQueryRequestCache, reqname string, query func() (TableQueryResponse, error), fixture []byte) (TableQueryResponse, error) {
	t.Helper()

	resultCh := make(chan TableQueryResponse, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := query()
		resultCh <- resp
		errCh <- err
	}()

	waitForPendingQuery(t, cache, reqname, time.Second)
	bus.Deliver("nodes/node1/net/tablequery/result", fixture)

	select {
	case err := <-errCh:
		return <-resultCh, err
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the table query result")
		return TableQueryResponse{}, nil
	}
}

func TestTableQuery_ResolvedByQueryKey(t *testing.T) {
	resetForTest(t)
	bus := installBus(t)
	cache := GetTableQueryRequestCacheInstance()
	tableQueryTimeout = time.Second

	fixture := loadContract(t, "tablequery_result.json")
	var want TableQueryResponse
	assert.NilError(t, json.Unmarshal(fixture, &want))

	// query_key ("10.30.0.1") happens to equal the RR service_ip Address in
	// this fixture too, but that's incidental - any key in the response's
	// query-key list releases the same waiter.
	resp, err := deliverResult(t, bus, cache, "10.30.0.1", func() (TableQueryResponse, error) {
		return cache.TableQueryByIpRequestBlocking("10.30.0.1")
	}, fixture)

	assert.NilError(t, err)
	assert.DeepEqual(t, resp, want)
}

func TestTableQuery_ResolvedByJobName(t *testing.T) {
	resetForTest(t)
	bus := installBus(t)
	cache := GetTableQueryRequestCacheInstance()
	tableQueryTimeout = time.Second

	fixture := loadContract(t, "tablequery_result.json")
	var want TableQueryResponse
	assert.NilError(t, json.Unmarshal(fixture, &want))

	resp, err := deliverResult(t, bus, cache, "app.ns.svc.inst", func() (TableQueryResponse, error) {
		return cache.TableQueryByJobNameRequestBlocking("app.ns.svc.inst")
	}, fixture)

	assert.NilError(t, err)
	assert.DeepEqual(t, resp, want)
}

func TestTableQuery_ResolvedBySipAddress(t *testing.T) {
	resetForTest(t)
	bus := installBus(t)
	cache := GetTableQueryRequestCacheInstance()
	tableQueryTimeout = time.Second

	fixture := loadContract(t, "tablequery_result.json")
	var want TableQueryResponse
	assert.NilError(t, json.Unmarshal(fixture, &want))

	// "10.30.1.1" is the instance_ip service_ip Address, distinct from query_key/app_name.
	resp, err := deliverResult(t, bus, cache, "10.30.1.1", func() (TableQueryResponse, error) {
		return cache.TableQueryByIpRequestBlocking("10.30.1.1")
	}, fixture)

	assert.NilError(t, err)
	assert.DeepEqual(t, resp, want)
}

func TestTableQuery_ResolvedBySipAddressV6(t *testing.T) {
	resetForTest(t)
	bus := installBus(t)
	cache := GetTableQueryRequestCacheInstance()
	tableQueryTimeout = time.Second

	fixture := loadContract(t, "tablequery_result.json")
	var want TableQueryResponse
	assert.NilError(t, json.Unmarshal(fixture, &want))

	// "fdff:1001::1" is the instance_ip service_ip Address_v6.
	resp, err := deliverResult(t, bus, cache, "fdff:1001::1", func() (TableQueryResponse, error) {
		return cache.TableQueryByIpRequestBlocking("fdff:1001::1")
	}, fixture)

	assert.NilError(t, err)
	assert.DeepEqual(t, resp, want)
}

func TestTableQuery_Timeout_ReturnsMqttTimeoutAndLeaksEntry(t *testing.T) {
	resetForTest(t)
	installBus(t)
	cache := GetTableQueryRequestCacheInstance()
	tableQueryTimeout = 50 * time.Millisecond

	_, err := cache.TableQueryByIpRequestBlocking("10.40.0.1")
	var unknownErr net.UnknownNetworkError
	if !errors.As(err, &unknownErr) {
		t.Fatalf("expected net.UnknownNetworkError, got %T: %v", err, err)
	}
	assert.Equal(t, err.Error(), "unknown network Mqtt Timeout")

	// tableQueryRequestBlocking never clears cache.siprequests[reqname] on timeout,
	// so a later query for the same address is rejected until something else
	// clears it.
	_, err2 := cache.TableQueryByIpRequestBlocking("10.40.0.1")
	if err2 == nil || err2.Error() != "Table query already happening for this address" {
		t.Fatalf("expected the leaked entry to reject a second query, got %v", err2)
	}
}

func TestTableQuery_Concurrent_SecondIsRejected(t *testing.T) {
	resetForTest(t)
	installBus(t)
	cache := GetTableQueryRequestCacheInstance()
	tableQueryTimeout = 300 * time.Millisecond

	done := make(chan error, 1)
	go func() {
		_, err := cache.TableQueryByIpRequestBlocking("10.50.0.1")
		done <- err
	}()
	waitForPendingQuery(t, cache, "10.50.0.1", time.Second)

	_, err := cache.TableQueryByIpRequestBlocking("10.50.0.1")
	if err == nil || err.Error() != "Table query already happening for this address" {
		t.Fatalf("expected the concurrent query to be rejected, got %v", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the first query to finish")
	}
}

func TestTableQuery_InterestRegistered_ReturnsErrorUnlessForced(t *testing.T) {
	resetForTest(t)
	installBus(t)
	cache := GetTableQueryRequestCacheInstance()
	tableQueryTimeout = 50 * time.Millisecond

	runningHandlers.Add("10.60.0.1")

	_, err := cache.TableQueryByIpRequestBlocking("10.60.0.1")
	if err == nil || err.Error() != "interest already registered" {
		t.Fatalf("expected the interest-registered error, got %v", err)
	}

	// force=true bypasses the interest check; the query still runs (and times out,
	// since nothing answers it here).
	_, err = cache.TableQueryByIpRequestBlocking("10.60.0.1", true)
	var unknownErr net.UnknownNetworkError
	if !errors.As(err, &unknownErr) {
		t.Fatalf("expected the forced query to attempt and time out, got %v", err)
	}
}

func TestTablequeryResultHandler_MalformedJSON_LogsAndNilsEmptyKey(t *testing.T) {
	resetForTest(t)
	cache := GetTableQueryRequestCacheInstance()

	// On malformed JSON, JobName and QueryKey stay at their zero value (""); the
	// handler still runs its notify-and-clear loop for that key, leaving
	// siprequests[""] = nil even though nothing was ever pending on it.
	cache.handleTableQueryResult(messaging.Message{Payload: []byte("not json")})

	cache.requestadd.RLock()
	defer cache.requestadd.RUnlock()
	val, ok := cache.siprequests[""]
	if !ok {
		t.Fatal("expected an entry for the empty key to have been created")
	}
	if val != nil {
		t.Fatal("expected the empty key entry to be nil")
	}
}

func TestTablequeryResultHandler_CsmShapedHostPortString_FailsUnmarshal(t *testing.T) {
	resetForTest(t)
	bus := installBus(t)
	cache := GetTableQueryRequestCacheInstance()
	tableQueryTimeout = time.Second

	fixture := loadContract(t, "tablequery_result_csm_shape.json")

	// CSM echoes host_port as a JSON string (see tablequery_result_csm_shape.json)
	// while ServiceInstance.HostPort is an int, so this fixture fails to unmarshal
	// here.
	var probe TableQueryResponse
	if err := json.Unmarshal(fixture, &probe); err == nil {
		t.Fatal("expected the CSM-shaped payload to fail to unmarshal (host_port is a string)")
	}

	// Go's json.Unmarshal still fills in the fields it decoded before the type
	// mismatch, so app_name/query_key (and even service_ip) land in the struct and
	// the handler still dispatches by them.
	resp, err := deliverResult(t, bus, cache, "app.ns.svc.inst", func() (TableQueryResponse, error) {
		return cache.TableQueryByJobNameRequestBlocking("app.ns.svc.inst")
	}, fixture)

	assert.NilError(t, err)
	assert.Equal(t, resp.JobName, "app.ns.svc.inst")
	assert.Equal(t, resp.QueryKey, "10.30.0.1")
	assert.Equal(t, len(resp.InstanceList), 1)
	assert.Equal(t, resp.InstanceList[0].HostPort, 0)
}

func TestTablequeryResultHandler_NoWaiter_IsNoop(t *testing.T) {
	resetForTest(t)
	cache := GetTableQueryRequestCacheInstance()
	fixture := loadContract(t, "tablequery_result.json")

	// Nobody registered interest in any of these keys; the handler must not panic
	// or block. It just marks each key as seen (nil).
	cache.handleTableQueryResult(messaging.Message{Payload: fixture})

	cache.requestadd.RLock()
	defer cache.requestadd.RUnlock()
	for _, key := range []string{"app.ns.svc.inst", "10.30.0.1", "fdff:1000::1", "10.30.1.1", "fdff:1001::1"} {
		val, ok := cache.siprequests[key]
		if !ok || val != nil {
			t.Fatalf("expected key %q to be recorded as nil, got ok=%v val=%v", key, ok, val)
		}
	}
}
