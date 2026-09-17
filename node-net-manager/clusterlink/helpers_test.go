package clusterlink

import (
	"NetManager/utils"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	messaging "github.com/oakestra/oakestra/libraries/oakestra_messaging_go"
	"github.com/oakestra/oakestra/libraries/oakestra_messaging_go/memory"
	"gotest.tools/assert"
)

// resetForTest restores every package-level singleton and seam this package
// exposes, so tests don't leak state into each other.
func resetForTest(t *testing.T) {
	t.Helper()

	prevTableQueryTimeout := tableQueryTimeout
	prevSubnetworkTimeout := subnetworkTimeout
	prevSelfDestructTimeout := selfDestructTimeout

	initOnce = sync.Once{}
	initErr = nil
	bus = nil
	nodeID = ""
	once = sync.Once{}
	tableQueryRequestCacheInstance = TableQueryRequestCache{}
	runningHandlers = utils.NewStringSlice()
	subnetworkResponseChannel = nil

	t.Cleanup(func() {
		tableQueryTimeout = prevTableQueryTimeout
		subnetworkTimeout = prevSubnetworkTimeout
		selfDestructTimeout = prevSelfDestructTimeout
	})
}

// installBus wires an in-memory bus through Init under the fixed node ID
// "node1" every test in this package assumes, and returns it for inspecting
// publishes or subscriptions.
func installBus(t *testing.T) *memory.Bus {
	t.Helper()
	b := memory.New()
	if err := Init(b, "node1"); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return b
}

// awaitPublish polls bus's recorded publishes until one matches topic. Tests
// that trigger a publish from a background goroutine need this instead of
// reading bus.Published() once, since nothing else synchronizes with that
// goroutine's progress.
func awaitPublish(t *testing.T, bus *memory.Bus, topic string, timeout time.Duration) messaging.Message {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		for _, m := range bus.Published() {
			if m.Topic == topic {
				return m
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for a publish to topic %q", topic)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// loadContract reads a fixture from the shared testdata/mqtt_contract directory.
func loadContract(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "mqtt_contract", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading contract fixture %s: %v", path, err)
	}
	return data
}

// assertJSONEqual compares two JSON payloads semantically (parsed, not byte-for-byte).
func assertJSONEqual(t *testing.T, want, got []byte) {
	t.Helper()
	var wantAny, gotAny any
	if err := json.Unmarshal(want, &wantAny); err != nil {
		t.Fatalf("unmarshaling expected JSON: %v", err)
	}
	if err := json.Unmarshal(got, &gotAny); err != nil {
		t.Fatalf("unmarshaling actual JSON: %v", err)
	}
	assert.DeepEqual(t, wantAny, gotAny)
}
