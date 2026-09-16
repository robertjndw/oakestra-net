package mqtt

import (
	"NetManager/events"
	"fmt"
	"strings"
	"testing"
	"time"

	"gotest.tools/assert"
)

// uniqueJob derives a job name from the test name so each test that doesn't
// need to match a fixed fixture value gets its own key in the events package's
// process-wide (never-reset-by-tests) singleton, and doesn't collide with
// other tests or with itself across `go test -count=N` reruns.
func uniqueJob(t *testing.T) string {
	return "job-" + strings.ReplaceAll(t.Name(), "/", "_")
}

// waitForInterestCleared polls until the self-destruct goroutine for job has
// fully torn down. Every test that registers an interest must call this
// before returning: startSelfDestructTimeout reads the package-level
// selfDestructTimeout var on every loop iteration at an unpredictable time
// (goroutine scheduling gives no guarantee it has even started yet), so any
// interest left running when the next test's resetForTest rewrites that var
// is a data race, not just a leaked goroutine.
func waitForInterestCleared(t *testing.T, job string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for MqttIsInterestRegistered(job) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for the interest in %q to be cleared", job)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestMqttRegisterInterest_SubscribesJobTopicQoS1AndTracks(t *testing.T) {
	resetForTest(t)
	installFakeClient(nil)
	InitNetMqttClient("node1", "host", "1883", "", "")
	fc := netMqttClient.mainMqttClient.(*fakeClient)
	selfDestructTimeout = 40 * time.Millisecond
	job := uniqueJob(t)
	env := newFakeEnv()

	MqttRegisterInterest(job, env)

	if !MqttIsInterestRegistered(job) {
		t.Fatal("expected the interest to be tracked")
	}
	calls := fc.Subscribes()
	assert.Equal(t, len(calls), 1)
	assert.Equal(t, calls[0].topic, "jobs/"+job+"/updates_available")
	assert.Equal(t, calls[0].qos, byte(1))

	waitForInterestCleared(t, job, time.Second)
}

func TestMqttRegisterInterest_DuplicateIsNoop(t *testing.T) {
	resetForTest(t)
	installFakeClient(nil)
	InitNetMqttClient("node1", "host", "1883", "", "")
	fc := netMqttClient.mainMqttClient.(*fakeClient)
	selfDestructTimeout = 40 * time.Millisecond
	job := uniqueJob(t)

	MqttRegisterInterest(job, newFakeEnv())
	MqttRegisterInterest(job, newFakeEnv()) // second call for the same job: must be a no-op

	calls := fc.Subscribes()
	assert.Equal(t, len(calls), 1)

	waitForInterestCleared(t, job, time.Second)
}

func TestMqttRegisterInterest_IpStringJobNameUsedVerbatim(t *testing.T) {
	resetForTest(t)
	installFakeClient(nil)
	InitNetMqttClient("node1", "host", "1883", "", "")
	fc := netMqttClient.mainMqttClient.(*fakeClient)
	selfDestructTimeout = 40 * time.Millisecond
	// A service IP used as the "job" (see updates_available.json's <job> note);
	// stamp on a nanosecond-derived octet so repeated `-count=N` runs don't
	// collide on the shared events singleton.
	job := fmt.Sprintf("10.30.0.%d", time.Now().UnixNano()%250+1)

	MqttRegisterInterest(job, newFakeEnv())

	calls := fc.Subscribes()
	assert.Equal(t, len(calls), 1)
	assert.Equal(t, calls[0].topic, "jobs/"+job+"/updates_available")

	waitForInterestCleared(t, job, time.Second)
}

func TestJobUpdatesHandler_TriggersRefreshServiceTable(t *testing.T) {
	resetForTest(t)
	installFakeClient(nil)
	InitNetMqttClient("node1", "host", "1883", "", "")
	fc := netMqttClient.mainMqttClient.(*fakeClient)
	selfDestructTimeout = 40 * time.Millisecond
	job := uniqueJob(t)
	env := newFakeEnv()

	MqttRegisterInterest(job, env)

	calls := fc.Subscribes()
	assert.Equal(t, len(calls), 1)
	handler := calls[0].callback

	handler(fc, &fakeMessage{topic: "jobs/" + job + "/updates_available"})

	deadline := time.Now().Add(time.Second)
	for {
		refreshed := env.Refreshed()
		if len(refreshed) == 1 && refreshed[0] == job {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for RefreshServiceTable(%q), got %v", job, refreshed)
		}
		time.Sleep(2 * time.Millisecond)
	}

	waitForInterestCleared(t, job, time.Second)
}

func TestSelfDestruct_NotDeployed_PublishesInterestRemoveAndUnsubscribes(t *testing.T) {
	resetForTest(t)
	installFakeClient(nil)
	InitNetMqttClient("node1", "host", "1883", "", "")
	fc := netMqttClient.mainMqttClient.(*fakeClient)
	selfDestructTimeout = 30 * time.Millisecond
	// Must match interest_remove.json's fixed "appname".
	job := "app.ns.svc.inst"
	env := newFakeEnv()
	env.setDeployed(job, false)

	MqttRegisterInterest(job, env)

	call := awaitPublish(t, fc, "nodes/node1/net/interest/remove", time.Second)
	assertJSONEqual(t, loadContract(t, "interest_remove.json"), []byte(call.payload))

	deadline := time.Now().Add(time.Second)
	for len(fc.Unsubscribes()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the topic to be unsubscribed")
		}
		time.Sleep(2 * time.Millisecond)
	}
	unsubs := fc.Unsubscribes()
	assert.Equal(t, len(unsubs), 1)
	assert.DeepEqual(t, unsubs[0], []string{"jobs/" + job + "/updates_available"})

	waitForInterestCleared(t, job, time.Second)

	removed := env.Removed()
	if len(removed) != 1 || removed[0] != job {
		t.Fatalf("expected RemoveServiceEntries(%q) exactly once, got %v", job, removed)
	}
}

func TestSelfDestruct_Deployed_KeepsInterest(t *testing.T) {
	resetForTest(t)
	installFakeClient(nil)
	InitNetMqttClient("node1", "host", "1883", "", "")
	selfDestructTimeout = 20 * time.Millisecond
	job := uniqueJob(t)
	env := newFakeEnv()
	env.setDeployed(job, true)

	MqttRegisterInterest(job, env)

	// Survive several self-destruct periods while the service is "deployed".
	time.Sleep(3*selfDestructTimeout + 60*time.Millisecond)
	if !MqttIsInterestRegistered(job) {
		t.Fatal("expected the interest to survive timeouts while the service is deployed")
	}

	env.setDeployed(job, false)

	waitForInterestCleared(t, job, time.Second)
}

func TestSelfDestruct_EventResetsTimer(t *testing.T) {
	resetForTest(t)
	installFakeClient(nil)
	InitNetMqttClient("node1", "host", "1883", "", "")
	selfDestructTimeout = 100 * time.Millisecond
	job := uniqueJob(t)
	env := newFakeEnv()
	env.setDeployed(job, false)

	MqttRegisterInterest(job, env)

	// Pre-register the event channel from the test goroutine itself:
	// events.Register is idempotent (returns the existing channel if one is
	// already there), so this guarantees the channel exists before Emit runs
	// regardless of how quickly the background self-destruct goroutine gets
	// scheduled - otherwise Emit silently drops the event against a channel
	// that doesn't exist yet.
	events.GetInstance().Register(events.TableQuery, job)

	// Emit halfway through the first period (deadline ~100ms from
	// registration); this must push the deadline out to ~150ms rather than
	// letting the original one expire.
	time.Sleep(selfDestructTimeout / 2)
	events.GetInstance().Emit(events.Event{EventType: events.TableQuery, EventTarget: job})

	// 120ms since registration: past the *original* 100ms deadline but with
	// margin before the reset one at ~150ms. Still registered here proves the
	// reset took effect.
	time.Sleep(70 * time.Millisecond)
	if !MqttIsInterestRegistered(job) {
		t.Fatal("expected the TableQuery event to reset the self-destruct timer")
	}

	waitForInterestCleared(t, job, time.Second)
}
