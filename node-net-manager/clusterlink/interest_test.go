package clusterlink

import (
	"NetManager/events"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/oakestra/oakestra/libraries/oakestra_messaging_go/memory"
)

// uniqueJob derives a job name from the test name, for tests that don't need
// a fixed fixture value. Keeps them from colliding on the events package's
// process-wide singleton (never reset by tests), including across
// `go test -count=N` reruns of the same test.
func uniqueJob(t *testing.T) string {
	return "job-" + strings.ReplaceAll(t.Name(), "/", "_")
}

// waitForInterestCleared polls until the self-destruct goroutine for job
// tears down. Every test that registers an interest must call this:
// startSelfDestructTimeout reads the package-level selfDestructTimeout var at
// an unpredictable time, so a goroutine still running when the next test's
// resetForTest rewrites that var is a data race, not just a leaked goroutine.
func waitForInterestCleared(t *testing.T, job string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for IsInterestRegistered(job) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for the interest in %q to be cleared", job)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func hasSubscription(bus *memory.Bus, pattern string) bool {
	for _, p := range bus.Subscriptions() {
		if p == pattern {
			return true
		}
	}
	return false
}

func TestRegisterInterest_SubscribesJobTopicAndTracks(t *testing.T) {
	resetForTest(t)
	bus := installBus(t)
	selfDestructTimeout = 40 * time.Millisecond
	job := uniqueJob(t)
	env := newFakeEnv()

	RegisterInterest(job, env)

	if !IsInterestRegistered(job) {
		t.Fatal("expected the interest to be tracked")
	}
	if !hasSubscription(bus, "jobs/"+job+"/updates_available") {
		t.Fatalf("expected a subscription to jobs/%s/updates_available", job)
	}

	waitForInterestCleared(t, job, time.Second)
}

func TestRegisterInterest_DuplicateIsNoop(t *testing.T) {
	resetForTest(t)
	installBus(t)
	selfDestructTimeout = 40 * time.Millisecond
	job := uniqueJob(t)

	RegisterInterest(job, newFakeEnv())
	RegisterInterest(job, newFakeEnv()) // second call for the same job: must be a no-op

	if !IsInterestRegistered(job) {
		t.Fatal("expected the interest to be tracked")
	}

	waitForInterestCleared(t, job, time.Second)
}

func TestRegisterInterest_IpStringJobNameUsedVerbatim(t *testing.T) {
	resetForTest(t)
	bus := installBus(t)
	selfDestructTimeout = 40 * time.Millisecond
	// A service IP used as the "job" (see updates_available.json's <job> note);
	// stamp on a nanosecond-derived octet so repeated `-count=N` runs don't
	// collide on the shared events singleton.
	job := fmt.Sprintf("10.30.0.%d", time.Now().UnixNano()%250+1)

	RegisterInterest(job, newFakeEnv())

	if !hasSubscription(bus, "jobs/"+job+"/updates_available") {
		t.Fatalf("expected a subscription to jobs/%s/updates_available", job)
	}

	waitForInterestCleared(t, job, time.Second)
}

func TestJobUpdatesHandler_TriggersRefreshServiceTable(t *testing.T) {
	resetForTest(t)
	bus := installBus(t)
	selfDestructTimeout = 40 * time.Millisecond
	job := uniqueJob(t)
	env := newFakeEnv()

	RegisterInterest(job, env)

	topic := "jobs/" + job + "/updates_available"
	if !hasSubscription(bus, topic) {
		t.Fatalf("expected a subscription to %s", topic)
	}

	bus.Deliver(topic, nil)

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
	bus := installBus(t)
	selfDestructTimeout = 30 * time.Millisecond
	// Must match interest_remove.json's fixed "appname".
	job := "app.ns.svc.inst"
	env := newFakeEnv()
	env.setDeployed(job, false)

	RegisterInterest(job, env)

	call := awaitPublish(t, bus, "nodes/node1/net/interest/remove", time.Second)
	assertJSONEqual(t, loadContract(t, "interest_remove.json"), call.Payload)

	waitForInterestCleared(t, job, time.Second)

	topic := "jobs/" + job + "/updates_available"
	if hasSubscription(bus, topic) {
		t.Fatalf("expected %s to be unsubscribed after self-destruct", topic)
	}

	removed := env.Removed()
	if len(removed) != 1 || removed[0] != job {
		t.Fatalf("expected RemoveServiceEntries(%q) exactly once, got %v", job, removed)
	}
}

func TestSelfDestruct_Deployed_KeepsInterest(t *testing.T) {
	resetForTest(t)
	installBus(t)
	selfDestructTimeout = 20 * time.Millisecond
	job := uniqueJob(t)
	env := newFakeEnv()
	env.setDeployed(job, true)

	RegisterInterest(job, env)

	// Survive several self-destruct periods while the service is "deployed".
	time.Sleep(3*selfDestructTimeout + 60*time.Millisecond)
	if !IsInterestRegistered(job) {
		t.Fatal("expected the interest to survive timeouts while the service is deployed")
	}

	env.setDeployed(job, false)

	waitForInterestCleared(t, job, time.Second)
}

func TestSelfDestruct_EventResetsTimer(t *testing.T) {
	resetForTest(t)
	installBus(t)
	selfDestructTimeout = 100 * time.Millisecond
	job := uniqueJob(t)
	env := newFakeEnv()
	env.setDeployed(job, false)

	RegisterInterest(job, env)

	// Pre-register the event channel from the test goroutine: events.Register
	// is idempotent, so the channel exists before Emit runs no matter how
	// fast the self-destruct goroutine gets scheduled. Otherwise Emit
	// silently drops the event against a channel that doesn't exist yet.
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
	if !IsInterestRegistered(job) {
		t.Fatal("expected the TableQuery event to reset the self-destruct timer")
	}

	waitForInterestCleared(t, job, time.Second)
}
