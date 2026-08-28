// Package events tracks per-target "last used" activity.
//
// It used to be a channel-based pub/sub: GetTableEntryByServiceIP fired an
// Emit on every packet that hit a job's ServiceIP, and the interest
// self-destruct timer in mqtt/MqttJobUpdates.go consumed it to reset its
// idle countdown. That meant every packet took a process-global RWMutex and
// hashed a string map key just to keep a timer alive.
//
// Activity replaces that with a single atomic timestamp per target, handed
// out once (when a table entry is created, not per packet) and touched with
// one atomic store. The self-destruct timer polls it instead of blocking on
// a channel - it only checked every 10s anyway.
package events

import (
	"sync"
	"sync/atomic"
	"time"
)

// Activity is a per-target last-used timestamp. The zero value reports as
// "never touched".
type Activity struct {
	stamp atomic.Int64 // Unix seconds, 0 = never touched
}

// Touch records that target was just used. Safe to call from any goroutine;
// does not allocate or block.
func (a *Activity) Touch() {
	a.stamp.Store(time.Now().Unix())
}

// IdleFor returns how long it has been since the last Touch. An Activity
// that has never been touched reports as idle forever.
func (a *Activity) IdleFor() time.Duration {
	last := a.stamp.Load()
	if last == 0 {
		return time.Duration(1<<63 - 1)
	}
	return time.Since(time.Unix(last, 0))
}

var (
	registryMu sync.RWMutex
	registry   = make(map[string]*Activity)
)

// GetOrCreate returns the shared Activity for target, creating it if this is
// the first time target has been seen. Called when a table entry is
// added/refreshed - not on the packet path.
func GetOrCreate(target string) *Activity {
	registryMu.RLock()
	a, ok := registry[target]
	registryMu.RUnlock()
	if ok {
		return a
	}

	registryMu.Lock()
	defer registryMu.Unlock()
	if a, ok = registry[target]; ok {
		return a
	}
	a = &Activity{}
	registry[target] = a
	return a
}

// Delete removes the Activity for target once its interest has been torn
// down, so the registry doesn't grow with every job ever seen.
func Delete(target string) {
	registryMu.Lock()
	delete(registry, target)
	registryMu.Unlock()
}
