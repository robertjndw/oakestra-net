// Package clusterlink is NetManager's connection to the cluster: it owns the
// message bus and the publish/subscribe primitives that the table query,
// subnet and interest logic build on.
package clusterlink

import (
	"NetManager/logger"
	"fmt"
	"sync"

	messaging "github.com/oakestra/oakestra/libraries/oakestra_messaging_go"
)

var (
	initOnce sync.Once
	initErr  error

	busMu sync.RWMutex
	bus   messaging.Bus

	nodeIDMu sync.RWMutex
	nodeID   string
)

func setBus(b messaging.Bus) {
	busMu.Lock()
	defer busMu.Unlock()
	bus = b
}

func getBus() messaging.Bus {
	busMu.RLock()
	defer busMu.RUnlock()
	return bus
}

func setNodeID(id string) {
	nodeIDMu.Lock()
	defer nodeIDMu.Unlock()
	nodeID = id
}

func getNodeID() string {
	nodeIDMu.RLock()
	defer nodeIDMu.RUnlock()
	return nodeID
}

// Init subscribes to the table query and subnetwork result topics under
// nodeID and connects. It only runs once; later calls are no-ops that return
// the first call's error.
func Init(b messaging.Bus, id string) error {
	initOnce.Do(func() {
		setBus(b)
		setNodeID(id)

		cache := GetTableQueryRequestCacheInstance()
		_ = b.Subscribe(fmt.Sprintf("nodes/%s/net/tablequery/result", id), cache.handleTableQueryResult)
		_ = b.Subscribe(fmt.Sprintf("nodes/%s/net/subnetwork/result", id), handleSubnetworkResult)

		initErr = b.Connect()
	})
	return initErr
}

// publish sends payload on nodes/<id>/net/<suffix>. Failures are logged, not
// returned - callers never check this error anyway.
func publish(suffix, payload string) error {
	b := getBus()
	if b == nil {
		logger.ErrorLogger().Printf("clusterlink: publish to %s dropped, bus not initialized", suffix)
		return nil
	}

	topic := fmt.Sprintf("nodes/%s/net/%s", getNodeID(), suffix)
	logger.DebugLogger().Printf("clusterlink - publish to - %s - the payload - %s", topic, payload)
	if err := b.Publish(topic, []byte(payload)); err != nil {
		logger.ErrorLogger().Printf("clusterlink: publish to %s failed: %v", topic, err)
	}
	return nil
}
