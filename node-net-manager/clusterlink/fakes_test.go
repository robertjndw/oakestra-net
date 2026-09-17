package clusterlink

import "sync"

// fakeEnv implements jobEnvironmentManagerActions for interest/self-destruct tests.
type fakeEnv struct {
	mu sync.Mutex

	deployed map[string]bool

	refreshed []string
	removed   []string
}

func newFakeEnv() *fakeEnv {
	return &fakeEnv{deployed: make(map[string]bool)}
}

func (e *fakeEnv) RefreshServiceTable(sname string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refreshed = append(e.refreshed, sname)
}

func (e *fakeEnv) RemoveServiceEntries(sname string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.removed = append(e.removed, sname)
}

func (e *fakeEnv) IsServiceDeployed(fullSnameAndInstance string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.deployed[fullSnameAndInstance]
}

func (e *fakeEnv) setDeployed(name string, deployed bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.deployed[name] = deployed
}

func (e *fakeEnv) Refreshed() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string{}, e.refreshed...)
}

func (e *fakeEnv) Removed() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string{}, e.removed...)
}
