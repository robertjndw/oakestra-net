package proxy

import (
	"NetManager/logger"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type ConversionEntry struct {
	srcip         netip.Addr
	dstip         netip.Addr
	dstServiceIp  netip.Addr
	srcInstanceIp netip.Addr
	srcport       int
	dstport       int
	// dstNode/dstNodePort cache which node dstip actually lives on, so the
	// packet path doesn't need a second table lookup by namespace IP -
	// outgoingProxy instead revalidates this cached tuple (dstip, dstNode,
	// dstNodePort) against the translation table on every cache hit.
	dstNode     netip.Addr
	dstNodePort int
}

type ConversionList struct {
	nextEntry int
	// lastUsed holds a coarse Unix-seconds timestamp (see coarseClock below).
	// It is atomic so retrieve methods can update it while holding only the
	// cache's read lock (RLock), instead of requiring a write lock.
	lastUsed       atomic.Int64
	conversionList []ConversionEntry
}

type ProxyCache struct {
	//One position for each port number. Higher mem usage but lower cpu usage
	cache                 []ConversionList
	conversionListMaxSize int
	rwlock                sync.RWMutex
}

// coarseClock is a 1Hz-updated Unix-seconds clock shared by every
// ProxyCache entry. Recording "last used" on every cache hit doesn't need
// second-level precision, so entries read this instead of each calling
// time.Now() (a vDSO call) on every packet.
var coarseClock atomic.Int64

func init() {
	coarseClock.Store(time.Now().Unix())
	go func() {
		ticker := time.NewTicker(time.Second)
		for range ticker.C {
			coarseClock.Store(time.Now().Unix())
		}
	}()
}

func NewProxyCache() *ProxyCache {
	cache := &ProxyCache{
		cache:                 make([]ConversionList, 65536),
		conversionListMaxSize: 10,
	}
	cache.runEvictionJob(30*time.Second, 1*time.Minute)
	return cache
}

// runEvictionJob starts a goroutine that periodically evicts old cache entries.
func (cache *ProxyCache) runEvictionJob(interval time.Duration, timeout time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			cache.evictOldEntries(timeout)
		}
	}()
}

// evictOldEntries removes entries that have not been used for the duration of the timeout.
func (cache *ProxyCache) evictOldEntries(timeout time.Duration) {
	cache.rwlock.Lock()
	defer cache.rwlock.Unlock()

	now := coarseClock.Load()
	timeoutSeconds := int64(timeout.Seconds())
	evictedCount := 0
	for i := range cache.cache {
		lastUsed := cache.cache[i].lastUsed.Load()
		if lastUsed != 0 && (now-lastUsed) > timeoutSeconds {
			cache.cache[i].lastUsed.Store(0)
			cache.cache[i].nextEntry = 0
			cache.cache[i].conversionList = nil
			evictedCount++
		}
	}
	if evictedCount > 0 {
		logger.InfoLogger().Printf("Evicted %d entries from cache", evictedCount)
	}
}

// RetrieveByServiceIP Retrieve proxy proxycache entry based on source ip and source port and destination ServiceIP
func (cache *ProxyCache) RetrieveByServiceIP(srcip netip.Addr, instanceIP netip.Addr, srcport int, dstServiceIp netip.Addr, dstport int) (ConversionEntry, bool) {
	cache.rwlock.RLock()
	defer cache.rwlock.RUnlock()

	elem := &cache.cache[srcport]
	if elem.conversionList != nil {
		for _, cacheEntry := range elem.conversionList {
			if cacheEntry.dstport == dstport &&
				cacheEntry.dstServiceIp == dstServiceIp &&
				cacheEntry.srcip == srcip &&
				cacheEntry.srcInstanceIp == instanceIP {
				elem.lastUsed.Store(coarseClock.Load())
				return cacheEntry, true
			}
		}
	}
	return ConversionEntry{}, false
}

// RetrieveByInstanceIp Retrieve proxy proxycache entry based on source ip and source port and destination ip
func (cache *ProxyCache) RetrieveByInstanceIp(srcip netip.Addr, srcport int, dstport int) (ConversionEntry, bool) {
	cache.rwlock.RLock()
	defer cache.rwlock.RUnlock()

	elem := &cache.cache[srcport]
	if elem.conversionList != nil {
		for _, entry := range elem.conversionList {
			if entry.dstport == dstport && entry.srcip == srcip {
				elem.lastUsed.Store(coarseClock.Load())
				return entry, true
			}
		}
	}
	return ConversionEntry{}, false
}

// Add new conversion entry, if srcpip && srcport already added the entry is updated
func (cache *ProxyCache) Add(entry ConversionEntry) {
	cache.rwlock.Lock()
	defer cache.rwlock.Unlock()

	elem := &cache.cache[entry.srcport]
	if elem.conversionList == nil || len(elem.conversionList) == 0 {
		elem.nextEntry = 0
		elem.conversionList = make([]ConversionEntry, cache.conversionListMaxSize)
	}

	cache.addToConversionList(entry)
}

func (cache *ProxyCache) addToConversionList(entry ConversionEntry) {
	elem := &cache.cache[entry.srcport]
	elem.lastUsed.Store(coarseClock.Load())
	alreadyExist := false
	alreadyExistPosition := 0
	//check if used port is already in proxycache
	for i, elementry := range elem.conversionList {
		if elementry.dstport == entry.dstport {
			alreadyExistPosition = i
			alreadyExist = true
			break
		}
	}
	if alreadyExist {
		//if sourceport already in proxycache overwrite the proxycache entry
		elem.conversionList[alreadyExistPosition] = entry

	} else {
		//otherwise add a new proxycache entry in the next slot available
		elem.conversionList[elem.nextEntry] = entry
		elem.nextEntry = (elem.nextEntry + 1) % cache.conversionListMaxSize
	}
}
