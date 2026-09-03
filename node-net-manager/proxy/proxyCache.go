package proxy

import (
	"NetManager/TableEntryCache"
	"NetManager/clock"
	"NetManager/logger"
	"NetManager/resolver"
	"net/netip"
	"sync"
	"time"
)

// ConversionEntry is one translated flow, identified by the full 5-tuple in
// both directions: destination port alone collides as soon as one local
// socket talks to two different Service VIPs on the same port (the common UDP
// shape), reverse-translating a reply for one VIP as though it belonged to
// the other.
type ConversionEntry struct {
	srcip         netip.Addr
	dstip         netip.Addr
	dstServiceIp  netip.Addr
	srcInstanceIp netip.Addr
	// dstInstanceIp is the address replies actually arrive from (not dstip:
	// the remote node's outgoingProxy sources them from its own instance IP).
	// Zero means "matches any remote" - used when the entry has no
	// InstanceNumber ServiceIP to predict a reply source from.
	dstInstanceIp netip.Addr
	srcport       int
	dstport       int
	protocol      uint8
	// dstNode/dstNodePort cache which node dstip actually lives on, so the
	// packet path doesn't need a second table lookup by namespace IP.
	dstNode     netip.Addr
	dstNodePort int
	// routeGen is the translation table generation this route was chosen
	// from. While it still matches, the route is known to be current and the
	// per-replica revalidation scan can be skipped entirely.
	routeGen uint64
	lastUsed int64
}

// conversionBucket holds every flow whose *local* port is this bucket's index.
// Both directions key on the local port - outgoing on its source port, ingoing
// on the reply's destination port - so one direct index serves both without
// hashing anything on the packet path.
type conversionBucket struct {
	entries []ConversionEntry
}

const (
	// maxFlowsPerPort bounds one local port's flow list. A single socket
	// talking to more distinct endpoints than this is possible but unusual;
	// past the cap the least recently used flow is recycled.
	maxFlowsPerPort = 64
	// cacheShards is the number of striped locks over the bucket array.
	// Sharding keeps eviction from taking a lock that covers every flow on
	// the node while the datapath is trying to translate.
	cacheShards = 256
)

type ProxyCache struct {
	// One bucket per local port number. Higher mem usage but lower cpu usage.
	cache []conversionBucket
	locks [cacheShards]sync.Mutex
	frags *fragmentCache
}

func NewProxyCache() *ProxyCache {
	cache := &ProxyCache{
		cache: make([]conversionBucket, 65536),
		frags: newFragmentCache(),
	}
	cache.runEvictionJob(30*time.Second, 1*time.Minute)
	return cache
}

func shardOf(localPort int) int { return localPort & (cacheShards - 1) }

// runEvictionJob starts a goroutine that periodically evicts old cache entries.
func (cache *ProxyCache) runEvictionJob(interval time.Duration, timeout time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			cache.evictOldEntries(timeout)
			cache.frags.evictExpired()
		}
	}()
}

// evictOldEntries removes flows that have not been used for the duration of
// the timeout. It walks one shard at a time so it never holds a lock covering
// the whole table.
func (cache *ProxyCache) evictOldEntries(timeout time.Duration) {
	now := clock.Unix()
	timeoutSeconds := int64(timeout.Seconds())
	evictedCount := 0

	for shard := range cache.locks {
		cache.locks[shard].Lock()
		for port := shard; port < len(cache.cache); port += cacheShards {
			bucket := &cache.cache[port]
			kept := bucket.entries[:0]
			for _, entry := range bucket.entries {
				if now-entry.lastUsed > timeoutSeconds {
					evictedCount++
					continue
				}
				kept = append(kept, entry)
			}
			if len(kept) == 0 {
				bucket.entries = nil
			} else {
				bucket.entries = kept
			}
		}
		cache.locks[shard].Unlock()
	}

	if evictedCount > 0 {
		logger.InfoLogger().Printf("Evicted %d entries from cache", evictedCount)
	}
}

// Route is what the datapath needs from a cached flow: how to rewrite the
// packet, and where to send it.
type Route struct {
	SrcInstanceIP netip.Addr
	DstIP         netip.Addr
	DstNode       netip.Addr
	DstNodePort   int
}

// ReverseRoute is the equivalent for a reply being translated back.
type ReverseRoute struct {
	DstServiceIP netip.Addr
	SrcIP        netip.Addr
}

// FlowKey identifies one flow: the full 5-tuple, as seen leaving the local
// namespace. See ConversionEntry for why the full tuple, not just a port, is
// what identifies a flow.
type FlowKey struct {
	Protocol                           uint8
	SrcIP, SrcInstanceIP, DstServiceIP netip.Addr
	SrcPort, DstPort                   int
}

// Route resolves the cached route for key. If the flow was chosen under a
// generation older than lookup.Generation, it is revalidated against
// lookup.Entries inside the same held lock and its generation refreshed - so
// later packets on the same flow can skip the scan while the table stays
// unchanged. One lock, one scan.
func (cache *ProxyCache) Route(key FlowKey, lookup resolver.ServiceLookup) (Route, bool) {
	shard := shardOf(key.SrcPort)
	cache.locks[shard].Lock()
	defer cache.locks[shard].Unlock()

	bucket := &cache.cache[key.SrcPort]
	for i := range bucket.entries {
		entry := &bucket.entries[i]
		if entry.protocol != key.Protocol ||
			entry.dstport != key.DstPort ||
			entry.dstServiceIp != key.DstServiceIP ||
			entry.srcip != key.SrcIP ||
			entry.srcInstanceIp != key.SrcInstanceIP {
			continue
		}
		if entry.dstport < 1 {
			return Route{}, false
		}
		if entry.routeGen != lookup.Generation {
			// The table changed since this route was picked, so it has to be
			// checked against the current replica set once. While the
			// generation matches, that scan is skipped entirely.
			if !TableEntryCache.IsRouteStillValid(entry.dstip, entry.dstNode, entry.dstNodePort, lookup.Entries) {
				return Route{}, false
			}
			entry.routeGen = lookup.Generation
		}
		entry.lastUsed = clock.Unix()
		return Route{
			SrcInstanceIP: entry.srcInstanceIp,
			DstIP:         entry.dstip,
			DstNode:       entry.dstNode,
			DstNodePort:   entry.dstNodePort,
		}, true
	}
	return Route{}, false
}

// Install records a freshly chosen route for key, tagged with the
// translation table generation it was chosen from.
func (cache *ProxyCache) Install(key FlowKey, r Route, dstInstanceIP netip.Addr, gen uint64) {
	cache.Add(ConversionEntry{
		srcip:         key.SrcIP,
		dstip:         r.DstIP,
		dstServiceIp:  key.DstServiceIP,
		srcInstanceIp: key.SrcInstanceIP,
		dstInstanceIp: dstInstanceIP,
		srcport:       key.SrcPort,
		dstport:       key.DstPort,
		protocol:      key.Protocol,
		dstNode:       r.DstNode,
		dstNodePort:   r.DstNodePort,
		routeGen:      gen,
	})
}

// Reverse resolves the flow a reply belongs to, so it can be
// reverse-translated. The arguments are read off the reply packet: it is
// addressed to the local namespace IP and local port the flow originated from,
// and sourced from the remote instance IP and port it was sent to.
func (cache *ProxyCache) Reverse(protocol uint8, localNsIP netip.Addr, localPort int,
	remoteIP netip.Addr, remotePort int) (ReverseRoute, bool) {
	shard := shardOf(localPort)
	cache.locks[shard].Lock()
	defer cache.locks[shard].Unlock()

	bucket := &cache.cache[localPort]
	for i := range bucket.entries {
		entry := &bucket.entries[i]
		if entry.protocol != protocol || entry.dstport != remotePort || entry.srcip != localNsIP {
			continue
		}
		// A zero dstInstanceIp means the route had no InstanceNumber
		// ServiceIP to predict the reply source from; fall back to the
		// looser match rather than dropping the flow's replies entirely.
		if entry.dstInstanceIp.IsValid() && entry.dstInstanceIp != remoteIP {
			continue
		}
		entry.lastUsed = clock.Unix()
		return ReverseRoute{DstServiceIP: entry.dstServiceIp, SrcIP: entry.srcip}, true
	}
	return ReverseRoute{}, false
}

// sameFlowAs compares the full forward identity of two entries. Anything less
// - notably comparing destination port alone - conflates distinct flows.
func (e *ConversionEntry) sameFlowAs(other *ConversionEntry) bool {
	return e.protocol == other.protocol &&
		e.srcport == other.srcport &&
		e.dstport == other.dstport &&
		e.srcip == other.srcip &&
		e.srcInstanceIp == other.srcInstanceIp &&
		e.dstServiceIp == other.dstServiceIp
}

// Add inserts a flow, replacing the entry for the same flow if there is one.
func (cache *ProxyCache) Add(entry ConversionEntry) {
	entry.lastUsed = clock.Unix()

	shard := shardOf(entry.srcport)
	cache.locks[shard].Lock()
	defer cache.locks[shard].Unlock()

	bucket := &cache.cache[entry.srcport]
	for i := range bucket.entries {
		if bucket.entries[i].sameFlowAs(&entry) {
			bucket.entries[i] = entry
			return
		}
	}

	if len(bucket.entries) < maxFlowsPerPort {
		bucket.entries = append(bucket.entries, entry)
		return
	}

	// Bucket full: recycle the least recently used flow.
	oldest := 0
	for i := range bucket.entries {
		if bucket.entries[i].lastUsed < bucket.entries[oldest].lastUsed {
			oldest = i
		}
	}
	bucket.entries[oldest] = entry
}
