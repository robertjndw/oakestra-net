package env

import (
	"NetManager/TableEntryCache"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func resolvableEntry(job, vip string) TableEntryCache.TableEntry {
	return TableEntryCache.TableEntry{
		JobName:          job,
		Appname:          "app",
		Appns:            "ns",
		Servicename:      "svc",
		Servicenamespace: "svcns",
		Instancenumber:   0,
		Cluster:          0,
		Nodeip:           net.ParseIP("10.0.0.1"),
		Nodeport:         50103,
		Nsip:             net.ParseIP("10.19.1.1"),
		Nsipv6:           net.ParseIP("fc00::1"),
		ServiceIP: []TableEntryCache.ServiceIP{{
			IpType:     TableEntryCache.RoundRobin,
			Address:    net.ParseIP(vip),
			Address_v6: net.ParseIP("fdff::1"),
		}},
	}
}

// A table query that leaves the address unresolved must be reported as a
// failure. resolveServiceIPOnce keys the negative cache off the return value,
// so reporting success would clear it and let the next packet start another
// blocking MQTT round trip - one per packet burst, for an address that is
// never going to resolve.
func TestUnresolvedQueryIsAFailure(t *testing.T) {
	const vip = "10.30.9.9"
	addr := netip.MustParseAddr(vip)

	for name, query := range map[string]func(netip.Addr) ([]TableEntryCache.TableEntry, error){
		"query failed": func(netip.Addr) ([]TableEntryCache.TableEntry, error) {
			return nil, errors.New("mqtt timeout")
		},
		"empty response": func(netip.Addr) ([]TableEntryCache.TableEntry, error) {
			return nil, nil
		},
		"invalid entries": func(netip.Addr) ([]TableEntryCache.TableEntry, error) {
			bad := resolvableEntry("job", vip)
			bad.Nodeip = nil
			return []TableEntryCache.TableEntry{bad}, nil
		},
		"response for a different address": func(netip.Addr) ([]TableEntryCache.TableEntry, error) {
			return []TableEntryCache.TableEntry{resolvableEntry("job", "10.30.1.1")}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			env := &Environment{
				translationTable: TableEntryCache.NewTableManager(),
				tableQuery:       query,
			}

			if err := env.resolveServiceIP(addr); err == nil {
				t.Fatal("resolveServiceIP reported success for an address it did not resolve")
			}

			// The failure has to reach the negative cache, or the address is
			// re-queried on every packet.
			<-env.resolveServiceIPOnce(addr)
			env.resolveLock.Lock()
			_, remembered := env.failedServiceIPs[addr]
			env.resolveLock.Unlock()
			if !remembered {
				t.Error("the failed resolution was not recorded in the negative cache")
			}

			// And a following packet must be turned away rather than starting
			// a second query.
			if again := env.resolveServiceIPOnce(addr); again != nil {
				t.Error("a second resolution was started inside the negative-cache TTL")
			}
		})
	}
}

// The negative cache is a rate limit, not a permanent block: once the TTL is
// past, the address gets another chance.
func TestNegativeCacheExpires(t *testing.T) {
	addr := netip.MustParseAddr("10.30.9.9")
	env := &Environment{
		translationTable: TableEntryCache.NewTableManager(),
		tableQuery: func(netip.Addr) ([]TableEntryCache.TableEntry, error) {
			return nil, errors.New("mqtt timeout")
		},
	}

	<-env.resolveServiceIPOnce(addr)
	if env.resolveServiceIPOnce(addr) != nil {
		t.Fatal("expected the negative cache to suppress an immediate retry")
	}

	env.resolveLock.Lock()
	env.failedServiceIPs[addr] = time.Now().Add(-2 * negativeResolveCacheTTL)
	env.resolveLock.Unlock()

	done := env.resolveServiceIPOnce(addr)
	if done == nil {
		t.Fatal("expected a retry once the negative-cache TTL had passed")
	}
	<-done
}

// A response that does not answer the question must not leave any trace in the
// table. ReplaceJobEntries deliberately displaces whatever holds the namespace
// IPs a new entry claims, so installing first and validating afterwards lets a
// rejected response destroy a perfectly good route on its way out.
func TestWrongAddressResponseLeavesTableUntouched(t *testing.T) {
	const wantedVIP = "10.30.9.9"

	// An existing, healthy route, sharing a namespace IP with what the bogus
	// response will claim.
	good := resolvableEntry("goodjob", "10.30.1.1")

	env := &Environment{
		translationTable: TableEntryCache.NewTableManager(),
		tableQuery: func(netip.Addr) ([]TableEntryCache.TableEntry, error) {
			// structurally valid, for a different job, and answering for a
			// Service IP that is not the one we asked about
			return []TableEntryCache.TableEntry{resolvableEntry("otherjob", "10.30.2.2")}, nil
		},
	}
	if err := env.translationTable.Add(good); err != nil {
		t.Fatal(err)
	}

	if err := env.resolveServiceIP(netip.MustParseAddr(wantedVIP)); err == nil {
		t.Fatal("expected an error for a response that does not resolve the requested address")
	}

	if got := len(env.translationTable.SearchByJobName("goodjob")); got != 1 {
		t.Errorf("the rejected response displaced the existing route: goodjob has %d entries, want 1", got)
	}
	if got := len(env.translationTable.SearchByJobName("otherjob")); got != 0 {
		t.Errorf("the rejected response was installed anyway: otherjob has %d entries, want 0", got)
	}
	if entries, _ := env.translationTable.SearchByServiceIP(netip.MustParseAddr("10.30.1.1")); len(entries) != 1 {
		t.Errorf("the existing route is no longer resolvable: %d entries", len(entries))
	}
}

// Every entry in one response belongs to one job (responseParser stamps a
// single JobName), so a response that mixes jobs is malformed and must be
// rejected rather than half-installed under the first entry's name.
func TestMixedJobResponseRejected(t *testing.T) {
	env := &Environment{
		translationTable: TableEntryCache.NewTableManager(),
		tableQuery: func(netip.Addr) ([]TableEntryCache.TableEntry, error) {
			first := resolvableEntry("jobone", "10.30.9.9")
			second := resolvableEntry("jobtwo", "10.30.9.9")
			second.Nsip = net.ParseIP("10.19.1.2")
			return []TableEntryCache.TableEntry{first, second}, nil
		},
	}

	if err := env.resolveServiceIP(netip.MustParseAddr("10.30.9.9")); err == nil {
		t.Fatal("expected an error for a response mixing job names")
	}
	if got := len(env.translationTable.SearchByJobName("jobone")); got != 0 {
		t.Errorf("a malformed response was partially installed: jobone has %d entries", got)
	}
}
