package resolver

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

// an unresolved query must return an error, or the negative cache never arms
// and every packet burst restarts a blocking MQTT round trip
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
			r := &ServiceResolver{
				translationTable: TableEntryCache.NewTableManager(),
				tableQuery:       query,
			}

			if err := r.resolveServiceIP(addr); err == nil {
				t.Fatal("resolveServiceIP reported success for an address it did not resolve")
			}

			<-r.resolveServiceIPOnce(addr)
			r.resolveLock.Lock()
			_, remembered := r.failedServiceIPs[addr]
			r.resolveLock.Unlock()
			if !remembered {
				t.Error("the failed resolution was not recorded in the negative cache")
			}

			if again := r.resolveServiceIPOnce(addr); again != nil {
				t.Error("a second resolution was started inside the negative-cache TTL")
			}
		})
	}
}

func TestNegativeCacheExpires(t *testing.T) {
	addr := netip.MustParseAddr("10.30.9.9")
	r := &ServiceResolver{
		translationTable: TableEntryCache.NewTableManager(),
		tableQuery: func(netip.Addr) ([]TableEntryCache.TableEntry, error) {
			return nil, errors.New("mqtt timeout")
		},
	}

	<-r.resolveServiceIPOnce(addr)
	if r.resolveServiceIPOnce(addr) != nil {
		t.Fatal("expected the negative cache to suppress an immediate retry")
	}

	r.resolveLock.Lock()
	r.failedServiceIPs[addr] = time.Now().Add(-2 * negativeResolveCacheTTL)
	r.resolveLock.Unlock()

	done := r.resolveServiceIPOnce(addr)
	if done == nil {
		t.Fatal("expected a retry once the negative-cache TTL had passed")
	}
	<-done
}

// a rejected response must not displace the existing route sharing its namespace IP
func TestWrongAddressResponseLeavesTableUntouched(t *testing.T) {
	const wantedVIP = "10.30.9.9"

	good := resolvableEntry("goodjob", "10.30.1.1")

	r := &ServiceResolver{
		translationTable: TableEntryCache.NewTableManager(),
		tableQuery: func(netip.Addr) ([]TableEntryCache.TableEntry, error) {
			// valid response, but for a different job and a different Service IP than asked
			return []TableEntryCache.TableEntry{resolvableEntry("otherjob", "10.30.2.2")}, nil
		},
	}
	if err := r.translationTable.Add(good); err != nil {
		t.Fatal(err)
	}

	if err := r.resolveServiceIP(netip.MustParseAddr(wantedVIP)); err == nil {
		t.Fatal("expected an error for a response that does not resolve the requested address")
	}

	if got := len(r.translationTable.SearchByJobName("goodjob")); got != 1 {
		t.Errorf("the rejected response displaced the existing route: goodjob has %d entries, want 1", got)
	}
	if got := len(r.translationTable.SearchByJobName("otherjob")); got != 0 {
		t.Errorf("the rejected response was installed anyway: otherjob has %d entries, want 0", got)
	}
	if entries, _ := r.translationTable.SearchByServiceIP(netip.MustParseAddr("10.30.1.1")); len(entries) != 1 {
		t.Errorf("the existing route is no longer resolvable: %d entries", len(entries))
	}
}

func TestMixedJobResponseRejected(t *testing.T) {
	r := &ServiceResolver{
		translationTable: TableEntryCache.NewTableManager(),
		tableQuery: func(netip.Addr) ([]TableEntryCache.TableEntry, error) {
			first := resolvableEntry("jobone", "10.30.9.9")
			second := resolvableEntry("jobtwo", "10.30.9.9")
			second.Nsip = net.ParseIP("10.19.1.2")
			return []TableEntryCache.TableEntry{first, second}, nil
		},
	}

	if err := r.resolveServiceIP(netip.MustParseAddr("10.30.9.9")); err == nil {
		t.Fatal("expected an error for a response mixing job names")
	}
	if got := len(r.translationTable.SearchByJobName("jobone")); got != 0 {
		t.Errorf("a malformed response was partially installed: jobone has %d entries", got)
	}
}
