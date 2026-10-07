package validate

import (
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/miekg/dns"
)

// RM51X-002: probes cover every nameserver identity, but an address this
// host has no route to (the other address family on a single-stack host)
// is skipped when another address of the same nameserver answers. Any
// other failure, and a nameserver with no reachable address, still fails.

// interceptExchange makes the direct exchange to server fail with err and
// leaves every other exchange on the real transport.
func interceptExchange(t *testing.T, server string, err error) {
	t.Helper()
	orig := directExchange
	directExchange = func(c *dns.Client, m *dns.Msg, srv string) (*dns.Msg, error) {
		if srv == server {
			return nil, err
		}
		return orig(c, m, srv)
	}
	t.Cleanup(func() { directExchange = orig })
}

func routeError(code syscall.Errno) error {
	return &net.OpError{Op: "dial", Net: "udp", Err: &os.SyscallError{Syscall: "connect", Err: code}}
}

type fakeTimeout struct{}

func (fakeTimeout) Error() string   { return "i/o timeout" }
func (fakeTimeout) Timeout() bool   { return true }
func (fakeTimeout) Temporary() bool { return true }

func timeoutError() error {
	return &net.OpError{Op: "read", Net: "udp", Err: fakeTimeout{}}
}

// singleNSDualStack delegates parent.test. to one nameserver whose A points
// at the lab's IPv4 server and whose AAAA is an address outside the lab.
func (l *probeLab) singleNSDualStack(v6 string) {
	l.setResolve(func(q dns.Question, tcp bool) *dns.Msg {
		switch {
		case q.Qtype == dns.TypeNS && strings.EqualFold(q.Name, parentZone):
			return answer(q, []dns.RR{nsRR(parentZone, "ns.parent.test.")}, nil, []dns.RR{aRR("ns.parent.test.", "127.0.0.1")})
		case q.Qtype == dns.TypeAAAA && strings.EqualFold(q.Name, "ns.parent.test."):
			return answer(q, []dns.RR{aaaaRR(q.Name, v6)}, nil, nil)
		}
		return answer(q, nil, nil, nil)
	})
}

func TestRM51X002_UnroutableFamilyIsSkippedWhenTheOtherAnswers(t *testing.T) {
	lab := newProbeLab(t)
	k := testKSK(t, 1)
	unroutable := net.JoinHostPort("100::1", lab.port)
	lab.singleNSDualStack("100::1")
	interceptExchange(t, unroutable, routeError(syscall.ENETUNREACH))
	lab.setAuth(func(addr string, q dns.Question) *dns.Msg {
		if q.Qtype == dns.TypeSOA {
			m := answer(q, []dns.RR{soaRR(q.Name, 42)}, nil, nil)
			m.Authoritative = true
			return m
		}
		return authDS(q, k)
	})
	v := lab.validator()

	obs, err := v.ProbeParentDS("child.parent.test.", []*dns.DNSKEY{k})
	if err != nil {
		t.Fatalf("a route error on one address must not fail the probe when the nameserver answers elsewhere: %v", err)
	}
	if len(obs.Servers) != 1 || obs.Servers[0] != lab.v4() {
		t.Fatalf("answering servers = %v, want only %s", obs.Servers, lab.v4())
	}
	if len(obs.Skipped) != 1 || obs.Skipped[0] != unroutable {
		t.Fatalf("skipped = %v, want %s", obs.Skipped, unroutable)
	}
	if !obs.PresentOnAll[k.KeyTag()] {
		t.Fatalf("presence must be judged over the answering servers: %+v", obs)
	}
	if got := obs.ByNameserver["ns.parent.test."]; len(got) != 2 {
		t.Fatalf("the discovered address list must still carry both families: %v", got)
	}

	ok, details, err := v.ProbePublishedSerial("parent.test.", 42)
	if err != nil || !ok {
		t.Fatalf("publication probe = %v, %q, %v; want confirmed", ok, details, err)
	}
	if !strings.Contains(details, "skipped") || !strings.Contains(details, unroutable) {
		t.Fatalf("details must name the skipped address: %q", details)
	}
}

func TestRM51X002_TimeoutOnOneAddressStillFails(t *testing.T) {
	lab := newProbeLab(t)
	k := testKSK(t, 1)
	silent := net.JoinHostPort("100::1", lab.port)
	lab.singleNSDualStack("100::1")
	interceptExchange(t, silent, timeoutError())
	lab.setAuth(func(addr string, q dns.Question) *dns.Msg {
		if q.Qtype == dns.TypeSOA {
			m := answer(q, []dns.RR{soaRR(q.Name, 42)}, nil, nil)
			m.Authoritative = true
			return m
		}
		return authDS(q, k)
	})
	v := lab.validator()

	_, err := v.ProbeParentDS("child.parent.test.", []*dns.DNSKEY{k})
	if err == nil || !strings.Contains(err.Error(), silent) || !strings.Contains(err.Error(), "ns.parent.test.") {
		t.Fatalf("a timeout is a partial view and must fail naming the address and nameserver, got %v", err)
	}
	ok, details, err := v.ProbePublishedSerial("parent.test.", 42)
	if err != nil || ok {
		t.Fatalf("publication probe = %v, %q, %v; want not yet", ok, details, err)
	}
	if !strings.Contains(details, "SOA query to "+silent) {
		t.Fatalf("details must name the silent address: %q", details)
	}
}

func TestRM51X002_NameserverWithNoReachableAddressFails(t *testing.T) {
	lab := newProbeLab(t)
	k := testKSK(t, 1)
	unroutable := net.JoinHostPort("100::1", lab.port)
	// Two identities: ns4 answers on IPv4; ns6 exists only at an address this
	// host cannot route to. Coverage of ns6 is impossible, so the probe fails.
	lab.setResolve(func(q dns.Question, tcp bool) *dns.Msg {
		switch {
		case q.Qtype == dns.TypeNS && strings.EqualFold(q.Name, parentZone):
			return answer(q,
				[]dns.RR{nsRR(parentZone, "ns4.parent.test."), nsRR(parentZone, "ns6.parent.test.")}, nil,
				[]dns.RR{aRR("ns4.parent.test.", "127.0.0.1"), aaaaRR("ns6.parent.test.", "100::1")})
		case q.Qtype == dns.TypeAAAA && strings.EqualFold(q.Name, "ns4.parent.test."),
			q.Qtype == dns.TypeA && strings.EqualFold(q.Name, "ns6.parent.test."):
			return answer(q, nil, nil, nil)
		}
		return answer(q, nil, nil, nil)
	})
	interceptExchange(t, unroutable, routeError(syscall.EHOSTUNREACH))
	lab.setAuth(func(addr string, q dns.Question) *dns.Msg { return authDS(q, k) })

	_, err := lab.validator().ProbeParentDS("child.parent.test.", []*dns.DNSKEY{k})
	if err == nil || !strings.Contains(err.Error(), "no address of nameserver ns6.parent.test. is reachable") {
		t.Fatalf("an identity with no reachable address must fail the probe, got %v", err)
	}
	if lab.queries(lab.v4()) == 0 {
		t.Fatal("the reachable identity must still have been queried")
	}
}

func TestRM51X002_IsLocalRouteError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"network unreachable", routeError(syscall.ENETUNREACH), true},
		{"host unreachable", routeError(syscall.EHOSTUNREACH), true},
		{"address not available", routeError(syscall.EADDRNOTAVAIL), true},
		{"family unsupported", routeError(syscall.EAFNOSUPPORT), true},
		{"connection refused is a server-side condition", routeError(syscall.ECONNREFUSED), false},
		{"timeout", timeoutError(), false},
		{"plain error", errors.New("dns: bad rrset"), false},
		{"wrapped route error", &net.OpError{Op: "dial", Err: routeError(syscall.ENETUNREACH)}, true},
	}
	for _, tc := range cases {
		if got := isLocalRouteError(tc.err); got != tc.want {
			t.Errorf("%s: isLocalRouteError = %v, want %v", tc.name, got, tc.want)
		}
	}
}
