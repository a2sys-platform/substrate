//go:build linux

// Copyright 2026 The Agent Substrate Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package atunnel

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"go.ate.dev/substrate/internal/proto/ateletpb"
)

func passthrough(ports *ateletpb.EgressPorts, hostnames ...string) *ateletpb.EgressRule {
	return &ateletpb.EgressRule{TlsPassthrough: &ateletpb.EgressDestinations{Hostnames: hostnames, Ports: ports}}
}

func policyOf(rules ...*ateletpb.EgressRule) *ateletpb.EgressPolicy {
	return &ateletpb.EgressPolicy{Rules: rules}
}

var (
	allPorts = &ateletpb.EgressPorts{All: &ateletpb.EgressAllPorts{}}
	port443  = &ateletpb.EgressPorts{Numbers: []int32{443}}
)

func TestPassthroughNarrowed(t *testing.T) {
	httpOnly := policyOf(&ateletpb.EgressRule{Http: &ateletpb.EgressDestinations{Hostnames: []string{"*"}, Ports: allPorts}})
	cases := []struct {
		name       string
		prev, next *ateletpb.EgressPolicy
		want       bool
	}{
		{"same policy", policyOf(passthrough(allPorts, "pypi.org")), policyOf(passthrough(allPorts, "pypi.org")), false},
		{"no policy to a policy", nil, policyOf(passthrough(allPorts, "pypi.org")), false},
		{"policy removed", policyOf(passthrough(allPorts, "pypi.org")), nil, true},
		{"hostname added", policyOf(passthrough(allPorts, "a.com")), policyOf(passthrough(allPorts, "a.com", "b.com")), false},
		{"hostname replaced", policyOf(passthrough(allPorts, "a.com")), policyOf(passthrough(allPorts, "b.com")), true},
		{"hostname widened to every name", policyOf(passthrough(allPorts, "a.com")), policyOf(passthrough(allPorts, "*")), false},
		{"every name narrowed to one", policyOf(passthrough(allPorts, "*")), policyOf(passthrough(allPorts, "a.com")), true},
		{"name covered by a wildcard", policyOf(passthrough(allPorts, "api.a.com")), policyOf(passthrough(allPorts, "*.a.com")), false},
		{"wildcard does not cover the bare name", policyOf(passthrough(allPorts, "a.com")), policyOf(passthrough(allPorts, "*.a.com")), true},
		{"wildcard does not cover two labels", policyOf(passthrough(allPorts, "x.api.a.com")), policyOf(passthrough(allPorts, "*.a.com")), true},
		{"wildcard does not cover a wider wildcard", policyOf(passthrough(allPorts, "*.a.com")), policyOf(passthrough(allPorts, "*.api.a.com")), true},
		{"ports narrowed", policyOf(passthrough(allPorts, "a.com")), policyOf(passthrough(port443, "a.com")), true},
		{"ports widened", policyOf(passthrough(port443, "a.com")), policyOf(passthrough(allPorts, "a.com")), false},
		{"passthrough replaced by http", policyOf(passthrough(allPorts, "*")), httpOnly, true},
		{"http rule removed", httpOnly, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := passthroughNarrowed(tc.prev, tc.next); got != tc.want {
				t.Errorf("passthroughNarrowed = %v, want %v", got, tc.want)
			}
		})
	}
}

// watchedPolicy is the policy a test's watch reads, and the resets it made.
type watchedPolicy struct {
	mu     sync.Mutex
	policy *ateletpb.EgressPolicy
	err    error
	resets chan time.Time
}

func (p *watchedPolicy) set(policy *ateletpb.EgressPolicy, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.policy, p.err = policy, err
}

func startWatch(t *testing.T, initial *ateletpb.EgressPolicy, delay time.Duration) *watchedPolicy {
	t.Helper()
	p := &watchedPolicy{policy: initial, resets: make(chan time.Time, 8)}
	fetched := make(chan struct{}, 1)
	watch := &egressPolicyWatch{
		fetch: func(context.Context) (*ateletpb.EgressPolicy, error) {
			p.mu.Lock()
			defer p.mu.Unlock()
			select {
			case fetched <- struct{}{}:
			default:
			}
			return p.policy, p.err
		},
		reset:    func() { p.resets <- time.Now() },
		interval: 5 * time.Millisecond,
		delay:    delay,
		log:      slog.New(slog.DiscardHandler),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		watch.run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	// The baseline is read before the test changes the policy.
	<-fetched
	time.Sleep(20 * time.Millisecond)
	return p
}

func TestEgressPolicyWatchResetsAfterTheDelayWhenPassthroughNarrows(t *testing.T) {
	const delay = 150 * time.Millisecond
	p := startWatch(t, policyOf(passthrough(allPorts, "*")), delay)
	changed := time.Now()
	p.set(policyOf(passthrough(allPorts, "pypi.org")), nil)
	select {
	case at := <-p.resets:
		if waited := at.Sub(changed); waited < delay {
			t.Errorf("reset %s after the change, before the %s delay", waited, delay)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no reset after the policy narrowed")
	}
	select {
	case <-p.resets:
		t.Error("a second reset for one change")
	case <-time.After(2 * delay):
	}
}

func TestEgressPolicyWatchLeavesTunnelsWhenPassthroughWidens(t *testing.T) {
	p := startWatch(t, policyOf(passthrough(allPorts, "pypi.org")), time.Millisecond)
	p.set(policyOf(passthrough(allPorts, "pypi.org", "example.com")), nil)
	p.set(policyOf(passthrough(allPorts, "*")), nil)
	select {
	case <-p.resets:
		t.Error("reset although the policy only widened")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestEgressPolicyWatchSeesAChangeMadeWhileFetchesFailed(t *testing.T) {
	p := startWatch(t, policyOf(passthrough(allPorts, "*")), time.Millisecond)
	p.set(nil, errors.New("atelet is unreachable"))
	time.Sleep(30 * time.Millisecond)
	select {
	case <-p.resets:
		t.Fatal("reset on a failed fetch")
	default:
	}
	p.set(nil, nil)
	select {
	case <-p.resets:
	case <-time.After(5 * time.Second):
		t.Fatal("no reset once the removed policy could be read")
	}
}
