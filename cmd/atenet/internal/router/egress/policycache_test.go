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

package egress

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.ate.dev/substrate/api/ateapi/v1"
	"go.ate.dev/substrate/cmd/atenet/internal/router/extproc"
	"go.ate.dev/substrate/internal/atenet"
	"go.ate.dev/substrate/internal/egresspolicy"
	"go.ate.dev/substrate/internal/resources"
)

var testActorRef = resources.ActorRef{Atespace: testEgressAtespace, Name: testEgressActor}

// newTestCache builds a cache over client with a clock the test advances.
func newTestCache(client *egressMockClient, ttl time.Duration) (*policyCache, *time.Time) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	c := newPolicyCache(client, ttl)
	c.now = func() time.Time { return now }
	return c, &now
}

func TestPolicyCacheServesFromCacheWithinTTL(t *testing.T) {
	client := &egressMockClient{policy: allowAllPolicy()}
	c, now := newTestCache(client, 10*time.Second)

	for range 3 {
		if _, err := c.get(context.Background(), testActorRef, 0); err != nil {
			t.Fatalf("get: %v", err)
		}
	}
	if calls := client.policyCalls.Load(); calls != 1 {
		t.Fatalf("GetActorEgressPolicy calls = %d, want 1 within the TTL", calls)
	}

	*now = now.Add(10*time.Second + time.Millisecond)
	if _, err := c.get(context.Background(), testActorRef, 0); err != nil {
		t.Fatalf("get after expiry: %v", err)
	}
	if calls := client.policyCalls.Load(); calls != 2 {
		t.Errorf("GetActorEgressPolicy calls = %d, want 2 after the TTL elapsed", calls)
	}
}

// "No policy" is cached exactly like a policy.
func TestPolicyCacheCachesNoPolicy(t *testing.T) {
	client := &egressMockClient{}
	c, _ := newTestCache(client, 10*time.Second)

	for range 3 {
		if _, err := c.get(context.Background(), testActorRef, 0); !errors.Is(err, errNoPolicy) {
			t.Fatalf("get = %v, want errNoPolicy", err)
		}
	}
	if calls := client.policyCalls.Load(); calls != 1 {
		t.Errorf("GetActorEgressPolicy calls = %d, want 1", calls)
	}
}

// A failed fetch answers this request and no other: the next one tries again.
func TestPolicyCacheDoesNotCacheFetchErrors(t *testing.T) {
	client := &egressMockClient{policy: allowAllPolicy(), policyErr: status.Error(codes.Unavailable, "ateapi is down")}
	c, _ := newTestCache(client, 10*time.Second)

	if _, err := c.get(context.Background(), testActorRef, 0); status.Code(errors.Unwrap(err)) != codes.Unavailable {
		t.Fatalf("get = %v, want the Unavailable fetch error", err)
	}
	client.policyErr = nil
	if _, err := c.get(context.Background(), testActorRef, 0); err != nil {
		t.Fatalf("get after ateapi recovered: %v", err)
	}
	if calls := client.policyCalls.Load(); calls != 2 {
		t.Errorf("GetActorEgressPolicy calls = %d, want 2", calls)
	}
}

func TestPolicyCacheDisabledFetchesEveryTime(t *testing.T) {
	client := &egressMockClient{policy: allowAllPolicy()}
	c, _ := newTestCache(client, 0)

	for range 3 {
		if _, err := c.get(context.Background(), testActorRef, 0); err != nil {
			t.Fatalf("get: %v", err)
		}
	}
	if calls := client.policyCalls.Load(); calls != 3 {
		t.Errorf("GetActorEgressPolicy calls = %d, want 3 with the cache disabled", calls)
	}
}

// Concurrent callers on a cold entry share one fetch.
func TestPolicyCacheCollapsesConcurrentFetches(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &egressMockClient{policy: allowAllPolicy(), policyGate: make(chan struct{})}
		c, _ := newTestCache(client, 10*time.Second)

		const callers = 8
		var wg sync.WaitGroup
		errs := make(chan error, callers)
		for range callers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := c.get(context.Background(), testActorRef, 0)
				errs <- err
			}()
		}
		// synctest.Wait returns once every caller is parked on the fetch, so
		// the release below cannot beat one of them to it. A caller that
		// reached the fetch after it completed would start its own, which says
		// nothing about collapsing.
		synctest.Wait()
		close(client.policyGate)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Errorf("get: %v", err)
			}
		}
		if calls := client.policyCalls.Load(); calls != 1 {
			t.Errorf("GetActorEgressPolicy calls = %d, want 1 for %d concurrent callers", calls, callers)
		}
	})
}

// The leader's cancellation must not fail the callers that joined its fetch,
// and the fetch it started still lands in the cache.
func TestPolicyCacheFetchOutlivesCanceledCaller(t *testing.T) {
	client := &egressMockClient{policy: allowAllPolicy(), policyGate: make(chan struct{})}
	c, _ := newTestCache(client, 10*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.get(ctx, testActorRef, 0)
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for client.policyCalls.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no fetch started")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled caller got %v, want context.Canceled", err)
	}

	close(client.policyGate)
	if _, err := c.get(context.Background(), testActorRef, 0); err != nil {
		t.Fatalf("get after the detached fetch completed: %v", err)
	}
	if calls := client.policyCalls.Load(); calls != 1 {
		t.Errorf("GetActorEgressPolicy calls = %d, want 1: the canceled caller's fetch should have been reused", calls)
	}
}

// An entry is stale the instant its TTL has elapsed, not a tick later, and a
// refetch after expiry returns the policy as it is now, not as it was.
func TestPolicyCacheExpiryBoundaryAndUpdateVisibility(t *testing.T) {
	client := &egressMockClient{policy: httpPolicy("old.example")}
	c, now := newTestCache(client, 10*time.Second)

	before, err := c.get(context.Background(), testActorRef, 0)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	client.policy = httpPolicy("new.example")

	*now = now.Add(10*time.Second - time.Nanosecond)
	if p, _ := c.get(context.Background(), testActorRef, 0); p != before {
		t.Fatal("entry refetched before its TTL elapsed")
	}
	*now = now.Add(time.Nanosecond)
	after, err := c.get(context.Background(), testActorRef, 0)
	if err != nil {
		t.Fatalf("get after expiry: %v", err)
	}
	if after == before || !after.EvaluateRequest(egresspolicy.Destination{Hostname: "new.example"}, false).Allowed {
		t.Error("the refetch did not pick up the updated policy")
	}
}

// Expired entries are removed once the map is large enough to matter, so a
// gateway that has seen many actors does not keep a policy for each forever.
func TestPolicyCacheRemovesExpiredEntries(t *testing.T) {
	client := &egressMockClient{policy: allowAllPolicy()}
	c, now := newTestCache(client, 10*time.Second)

	for i := range minCleanupSize {
		ref := resources.ActorRef{Atespace: "a", Name: fmt.Sprintf("actor-%d", i)}
		if _, err := c.get(context.Background(), ref, 0); err != nil {
			t.Fatalf("get: %v", err)
		}
	}
	// The next cleanup runs when the map has doubled; until then the expired
	// entries stay, and at that point all of them go.
	*now = now.Add(11 * time.Second)
	for i := range minCleanupSize {
		ref := resources.ActorRef{Atespace: "b", Name: fmt.Sprintf("actor-%d", i)}
		if _, err := c.get(context.Background(), ref, 0); err != nil {
			t.Fatalf("get: %v", err)
		}
	}
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n != minCleanupSize {
		t.Errorf("cache holds %d entries, want only the %d live ones after the cleanup", n, minCleanupSize)
	}
}

// A tunnel whose CONNECT names a newer policy version than the cache holds is
// decided by a fresh read, without waiting for the TTL.
func TestPolicyCacheRefetchesForANewerVersion(t *testing.T) {
	policy := allowAllPolicy()
	policy.Metadata = &ateapi.ResourceMetadata{Version: 3}
	client := &egressMockClient{policy: policy}
	c, _ := newTestCache(client, 10*time.Second)
	get := func(minVersion int64, wantCalls int32) {
		t.Helper()
		if _, err := c.get(context.Background(), testActorRef, minVersion); err != nil {
			t.Fatalf("get(%d): %v", minVersion, err)
		}
		if calls := client.policyCalls.Load(); calls != wantCalls {
			t.Fatalf("after get(%d): GetActorEgressPolicy calls = %d, want %d", minVersion, calls, wantCalls)
		}
	}
	get(0, 1)
	get(3, 1) // the cached read is already version 3
	get(2, 1)
	policy.Metadata.Version = 4
	get(4, 2) // newer than the cache: read again
	get(4, 2)
	get(0, 2) // the legs inside the tunnel use what the CONNECT fetched
	// A read that comes back older than asked is not repeated on every tunnel.
	get(9, 3)
	get(9, 3)
}

func TestPolicyVersionReadsTheConnectHeader(t *testing.T) {
	for value, want := range map[string]int64{"7": 7, "": 0, "x": 0, "-1": 0} {
		md := &extproc.RequestMetadata{Headers: map[string]string{}}
		if value != "" {
			md.Headers[atenet.EgressPolicyVersionHeader] = value
		}
		if got := policyVersion(md); got != want {
			t.Errorf("policyVersion(%q) = %d, want %d", value, got, want)
		}
	}
}
