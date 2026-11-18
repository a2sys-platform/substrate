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
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"go.ate.dev/substrate/internal/proto/ateletpb"
)

const (
	// egressPolicyWatchInterval is how often an active actor's egress policy is
	// read to see whether it stopped allowing a TLS passthrough destination.
	// It is the fallback for a change nobody announced on the control port; a
	// caller that wants the change applied at once sends "refresh" there.
	egressPolicyWatchInterval = time.Minute

	// egressStreamResetDelay is how long after such a change the actor's open
	// tunnels are closed. The gateway keeps deciding by the policy it cached,
	// for up to its --egress-policy-cache-ttl (10s by default), so a tunnel
	// opened in that time can still be one the old policy authorized. Closing
	// only once it has passed leaves none of those open.
	egressStreamResetDelay = 10 * time.Second
)

// egressPolicyWatch closes an actor's open egress tunnels after its egress
// policy stops allowing a TLS passthrough destination.
//
// The gateway authorizes a passthrough tunnel once, at its ClientHello, and
// need not close it when the policy changes. Without this watch a workload
// keeps reaching a destination the policy no longer allows for as long as it
// holds a connection opened earlier.
type egressPolicyWatch struct {
	fetch func(context.Context) (*ateletpb.EgressPolicy, error)
	reset func()
	// interval is the time between reads of the policy.
	interval time.Duration
	// delay is the time from seeing the change to closing the tunnels.
	delay time.Duration
	log   *slog.Logger

	// mu guards last and fetched, which run and control both advance.
	mu      sync.Mutex
	last    *ateletpb.EgressPolicy
	fetched bool
}

// check reads the policy and reports whether it stopped allowing a TLS
// passthrough destination since the last read. The first read is the baseline.
func (w *egressPolicyWatch) check(ctx context.Context) (narrowed bool, err error) {
	fetchCtx, cancel := context.WithTimeout(ctx, egressPolicyFetchTimeout)
	defer cancel()
	policy, err := w.fetch(fetchCtx)
	if err != nil {
		// last stays, so a change made while atelet was unreachable is still
		// seen afterwards.
		return false, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	narrowed = w.fetched && passthroughNarrowed(w.last, policy)
	w.last, w.fetched = policy, true
	return narrowed, nil
}

// control runs one operation sent to the actor's control port and returns the
// answer line.
//
//	refresh  reads the policy now. The DNS relay answers by it from here on,
//	         and if it stopped allowing a passthrough destination the open
//	         tunnels are closed. Answers "ok narrowed" or "ok".
//	reset    closes the open tunnels. A caller sends it once the gateway's
//	         policy cache has expired, to close a tunnel the old policy
//	         authorized after refresh.
func (w *egressPolicyWatch) control(ctx context.Context, op string) string {
	switch op {
	case "refresh":
		narrowed, err := w.check(ctx)
		if err != nil {
			return "err " + err.Error()
		}
		if narrowed {
			w.reset()
			return "ok narrowed"
		}
		return "ok"
	case "reset":
		w.reset()
		return "ok"
	}
	return "err unknown operation"
}

// run watches until ctx ends. The first policy it reads is the baseline, so
// it starts with a read rather than waiting one interval.
func (w *egressPolicyWatch) run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	// resetAt fires when the tunnels are due to close; nil when none are.
	var resetAt <-chan time.Time
	for {
		narrowed, err := w.check(ctx)
		switch {
		case err != nil:
			w.log.DebugContext(ctx, "Could not read the actor's egress policy to watch it for changes", slog.Any("err", err))
		case narrowed:
			// A later change restarts the delay: the tunnels it leaves behind
			// were authorized until now.
			resetAt = time.After(w.delay)
		}

		select {
		case <-ctx.Done():
			return
		case <-resetAt:
			resetAt = nil
			w.log.InfoContext(ctx, "Closing the actor's open egress tunnels: its egress policy stopped allowing a TLS passthrough destination")
			w.reset()
		case <-ticker.C:
		}
	}
}

// passthroughNarrowed reports whether next stops allowing a TLS passthrough
// destination that prev allowed. HTTP and intercepted HTTPS do not count: the
// gateway authorizes those per request. It compares the rules as written and
// errs toward true, which only costs the actor a reconnect.
func passthroughNarrowed(prev, next *ateletpb.EgressPolicy) bool {
	for _, rule := range prev.GetRules() {
		allowed := rule.GetTlsPassthrough()
		for _, hostname := range allowed.GetHostnames() {
			if !passthroughAllows(next, hostname, allowed.GetPorts()) {
				return true
			}
		}
	}
	return false
}

// passthroughAllows reports whether one passthrough rule of policy allows the
// hostname pattern on all of ports.
func passthroughAllows(policy *ateletpb.EgressPolicy, hostname string, ports *ateletpb.EgressPorts) bool {
	for _, rule := range policy.GetRules() {
		allowed := rule.GetTlsPassthrough()
		if allowed == nil || !portsCover(allowed.GetPorts(), ports) {
			continue
		}
		if slices.ContainsFunc(allowed.GetHostnames(), func(pattern string) bool { return patternCovers(pattern, hostname) }) {
			return true
		}
	}
	return false
}

// patternCovers reports whether every name the hostname pattern matches is
// also matched by pattern.
func patternCovers(pattern, hostname string) bool {
	if pattern == "*" || pattern == hostname {
		return true
	}
	suffix, wildcard := strings.CutPrefix(pattern, "*")
	if !wildcard {
		return false
	}
	// "*.example.com" covers a name with exactly one label before the suffix.
	label, found := strings.CutSuffix(hostname, suffix)
	return found && label != "" && !strings.ContainsAny(label, ".*")
}

// portsCover reports whether have includes every port of want.
func portsCover(have, want *ateletpb.EgressPorts) bool {
	if have.GetAll() != nil {
		return true
	}
	if want.GetAll() != nil {
		return false
	}
	for _, port := range want.GetNumbers() {
		if !slices.Contains(have.GetNumbers(), port) {
			return false
		}
	}
	return true
}
