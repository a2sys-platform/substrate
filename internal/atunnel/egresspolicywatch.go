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
	"strconv"
	"strings"
	"sync"
	"time"

	"go.ate.dev/substrate/internal/proto/ateletpb"
)

const (
	// egressPolicyWatchInterval is how often an active actor's egress policy is
	// read to see whether it stopped allowing a destination. It is the
	// fallback for a change nobody announced on the control port; a caller
	// that wants the change applied at once sends "refresh" there.
	egressPolicyWatchInterval = time.Minute

	// egressStreamResetDelay is how long after the fallback sees such a change
	// the actor's open tunnels are closed. Without a policy version to send,
	// the gateway keeps deciding by the policy it cached for up to its
	// --egress-policy-cache-ttl (10s by default), so a tunnel opened in that
	// time can still be one the old policy authorized. Closing only once it
	// has passed leaves none of those open.
	egressStreamResetDelay = 10 * time.Second
)

// egressPolicyWatch closes an actor's open egress tunnels after its egress
// policy stops allowing a destination.
//
// The gateway decides a TLS passthrough tunnel once, at its ClientHello, and
// decides the requests inside any other tunnel by the policy it has cached.
// Closing the tunnels makes the actor open new ones, which the gateway decides
// afresh.
type egressPolicyWatch struct {
	fetch func(context.Context) (*ateletpb.EgressPolicy, error)
	reset func()
	// stamp makes later tunnels carry a policy version to the gateway.
	stamp func(version int64)
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

// check reads the policy and reports whether it stopped allowing a
// destination since the last read. The first read is the baseline.
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
	narrowed = w.fetched && policyNarrowed(w.last, policy)
	w.last, w.fetched = policy, true
	return narrowed, nil
}

// control runs one operation sent to the actor's control port and returns the
// answer line.
//
//	refresh  reads the policy now. The DNS relay answers by it from here on,
//	         and if it stopped allowing a destination the open tunnels are
//	         closed. With a version, later tunnels carry it to the gateway,
//	         which then decides them by a policy at least that new. Answers
//	         "ok narrowed" or "ok".
//	reset    closes the open tunnels. A caller whose gateway does not read the
//	         version sends it once the gateway's policy cache has expired, to
//	         close a tunnel the old policy authorized after refresh.
func (w *egressPolicyWatch) control(ctx context.Context, op, version string) string {
	switch op {
	case "refresh":
		if version != "" {
			v, err := strconv.ParseInt(version, 10, 64)
			if err != nil || v <= 0 {
				return "err version must be a positive integer"
			}
			// Before the tunnels close: every tunnel opened from here on
			// carries the version, and the ones opened before it are the ones
			// reset closes.
			w.stamp(v)
		}
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
			w.log.InfoContext(ctx, "Closing the actor's open egress tunnels: its egress policy stopped allowing a destination")
			w.reset()
		case <-ticker.C:
		}
	}
}

// policyNarrowed reports whether next stops allowing a destination that prev
// allowed. It compares the rules of each protocol as written and errs toward
// true, which only costs the actor a reconnect.
func policyNarrowed(prev, next *ateletpb.EgressPolicy) bool {
	for _, destinations := range []func(*ateletpb.EgressRule) *ateletpb.EgressDestinations{
		(*ateletpb.EgressRule).GetHttp,
		(*ateletpb.EgressRule).GetHttps,
		(*ateletpb.EgressRule).GetTlsPassthrough,
	} {
		for _, rule := range prev.GetRules() {
			allowed := destinations(rule)
			for _, hostname := range allowed.GetHostnames() {
				if !allows(next, destinations, hostname, allowed.GetPorts()) {
					return true
				}
			}
		}
	}
	return false
}

// allows reports whether one rule of policy, under the protocol destinations
// reads, allows the hostname pattern on all of ports.
func allows(policy *ateletpb.EgressPolicy, destinations func(*ateletpb.EgressRule) *ateletpb.EgressDestinations, hostname string, ports *ateletpb.EgressPorts) bool {
	for _, rule := range policy.GetRules() {
		allowed := destinations(rule)
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
