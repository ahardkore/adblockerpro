package resolver

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestGroupCoalesces proves the point of the single-flight: when a smart TV
// and a phone ask for the same hostname at the same moment, only one packet
// leaves the Pi.
func TestGroupCoalesces(t *testing.T) {
	g := NewGroup()
	var calls int32
	release := make(chan struct{})

	const waiters = 20
	var wg sync.WaitGroup
	results := make([][]byte, waiters)
	shared := make([]bool, waiters)

	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, _, sh, err := g.Do(context.Background(), "example.com|1", func() ([]byte, string, error) {
				atomic.AddInt32(&calls, 1)
				<-release
				return []byte{0xAB, 0xCD, 0x01, 0x02}, "1.1.1.1:53", nil
			})
			if err != nil {
				t.Errorf("waiter %d: %v", i, err)
				return
			}
			results[i] = resp
			shared[i] = sh
		}(i)
	}

	// Give the goroutines a moment to pile up on the same key.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("upstream called %d times, want 1", n)
	}
	sharedCount := 0
	for i, r := range results {
		if len(r) != 4 || r[0] != 0xAB {
			t.Fatalf("waiter %d got %v", i, r)
		}
		if shared[i] {
			sharedCount++
		}
	}
	if sharedCount != waiters-1 {
		t.Errorf("%d waiters marked shared, want %d", sharedCount, waiters-1)
	}

	started, sharedStat := g.Stats()
	if started != 1 {
		t.Errorf("started = %d, want 1", started)
	}
	if sharedStat != uint64(waiters-1) {
		t.Errorf("shared = %d, want %d", sharedStat, waiters-1)
	}
}

// TestGroupCopiesResponse makes sure one waiter rewriting the DNS
// transaction id cannot corrupt another waiter's answer.
func TestGroupCopiesResponse(t *testing.T) {
	g := NewGroup()
	first, _, _, err := g.Do(context.Background(), "k", func() ([]byte, string, error) {
		return []byte{1, 2, 3, 4}, "up", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	first[0] = 0xFF

	second, _, _, err := g.Do(context.Background(), "k", func() ([]byte, string, error) {
		return []byte{1, 2, 3, 4}, "up", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if second[0] != 1 {
		t.Error("waiters share the same backing array")
	}
}

func TestGroupPropagatesError(t *testing.T) {
	g := NewGroup()
	var wg sync.WaitGroup
	release := make(chan struct{})
	errs := make([]error, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, _, err := g.Do(context.Background(), "bad", func() ([]byte, string, error) {
				<-release
				return nil, "", context.DeadlineExceeded
			})
			errs[i] = err
		}(i)
	}
	time.Sleep(30 * time.Millisecond)
	close(release)
	wg.Wait()
	for i, err := range errs {
		if err == nil {
			t.Errorf("waiter %d did not see the error", i)
		}
	}
	if g.InFlight() != 0 {
		t.Errorf("InFlight = %d after completion, want 0", g.InFlight())
	}
}

// TestGroupCancellation: a waiter that gives up must not block the others.
func TestGroupCancellation(t *testing.T) {
	g := NewGroup()
	release := make(chan struct{})
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, _, err := g.Do(ctx, "slow", func() ([]byte, string, error) {
			<-release
			return []byte{9}, "up", nil
		})
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Error("cancelled waiter returned no error")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled waiter did not return")
	}
}

func TestGroupSequentialCallsAreNotShared(t *testing.T) {
	g := NewGroup()
	for i := 0; i < 3; i++ {
		_, _, shared, err := g.Do(context.Background(), "seq", func() ([]byte, string, error) {
			return []byte{byte(i)}, "up", nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if shared {
			t.Errorf("call %d reported as shared", i)
		}
	}
	started, shared := g.Stats()
	if started != 3 || shared != 0 {
		t.Errorf("stats = (%d,%d), want (3,0)", started, shared)
	}
}
