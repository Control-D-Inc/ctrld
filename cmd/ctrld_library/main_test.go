package ctrld_library

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Control-D-Inc/ctrld/cmd/cli"
)

// Tests replace the first host-touching calls, not the Controller methods.
// They must not run in parallel because these seams are package globals.
func stubMobile(t *testing.T, run func(*cli.AppConfig, *cli.AppCallback, chan struct{}), check func(int64, chan struct{}) int) {
	t.Helper()
	oldRun, oldCheck := runMobile, checkDeactivationPin
	runMobile, checkDeactivationPin = run, check
	t.Cleanup(func() { runMobile, checkDeactivationPin = oldRun, oldCheck })
}

func startController(c *Controller) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		c.Start("uid", "provision", "hostname", "home", "doh", 2, "log")
		close(done)
	}()
	return done
}

func TestControllerConcurrentLifecycle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := NewController(nil)
		var runs, active atomic.Int32
		var pinCalls int // Deliberately non-atomic: PIN checks must be serialized.
		stubMobile(t, func(config *cli.AppConfig, _ *cli.AppCallback, stop chan struct{}) {
			if active.Add(1) != 1 {
				t.Error("overlapping mobile runs")
			}
			defer active.Add(-1)
			runs.Add(1)
			want := cli.AppConfig{CdUID: "uid", ProvisionID: "provision", CustomHostname: "hostname", HomeDir: "home", UpstreamProto: "doh", Verbose: 2, LogPath: "log"}
			if *config != want {
				t.Errorf("config = %+v, want %+v", *config, want)
			}
			<-stop
		}, func(_ int64, _ chan struct{}) int {
			pinCalls++
			return 0
		})

		if c.IsRunning() || c.Stop(true, 0) != 0 {
			t.Fatal("new controller must be stopped")
		}
		for cycle := 0; cycle < 25; cycle++ {
			var starters sync.WaitGroup
			for i := 0; i < 16; i++ {
				starters.Add(1)
				go func() { defer starters.Done(); <-startController(c) }()
			}
			synctest.Wait()
			if !c.IsRunning() || runs.Load() != int32(cycle+1) {
				t.Fatal("concurrent Starts did not claim exactly one run")
			}
			var stoppers sync.WaitGroup
			for i := 0; i < 16; i++ {
				stoppers.Add(1)
				go func() {
					defer stoppers.Done()
					c.IsRunning()
					if code := c.Stop(false, 1234); code != 0 {
						t.Errorf("Stop = %d", code)
					}
					c.IsRunning()
				}()
			}
			stoppers.Wait()
			starters.Wait()
			if c.IsRunning() || active.Load() != 0 {
				t.Fatal("Stop returned before run completion")
			}
		}
		if pinCalls != 25*16 {
			t.Fatalf("PIN checks = %d, want %d", pinCalls, 25*16)
		}
	})
}

func TestControllerStopWaitsAndTimeoutKeepsGuard(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := NewController(nil)
		release := make(chan struct{})
		var runs int
		stubMobile(t, func(_ *cli.AppConfig, _ *cli.AppCallback, stop chan struct{}) {
			runs++
			<-stop
			<-release
		}, func(int64, chan struct{}) int { t.Error("restart checked PIN"); return 1 })
		started := startController(c)
		synctest.Wait()
		stopped := make(chan struct{})
		before := time.Now()
		go func() {
			var stoppers sync.WaitGroup
			for i := 0; i < 8; i++ {
				stoppers.Add(1)
				go func() { defer stoppers.Done(); c.Stop(true, 0) }()
			}
			stoppers.Wait()
			close(stopped)
		}()
		synctest.Wait()
		select {
		case <-stopped:
			t.Fatal("Stop did not wait for teardown")
		default:
		}
		c.Start("", "", "", "", "", 0, "")
		if !c.IsRunning() || runs != 1 {
			t.Fatal("guard released during teardown")
		}
		<-stopped // synctest advances virtual time, not wall time.
		if elapsed := time.Since(before); elapsed != stopTimeout {
			t.Fatalf("Stop timeout = %v, want %v", elapsed, stopTimeout)
		}
		c.Start("", "", "", "", "", 0, "")
		if !c.IsRunning() || runs != 1 {
			t.Fatal("timeout released a live run's guard")
		}
		close(release)
		<-started
		if c.IsRunning() {
			t.Fatal("completed teardown retained guard")
		}
		started = startController(c)
		synctest.Wait()
		c.Stop(true, 0)
		<-started
		if runs != 2 || c.IsRunning() {
			t.Fatal("could not restart after timed-out teardown completed")
		}
	})
}

func TestControllerPinBehavior(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := NewController(nil)
		var runStop chan struct{}
		var pins []int64
		stubMobile(t, func(_ *cli.AppConfig, _ *cli.AppCallback, stop chan struct{}) {
			runStop = stop
			<-stop
		}, func(pin int64, stop chan struct{}) int {
			pins = append(pins, pin)
			if stop != runStop {
				t.Error("PIN check received wrong run")
			}
			if pin == 1234 {
				return 0
			}
			return 42
		})
		if code := c.Stop(false, 9); code != 42 {
			t.Fatalf("idle Stop PIN result = %d, want 42", code)
		}
		started := startController(c)
		synctest.Wait()
		if code := c.Stop(false, 8); code != 42 || !c.IsRunning() {
			t.Fatalf("invalid PIN Stop = %d, running = %v", code, c.IsRunning())
		}
		select {
		case <-runStop:
			t.Fatal("invalid PIN stopped run")
		default:
		}
		if code := c.Stop(false, 1234); code != 0 {
			t.Fatalf("valid PIN Stop = %d", code)
		}
		<-started
		started = startController(c)
		synctest.Wait()
		c.Stop(true, 9999)
		<-started
		if len(pins) != 3 || pins[0] != 9 || pins[1] != 8 || pins[2] != 1234 {
			t.Fatalf("PIN calls = %v", pins)
		}
	})
}

func TestControllerSlowPinCannotStopReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := NewController(nil)
		pinStarted, releasePin := make(chan struct{}), make(chan struct{})
		var currentStop chan struct{}
		stubMobile(t, func(_ *cli.AppConfig, _ *cli.AppCallback, stop chan struct{}) {
			currentStop = stop
			<-stop
		}, func(_ int64, stop chan struct{}) int {
			if stop != currentStop {
				t.Error("wrong PIN session")
			}
			close(pinStarted)
			<-releasePin
			return 0
		})
		first := startController(c)
		synctest.Wait()
		oldStop := make(chan struct{})
		go func() { c.Stop(false, 1234); close(oldStop) }()
		<-pinStarted
		c.Stop(true, 0)
		<-first
		second := startController(c)
		synctest.Wait()
		close(releasePin)
		<-oldStop
		if !c.IsRunning() {
			t.Fatal("old Stop cleared replacement guard")
		}
		select {
		case <-currentStop:
			t.Fatal("old Stop cancelled replacement")
		default:
		}
		c.Stop(true, 0)
		<-second
	})
}

func TestControllerMixedConcurrentCalls(t *testing.T) {
	c := NewController(nil)
	var active atomic.Int32
	stubMobile(t, func(config *cli.AppConfig, _ *cli.AppCallback, _ chan struct{}) {
		if active.Add(1) != 1 {
			t.Error("overlapping mobile runs")
		}
		defer active.Add(-1)
		runtime.Gosched()
		if config.CdUID != "uid" {
			t.Error("active config changed")
		}
	}, func(int64, chan struct{}) int { return 0 })
	var workers sync.WaitGroup
	for i := 0; i < 12; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				c.Start("uid", "", "", "", "", 0, "")
				c.IsRunning()
				c.Stop(j%2 == 0, 1234)
			}
		}()
	}
	workers.Wait()
	if c.IsRunning() || active.Load() != 0 {
		t.Fatal("concurrent calls left a run active")
	}
}

func TestControllerRunReturnReleasesGuard(t *testing.T) {
	c := NewController(nil)
	var runs int
	stubMobile(t, func(*cli.AppConfig, *cli.AppCallback, chan struct{}) { runs++ }, func(int64, chan struct{}) int { return 0 })
	for i := 0; i < 2; i++ {
		c.Start("", "", "", "", "", 0, "")
		if c.IsRunning() {
			t.Fatal("returned run retained guard")
		}
	}
	if runs != 2 {
		t.Fatalf("runs = %d, want 2", runs)
	}
}
