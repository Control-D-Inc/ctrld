package cli

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procQueryUnbiasedInterruptTime = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryUnbiasedInterruptTime")

var awakeClockBase = time.Now()

// awakeClock returns how long the host has been awake, from the unbiased
// interrupt time, which stops while Windows sleeps. Go's monotonic clock reads
// the interrupt time, which does not (golang/go#35482). If the call fails, it
// falls back to that clock, and the sleep check then finds no sleep.
func awakeClock() time.Duration {
	if d, ok := unbiasedInterruptTime(); ok {
		return d
	}
	return time.Since(awakeClockBase)
}

// unbiasedInterruptTime returns the time Windows has been awake since boot.
func unbiasedInterruptTime() (time.Duration, bool) {
	var t uint64 // 100 ns units
	if err := procQueryUnbiasedInterruptTime.Find(); err != nil {
		return 0, false
	}
	if r, _, _ := procQueryUnbiasedInterruptTime.Call(uintptr(unsafe.Pointer(&t))); r == 0 {
		return 0, false
	}
	return time.Duration(t) * 100, true
}
