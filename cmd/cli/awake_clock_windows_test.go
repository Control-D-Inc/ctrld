package cli

import "testing"

// The sleep check needs the unbiased interrupt time: the fallback clock keeps
// running while Windows sleeps, so the check would never find a sleep.
func TestUnbiasedInterruptTimeAvailable(t *testing.T) {
	if _, ok := unbiasedInterruptTime(); !ok {
		t.Fatal("QueryUnbiasedInterruptTime failed")
	}
}
