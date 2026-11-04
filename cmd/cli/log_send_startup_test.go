//go:build darwin || linux

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDelegatedLogValidateEmptySources(t *testing.T) {
	for _, journal := range []bool{false, true} {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("journal=%t/missing=%t", journal, missing), func(t *testing.T) {
				_, c := logSendFixture(t)
				if journal {
					c.sources = append(c.sources, delegatedLogSource{path: filepath.Join(c.tree.root, "journal.log"), budget: 4, backups: 2})
				}
				for _, source := range c.sources {
					writeLogSendFixture(t, source.path, "")
					if missing {
						if err := os.Remove(source.path); err != nil {
							t.Fatal(err)
						}
					}
				}
				if err := c.validate(context.Background()); err != nil {
					t.Fatalf("trusted empty sources prevent startup: %v", err)
				}
				if r, err := c.collect(context.Background()); !errors.Is(err, errLogFileEmpty) {
					if r != nil {
						r.Close()
					}
					t.Fatalf("empty upload error=%v, want %v", err, errLogFileEmpty)
				}
				// Files can gain data after startup without a service restart.
				writeLogSendFixture(t, c.sources[0].path, "new-data")
				want := "new-data"
				if journal {
					want += logWriterLogEndMarker
				}
				if got := readDelegated(t, c); got != want {
					t.Fatalf("upload after append=%q, want %q", got, want)
				}
			})
		}
	}
}
