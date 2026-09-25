//go:build windows

package cli

import "testing"

func TestBinaryPathArgumentPresent(t *testing.T) {
	path := `C:\ControlD\ctrld.exe run --config=C:\Users\officer\ctrld.toml --intercept-mode=dns`
	if !binaryPathArgumentPresent(path, "--intercept-mode=dns") {
		t.Fatal("exact inline argument was not found")
	}
	if binaryPathArgumentPresent(path, "--intercept-mode") {
		t.Fatal("inline flag was mistaken for a separate flag argument")
	}
	if binaryPathArgumentPresent(path, "off") {
		t.Fatal("substring in an unrelated path was mistaken for the off argument")
	}
}

func TestRemoveBinaryPathFlag(t *testing.T) {
	tests := []struct {
		name        string
		binaryPath  string
		wantPath    string
		wantRemoved bool
	}{
		{
			name:        "split form",
			binaryPath:  `ctrld.exe run --cd=uid --intercept-mode dns --config=ctrld.toml`,
			wantPath:    `ctrld.exe run --cd=uid --config=ctrld.toml`,
			wantRemoved: true,
		},
		{
			name:        "inline form",
			binaryPath:  `ctrld.exe run --cd=uid --intercept-mode=dns --config=ctrld.toml`,
			wantPath:    `ctrld.exe run --cd=uid --config=ctrld.toml`,
			wantRemoved: true,
		},
		{
			name:       "absent",
			binaryPath: `ctrld.exe run --cd=uid`,
			wantPath:   `ctrld.exe run --cd=uid`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path, removed := removeBinaryPathFlag(tc.binaryPath, "--intercept-mode")
			if path != tc.wantPath || removed != tc.wantRemoved {
				t.Fatalf("removeBinaryPathFlag() = (%q, %v), want (%q, %v)", path, removed, tc.wantPath, tc.wantRemoved)
			}
		})
	}
}
