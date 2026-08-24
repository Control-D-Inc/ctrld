package cli

import "testing"

// TestServiceBinaryFromImagePath covers the ImagePath shapes Windows stores. Getting this
// wrong makes readinessVerifiable compare the wrong directories, and "ctrld status" would
// then report a healthy service as not-ready - the false positive the readiness exit code
// exists to avoid.
func TestServiceBinaryFromImagePath(t *testing.T) {
	tests := []struct {
		name      string
		imagePath string
		want      string
	}{
		{
			// The installed form: quoted because the directory contains a space, with the
			// service arguments following it.
			name:      "quoted path with arguments",
			imagePath: `"C:\Program Files\Control D\ctrld.exe" run --config "C:\ProgramData\Control D\ctrld.toml"`,
			want:      `C:\Program Files\Control D\ctrld.exe`,
		},
		{
			name:      "quoted path without arguments",
			imagePath: `"C:\Program Files\Control D\ctrld.exe"`,
			want:      `C:\Program Files\Control D\ctrld.exe`,
		},
		{
			name:      "unquoted path with arguments",
			imagePath: `C:\ctrld\ctrld.exe run --cd abc123`,
			want:      `C:\ctrld\ctrld.exe`,
		},
		{
			name:      "unquoted path alone",
			imagePath: `C:\ctrld\ctrld.exe`,
			want:      `C:\ctrld\ctrld.exe`,
		},
		{
			name:      "surrounding whitespace",
			imagePath: `   "C:\ctrld\ctrld.exe" run   `,
			want:      `C:\ctrld\ctrld.exe`,
		},
		{
			// Unterminated quote: take what is there rather than returning nothing, since
			// "" means "cannot tell" and would silently disable the check.
			name:      "unterminated quote",
			imagePath: `"C:\ctrld\ctrld.exe run`,
			want:      `C:\ctrld\ctrld.exe run`,
		},
		{
			name:      "empty",
			imagePath: "",
			want:      "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := serviceBinaryFromImagePath(tc.imagePath); got != tc.want {
				t.Errorf("serviceBinaryFromImagePath(%q) = %q, want %q", tc.imagePath, got, tc.want)
			}
		})
	}
}

// TestSameExecutableDir pins the comparison itself: Windows paths are case-insensitive, and
// an empty side means "cannot tell", which must never read as a match.
func TestSameExecutableDir(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{
			name: "same directory",
			a:    `C:\Program Files\Control D\ctrld.exe`,
			b:    `C:\Program Files\Control D\ctrld.exe`,
			want: true,
		},
		{
			name: "same directory different case",
			a:    `C:\Program Files\Control D\ctrld.exe`,
			b:    `c:\program files\control d\ctrld.exe`,
			want: true,
		},
		{
			// The case the check exists for: a copy run from a download directory
			// resolves a different control socket than the installed service.
			name: "different directory",
			a:    `C:\Program Files\Control D\ctrld.exe`,
			b:    `C:\Users\admin\Downloads\ctrld.exe`,
			want: false,
		},
		{name: "unknown installed path", a: "", b: `C:\ctrld\ctrld.exe`, want: false},
		{name: "unknown self path", a: `C:\ctrld\ctrld.exe`, b: "", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameExecutableDir(tc.a, tc.b); got != tc.want {
				t.Errorf("sameExecutableDir(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
