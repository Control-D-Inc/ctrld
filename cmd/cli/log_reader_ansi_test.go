package cli

import (
	"io"
	"strings"
	"testing"
)

// splitReader yields its text in the pieces that the test names, one piece
// for each Read, so a test puts a chunk boundary where it wants one.
type splitReader struct {
	pieces []string
}

func (r *splitReader) Read(p []byte) (int, error) {
	if len(r.pieces) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.pieces[0])
	if n < len(r.pieces[0]) {
		r.pieces[0] = r.pieces[0][n:]
	} else {
		r.pieces = r.pieces[1:]
	}
	return n, nil
}

func Test_ansiStripReader_stripsSequencesSplitAcrossReads(t *testing.T) {
	const red, reset = "\x1b[31m", "\x1b[0m"
	for _, tc := range []struct {
		name   string
		pieces []string
		want   string
	}{
		{"one read", []string{"a " + red + "b" + reset + " c"}, "a b c"},
		{"split after the escape byte", []string{"a \x1b", "[31mb" + reset}, "a b"},
		{"split after the bracket", []string{"a \x1b[", "31mb"}, "a b"},
		{"split inside the parameters", []string{"a \x1b[3", "1mb"}, "a b"},
		{"split before the final byte", []string{"a \x1b[31", "mb"}, "a b"},
		{"two sequences in a row across a read", []string{"a " + red + "\x1b[", "1mb"}, "a b"},
		{"sequence open at the end of the source", []string{"a \x1b[31"}, "a \x1b[31"},
		{"lone escape at the end of the source", []string{"a \x1b"}, "a \x1b"},
		{"escape that starts no color sequence", []string{"a \x1bXb"}, "a \x1bXb"},
		{"letters inside the parameters stay", []string{"a \x1b[inva", "lidm b"}, "a \x1b[invalidm b"},
		{"empty source", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := io.ReadAll(newANSIStripReader(&splitReader{pieces: tc.pieces}))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func Test_ansiStripReader_holdsALongTailAcrossTheChunkSize(t *testing.T) {
	// The escape byte lands as the last byte of one chunk.
	head := strings.Repeat("x", ansiStripChunkSize-1)
	got, err := io.ReadAll(newANSIStripReader(&splitReader{pieces: []string{head + "\x1b", "[32my"}}))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != head+"y" {
		t.Fatalf("got %d bytes ending in %q, want the text without the color", len(got), got[len(got)-4:])
	}
}
