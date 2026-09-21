package cli

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"
)

// pfStateReadTimeout bounds each state read. These reads run on the network change
// path, so a pfctl that waits on a busy kernel lock must not hold it.
const pfStateReadTimeout = 3 * time.Second

// pfStateReadMaxBytes bounds the output of one state read. A ruleset or an
// interface dump of this size is not the state ctrld reads, and these reads run
// on the network change path.
const pfStateReadMaxBytes = 1 << 20

// errPFStateOutputTooLarge marks output that passed the bound. The bytes kept
// are a prefix of the real output, so the caller must not parse them.
var errPFStateOutputTooLarge = errors.New("pf state output passed its bound")

// boundedBuffer keeps at most limit bytes and remembers that it dropped the
// rest.
type boundedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	room := b.limit - b.Len()
	if len(p) > room {
		b.exceeded = true
		p = p[:max(room, 0)]
	}
	if _, err := b.Buffer.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// pfStateRunCommand runs one read-only state command. A var so tests replace it
// instead of shelling out.
var pfStateRunCommand = func(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pfStateReadTimeout)
	defer cancel()
	out := &boundedBuffer{limit: pfStateReadMaxBytes}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = out
	cmd.Stderr = out
	err := cmd.Run()
	if out.exceeded {
		return nil, errPFStateOutputTooLarge
	}
	return out.Bytes(), err
}

// pfRuleDump carries pfctl rule output that the caller already read. A nil
// field means that the caller holds no bytes for that flag, so the read runs
// here.
type pfRuleDump struct {
	rules []byte // "pfctl -sr"
	nat   []byte // "pfctl -sn"
}

// pfAnchorNames returns the anchor names of the running ruleset. A failed read
// gives no names, because a partial list reads as an anchor that went away.
func (p *prog) pfAnchorNames(dump pfRuleDump) []string {
	rules, ok := p.pfRuleBytes(dump.rules, "-sr", "list filter anchors")
	if !ok {
		return nil
	}
	nat, ok := p.pfRuleBytes(dump.nat, "-sn", "list translation anchors")
	if !ok {
		return nil
	}
	return parsePFAnchorNames(bytes.NewReader(rules), bytes.NewReader(nat))
}

// pfRuleBytes returns the rule output of one pfctl flag. It starts pfctl only
// when the caller holds no bytes, and a failed read feeds the backoff that
// keeps ctrld off an exhausted host.
func (p *prog) pfRuleBytes(held []byte, flag, operation string) ([]byte, bool) {
	if held != nil {
		return held, true
	}
	out, err := pfStateRunCommand("pfctl", flag)
	if err != nil {
		p.pfBackoffResourceExhaustion(err, out, operation)
		return nil, false
	}
	return out, true
}

// pfStatus reports whether pf runs and for how long. A failed read gives false
// and "".
func (p *prog) pfStatus() (bool, string) {
	out, err := pfStateRunCommand("pfctl", "-si")
	if err != nil {
		p.pfBackoffResourceExhaustion(err, out, "read pf status")
		return false, ""
	}
	return parsePFStatus(bytes.NewReader(out))
}

// tunnelOwner returns the network extension that owns a tunnel interface, or ""
// when the read fails or no extension owns it.
func tunnelOwner(iface string) string {
	if iface == "" {
		return ""
	}
	out, err := pfStateRunCommand("ifconfig", "-v", iface)
	if err != nil {
		return ""
	}
	return parseIfconfigAgent(bytes.NewReader(out))
}
