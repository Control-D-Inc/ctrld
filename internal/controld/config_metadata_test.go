package controld

import "testing"

func TestResolverConfigUtilityRequestMetadataScope(t *testing.T) {
	oldHostnameHints := hostnameHintsFn
	t.Cleanup(func() { hostnameHintsFn = oldHostnameHints })
	hostnameHintsFn = func() map[string]string {
		return map[string]string{"ComputerName": "workstation"}
	}

	baseMetadata := map[string]string{"os": "test-os", "username": "test-user"}
	full := resolverConfigUtilityRequest(&ResolverConfigRequest{
		Metadata:             baseMetadata,
		IncludeHostnameHints: true,
	}, "uid", "client")
	if got := full.Metadata["hostname_ComputerName"]; got != "workstation" {
		t.Errorf("full metadata hostname hint = %q, want workstation", got)
	}
	if got := full.Metadata["username"]; got != "test-user" {
		t.Errorf("full metadata username = %q, want test-user", got)
	}
	if _, ok := baseMetadata["hostname_ComputerName"]; ok {
		t.Error("building the utility request mutated the caller metadata")
	}

	runtime := resolverConfigUtilityRequest(&ResolverConfigRequest{
		Metadata: map[string]string{"os": "test-os"},
	}, "uid", "")
	if _, ok := runtime.Metadata["hostname_ComputerName"]; ok {
		t.Error("runtime metadata included hostname hints")
	}
	if _, ok := runtime.Metadata["username"]; ok {
		t.Error("runtime metadata included username")
	}

	empty := resolverConfigUtilityRequest(&ResolverConfigRequest{}, "uid", "")
	if empty.Metadata != nil {
		t.Error("request without metadata changed from null to an observed empty object")
	}
}
