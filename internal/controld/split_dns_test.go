package controld

import (
	"encoding/json"
	"strings"
	"testing"
)

// The API's utility response carries organization Internal Domains in
// resolver.split_dns. Parsing it must not change anything when the field is
// absent or empty, which is what every resolver without the feature returns.
func TestResolverConfigParsesSplitDNS(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want []SplitDNS
	}{
		{
			name: "absent",
			body: `{"success":true,"body":{"resolver":{"doh":"https://dns.controld.com/abc","uid":"abc"}}}`,
		},
		{
			name: "null",
			body: `{"success":true,"body":{"resolver":{"doh":"https://d","uid":"a","split_dns":null}}}`,
		},
		{
			name: "empty",
			body: `{"success":true,"body":{"resolver":{"doh":"https://d","uid":"a","split_dns":[]}}}`,
			want: []SplitDNS{},
		},
		{
			name: "explicit resolvers",
			body: `{"success":true,"body":{"resolver":{"doh":"https://d","uid":"a","split_dns":[
				{"domain":"aws.example.com","resolvers":["10.0.0.10","10.0.0.11"]}]}}}`,
			want: []SplitDNS{{Domain: "aws.example.com", Resolvers: []string{"10.0.0.10", "10.0.0.11"}}},
		},
		{
			name: "os resolver selection",
			body: `{"success":true,"body":{"resolver":{"doh":"https://d","uid":"a","split_dns":[
				{"domain":"corp.example.com","resolvers":[]},
				{"domain":"lab.example.com"}]}}}`,
			want: []SplitDNS{
				{Domain: "corp.example.com", Resolvers: []string{}},
				{Domain: "lab.example.com"},
			},
		},
		{
			name: "coexists with exclude",
			body: `{"success":true,"body":{"resolver":{"doh":"https://d","uid":"a",
				"exclude":["corp.example.com"],
				"split_dns":[{"domain":"aws.example.com","resolvers":["10.0.0.10"]}]}}}`,
			want: []SplitDNS{{Domain: "aws.example.com", Resolvers: []string{"10.0.0.10"}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var resp utilityResponse
			if err := json.NewDecoder(strings.NewReader(tc.body)).Decode(&resp); err != nil {
				t.Fatal(err)
			}
			got := resp.Body.Resolver.SplitDNS
			if len(got) != len(tc.want) {
				t.Fatalf("split_dns = %+v, want %+v", got, tc.want)
			}
			for i := range got {
				if got[i].Domain != tc.want[i].Domain {
					t.Errorf("[%d].Domain = %q, want %q", i, got[i].Domain, tc.want[i].Domain)
				}
				if len(got[i].Resolvers) != len(tc.want[i].Resolvers) {
					t.Fatalf("[%d].Resolvers = %v, want %v", i, got[i].Resolvers, tc.want[i].Resolvers)
				}
				for j := range got[i].Resolvers {
					if got[i].Resolvers[j] != tc.want[i].Resolvers[j] {
						t.Errorf("[%d].Resolvers[%d] = %q, want %q", i, j, got[i].Resolvers[j], tc.want[i].Resolvers[j])
					}
				}
			}
			// The rest of the model must be unaffected.
			if resp.Body.Resolver.DOH == "" || resp.Body.Resolver.UID == "" {
				t.Errorf("resolver = %+v", resp.Body.Resolver)
			}
		})
	}
}

// An unknown field in an entry must not fail the whole response: the API can
// add one before ctrld knows about it.
func TestResolverConfigToleratesUnknownSplitDNSFields(t *testing.T) {
	body := `{"success":true,"body":{"resolver":{"doh":"https://d","uid":"a","split_dns":[
		{"domain":"aws.example.com","resolvers":["10.0.0.10"],"future_field":{"a":1}}]}}}`
	var resp utilityResponse
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Body.Resolver.SplitDNS) != 1 || resp.Body.Resolver.SplitDNS[0].Domain != "aws.example.com" {
		t.Fatalf("split_dns = %+v", resp.Body.Resolver.SplitDNS)
	}
}

// The shape the API actually returns, mode field included.
func TestResolverConfigParsesSplitDNSMode(t *testing.T) {
	const body = `{
  "success": true,
  "body": {
    "resolver": {
      "split_dns": [
        {
          "domain": "corp.example.com",
          "mode": "resolvers",
          "resolvers": ["10.0.0.53", "10.0.0.54"]
        },
        {
          "domain": "office.example.com",
          "mode": "os",
          "resolvers": []
        }
      ]
    }
  }
}`
	var resp utilityResponse
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	got := resp.Body.Resolver.SplitDNS
	if len(got) != 2 {
		t.Fatalf("split_dns = %+v", got)
	}
	if got[0].Domain != "corp.example.com" || got[0].Mode != SplitDNSModeResolvers {
		t.Errorf("[0] = %+v", got[0])
	}
	if len(got[0].Resolvers) != 2 || got[0].Resolvers[0] != "10.0.0.53" || got[0].Resolvers[1] != "10.0.0.54" {
		t.Errorf("[0].Resolvers = %v", got[0].Resolvers)
	}
	if got[1].Domain != "office.example.com" || got[1].Mode != SplitDNSModeOS {
		t.Errorf("[1] = %+v", got[1])
	}
	if len(got[1].Resolvers) != 0 {
		t.Errorf("[1].Resolvers = %v, want empty", got[1].Resolvers)
	}
}

// A response without the field must still decode, so a deployment that predates
// mode keeps working.
func TestResolverConfigToleratesAbsentSplitDNSMode(t *testing.T) {
	const body = `{"success":true,"body":{"resolver":{"split_dns":[
		{"domain":"corp.example.com","resolvers":["10.0.0.53"]}]}}}`
	var resp utilityResponse
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if got := resp.Body.Resolver.SplitDNS; len(got) != 1 || got[0].Mode != "" {
		t.Fatalf("split_dns = %+v", got)
	}
}
