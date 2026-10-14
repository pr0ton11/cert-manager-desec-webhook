package solver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/nrdcg/desec"
)

// Tests if the Subdomain FQDN replacement logic works
func TestPresentSubdomainFromFQDN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		fqdn     string
		zone     string
		expected string
	}{
		{
			name:     "acme challenge subdomain",
			fqdn:     "_acme-challenge.example.com.",
			zone:     "example.com.",
			expected: "_acme-challenge",
		},
		{
			name:     "root record",
			fqdn:     "example.com.",
			zone:     "example.com.",
			expected: "",
		},
		{
			name:     "multi-label subdomain",
			fqdn:     "_acme-challenge.foo.example.com.",
			zone:     "example.com.",
			expected: "_acme-challenge.foo",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			zone := util.UnFqdn(test.zone)
			fqdn := util.UnFqdn(test.fqdn)
			subdomain := util.UnFqdn(strings.Replace(fqdn, zone, "", 1))

			if subdomain != test.expected {
				t.Fatalf("unexpected subdomain: got %q want %q", subdomain, test.expected)
			}
		})
	}
}

func TestAppendMissingRecords(t *testing.T) {
	t.Parallel()

	existing := []string{`"token-a"`, `"token-b"`}
	records, changed := appendMissingRecords(existing, []string{`"token-b"`, `"token-c"`})

	if !changed {
		t.Fatal("expected records to change")
	}
	if !slices.Equal(records, []string{`"token-a"`, `"token-b"`, `"token-c"`}) {
		t.Fatalf("unexpected records: got %v", records)
	}
	if !slices.Equal(existing, []string{`"token-a"`, `"token-b"`}) {
		t.Fatalf("existing records were mutated: got %v", existing)
	}
}

func TestAppendMissingRecordsNoChange(t *testing.T) {
	t.Parallel()

	records, changed := appendMissingRecords([]string{`"token-a"`}, []string{`"token-a"`})

	if changed {
		t.Fatal("expected records to be unchanged")
	}
	if !slices.Equal(records, []string{`"token-a"`}) {
		t.Fatalf("unexpected records: got %v", records)
	}
}

func TestRemoveRecord(t *testing.T) {
	t.Parallel()

	existing := []string{`"token-a"`, `"token-b"`, `"token-c"`}
	records, changed := removeRecord(existing, `"token-b"`)

	if !changed {
		t.Fatal("expected records to change")
	}
	if !slices.Equal(records, []string{`"token-a"`, `"token-c"`}) {
		t.Fatalf("unexpected records: got %v", records)
	}
}

func TestRemoveRecordNoChange(t *testing.T) {
	t.Parallel()

	records, changed := removeRecord([]string{`"token-a"`}, `"token-b"`)

	if changed {
		t.Fatal("expected records to be unchanged")
	}
	if !slices.Equal(records, []string{`"token-a"`}) {
		t.Fatalf("unexpected records: got %v", records)
	}
}

// TestTXTRecordUpdates exercises deSEC's write-once fields and token preservation.
func TestTXTRecordUpdates(t *testing.T) {
	for _, test := range []struct {
		name    string
		initial []string
		want    []string
		cleanup bool
	}{
		{"present preserves another token", []string{`"other"`}, []string{`"other"`, `"token"`}, false},
		{"cleanup preserves another token", []string{`"other"`, `"token"`}, []string{`"other"`}, true},
		{"cleanup deletes last token", []string{`"token"`}, []string{}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			records := slices.Clone(test.initial)
			writes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path != "/domains/example.com/rrsets/_acme-challenge/TXT/" {
					t.Errorf("unexpected path: %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				if r.Method != http.MethodGet {
					var body map[string]json.RawMessage
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if _, exists := body["subname"]; r.Method == http.MethodPatch && exists {
						w.WriteHeader(http.StatusBadRequest)
						_, _ = io.WriteString(w, `{"subname":["Can only be written on create."]}`)
						return
					}
					if r.Method != http.MethodPut || string(body["subname"]) != `"_acme-challenge"` || string(body["type"]) != `"TXT"` || string(body["ttl"]) != "3600" {
						t.Errorf("invalid replacement: method=%s body=%s", r.Method, body)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if err := json.Unmarshal(body["records"], &records); err != nil || records == nil {
						t.Errorf("invalid records: %s, error: %v", body["records"], err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					writes++
					if len(records) == 0 {
						w.WriteHeader(http.StatusNoContent)
						return
					}
				}
				_ = json.NewEncoder(w).Encode(desec.RRSet{SubName: "_acme-challenge", Type: "TXT", TTL: 3600, Records: records})
			}))
			defer server.Close()
			opts := desec.NewDefaultClientOptions()
			opts.HTTPClient = server.Client()
			client := desec.New("test-token", opts)
			client.BaseURL = server.URL
			var err error
			if test.cleanup {
				err = removeTXTRecord(context.Background(), client, "example.com", "_acme-challenge", `"token"`)
			} else {
				err = upsertTXTRecord(context.Background(), client, desec.RRSet{Domain: "example.com", SubName: "_acme-challenge", Type: "TXT", TTL: 3600, Records: []string{`"token"`}})
			}
			if err != nil {
				t.Fatal(err)
			}
			if writes != 1 || !slices.Equal(records, test.want) {
				t.Fatalf("writes=%d records=%v, want one write with %v", writes, records, test.want)
			}
		})
	}
}
