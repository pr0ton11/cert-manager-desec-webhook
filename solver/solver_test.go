package solver

import (
	"slices"
	"strings"
	"testing"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
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
