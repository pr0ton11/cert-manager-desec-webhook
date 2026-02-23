package solver_test

import (
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
