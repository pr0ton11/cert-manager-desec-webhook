package solver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/nrdcg/desec"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

const txtRecordType = "TXT"

// Configuration for the DeSEC DNS-01 challenge solver
type DeSECDNSProviderSolverConfig struct {
	// Reference to the kubernetes secret containing the API token for deSEC
	APIKeySecretRef v1.SecretKeySelector `json:"apiKeySecretRef"`
	// A global namespace (e.g APIKeySecretRefNamespace is not required, because ClusterIssuer provides the cert-manager namespace as default value for global issuers)
}

// A DNS-01 challenge solver for the DeSEC DNS Provider
type DeSECDNSProviderSolver struct {
	// Client to communicate with the kubernetes API
	k8s *kubernetes.Clientset
}

// Returns the name of the DNS solver
func (s *DeSECDNSProviderSolver) Name() string {
	return "desec"
}

// Initializes a new client
func (s *DeSECDNSProviderSolver) getClient(config *apiextensionsv1.JSON, namespace string) (*desec.Client, error) {
	// Check if configuration is empty or was not parsed
	if config == nil {
		return nil, fmt.Errorf("missing configuration in issuer found; webhook configuration requires apiKeySecretRef containing deSEC API token")
	}
	// Initialize the configuration object and unmarshal json
	solverConfig := DeSECDNSProviderSolverConfig{}
	if err := json.Unmarshal(config.Raw, &solverConfig); err != nil {
		return nil, fmt.Errorf("invalid configuration in issuer found; webhook configuration requires apiKeySecretRef containing deSEC API token")
	}
	// Check if the k8s client has been initialized
	// This should never happen as cert-manager calls s.Initialize() which assigns the k8s client
	if s.k8s == nil {
		return nil, fmt.Errorf("k8s client has not been initialized by cert-manager; this should never happen")
	}
	// Read the secret from k8s
	secret, err := s.k8s.CoreV1().Secrets(namespace).Get(context.Background(), solverConfig.APIKeySecretRef.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("k8s secret %s not found in namespace %s", solverConfig.APIKeySecretRef.Name, namespace)
	}
	token, ok := secret.Data[solverConfig.APIKeySecretRef.Key]
	if !ok {
		return nil, fmt.Errorf("k8s secret key %s not found in secret %s in namespace %s", solverConfig.APIKeySecretRef.Key, solverConfig.APIKeySecretRef.Name, namespace)
	}
	// Finally assign the client
	client := desec.New(string(token), desec.NewDefaultClientOptions())
	klog.InfoS("deSEC client configured", "component", "desec-solver", "event", "client_ready", "namespace", namespace, "secretName", solverConfig.APIKeySecretRef.Name, "secretKey", solverConfig.APIKeySecretRef.Key)

	// Return the client (reuse if initialized)
	return client, nil
}

// Present presents the TXT DNS entry after completion of the ACME DNS-01 challenge
func (s *DeSECDNSProviderSolver) Present(req *acme.ChallengeRequest) error {
	// Create or reuse the API client
	apiClient, err := s.getClient(req.Config, req.ResourceNamespace)
	if err != nil {
		return err
	}
	zone := util.UnFqdn(req.ResolvedZone)
	fqdn := util.UnFqdn(req.ResolvedFQDN)
	// Cut the zone from the fqdn to retrieve the subdomain
	subdomain := util.UnFqdn(strings.Replace(fqdn, zone, "", 1))
	// Check if zone is managed in deSEC
	domain, err := apiClient.Domains.Get(context.Background(), zone)
	if err != nil {
		return fmt.Errorf("domain %s could not be retrieved from deSEC API: %w", zone, err)
	}
	recordSet := desec.RRSet{
		Domain:  domain.Name,
		SubName: subdomain,
		Records: []string{fmt.Sprintf("\"%s\"", req.Key)},
		Type:    txtRecordType,
		TTL:     3600,
	}

	if err := upsertTXTRecord(context.Background(), apiClient, recordSet); err != nil {
		return fmt.Errorf("DNS record %s presentation failed: %w", fqdn, err)
	}
	klog.InfoS("DNS record presented", "component", "desec-solver", "event", "record_presented", "namespace", req.ResourceNamespace, "zone", zone, "fqdn", fqdn, "subdomain", subdomain, "ttl", recordSet.TTL)
	// Return no error
	return nil
}

// Cleanup removes the TXT DNS entry after completion of the ACME DNS-01 challenge
func (s *DeSECDNSProviderSolver) CleanUp(req *acme.ChallengeRequest) error {
	// Create or reuse the API client
	apiClient, err := s.getClient(req.Config, req.ResourceNamespace)
	if err != nil {
		return err
	}
	zone := util.UnFqdn(req.ResolvedZone)
	fqdn := util.UnFqdn(req.ResolvedFQDN)
	// Cut the zone from the fqdn to retrieve the subdomain
	subdomain := util.UnFqdn(strings.Replace(fqdn, zone, "", 1))
	// Check if zone is managed in deSEC
	domain, err := apiClient.Domains.Get(context.Background(), zone)
	if err != nil {
		return fmt.Errorf("domain %s could not be retrieved from deSEC API: %w", zone, err)
	}
	record := fmt.Sprintf("\"%s\"", req.Key)
	if err := removeTXTRecord(context.Background(), apiClient, domain.Name, subdomain, record); err != nil {
		return fmt.Errorf("DNS record %s cleanup failed: %w", fqdn, err)
	}
	klog.InfoS("DNS record cleaned up", "component", "desec-solver", "event", "record_deleted", "namespace", req.ResourceNamespace, "zone", zone, "fqdn", fqdn, "subdomain", subdomain)
	// Return no error
	return nil
}

func upsertTXTRecord(ctx context.Context, apiClient *desec.Client, recordSet desec.RRSet) error {
	existing, err := apiClient.Records.Get(ctx, recordSet.Domain, recordSet.SubName, txtRecordType)
	if isNotFound(err) {
		_, err = apiClient.Records.Create(ctx, recordSet)
		if err == nil {
			return nil
		}
		if !isAlreadyExists(err) {
			return fmt.Errorf("create TXT RRset failed: %w", err)
		}

		existing, err = apiClient.Records.Get(ctx, recordSet.Domain, recordSet.SubName, txtRecordType)
	}
	if err != nil {
		return fmt.Errorf("get TXT RRset failed: %w", err)
	}

	records, changed := appendMissingRecords(existing.Records, recordSet.Records)
	if !changed {
		return nil
	}

	_, err = apiClient.Records.Update(ctx, recordSet.Domain, recordSet.SubName, txtRecordType, desec.RRSet{
		Records: records,
		TTL:     recordSet.TTL,
	})
	if err != nil {
		return fmt.Errorf("update TXT RRset failed: %w", err)
	}

	return nil
}

func removeTXTRecord(ctx context.Context, apiClient *desec.Client, domain, subdomain, record string) error {
	existing, err := apiClient.Records.Get(ctx, domain, subdomain, txtRecordType)
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get TXT RRset failed: %w", err)
	}

	records, changed := removeRecord(existing.Records, record)
	if !changed {
		return nil
	}

	_, err = apiClient.Records.Update(ctx, domain, subdomain, txtRecordType, desec.RRSet{
		Records: records,
		TTL:     existing.TTL,
	})
	if err != nil {
		return fmt.Errorf("update TXT RRset failed: %w", err)
	}

	return nil
}

func appendMissingRecords(existing, additions []string) ([]string, bool) {
	records := append([]string(nil), existing...)
	seen := make(map[string]struct{}, len(existing))
	for _, record := range existing {
		seen[record] = struct{}{}
	}

	changed := false
	for _, record := range additions {
		if _, ok := seen[record]; ok {
			continue
		}
		records = append(records, record)
		seen[record] = struct{}{}
		changed = true
	}

	return records, changed
}

func removeRecord(existing []string, removed string) ([]string, bool) {
	records := make([]string, 0, len(existing))
	changed := false

	for _, record := range existing {
		if record == removed {
			changed = true
			continue
		}
		records = append(records, record)
	}

	return records, changed
}

func isNotFound(err error) bool {
	var notFound *desec.NotFoundError
	return errors.As(err, &notFound)
}

func isAlreadyExists(err error) bool {
	var apiError *desec.APIError
	return errors.As(err, &apiError) && apiError.StatusCode == 400 && strings.Contains(err.Error(), "Another RRset with the same subdomain and type exists")
}

// Initializes the solver
func (s *DeSECDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	// Create the k8s client
	k8s, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	// Assign the k8s client to the solver
	s.k8s = k8s
	klog.InfoS("solver initialized", "component", "desec-solver", "event", "initialized")
	// Return no error
	return nil
}
