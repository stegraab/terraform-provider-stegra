package provider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	stepToken "github.com/smallstep/cli-utils/token"
	stepProvision "github.com/smallstep/cli-utils/token/provision"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/randutil"
)

const stepAdminIssuer = "step-admin-client/1.0"

type apiClient struct {
	machineEnrollmentURL   string
	machineEnrollmentToken string
	stepCAURL              string
	adminProvisioner       string
	adminSubject           string
	adminPassword          string
	insecureSkipVerify     bool
	httpClient             *http.Client

	mu                sync.Mutex
	adminSigner       crypto.Signer
	adminSignerAlg    string
	adminX5CCertChain []string
	adminCertExpiry   time.Time
}

type machineEnrollment struct {
	ID               string            `json:"id,omitempty"`
	AttestorType     string            `json:"attestor_type"`
	AttestorIdentity string            `json:"attestor_identity"`
	AttestorClaims   map[string]string `json:"attestor_claims"`
	MachineIdentity  string            `json:"machine_identity"`
	SSHPrincipals    []string          `json:"ssh_principals"`
	Status           string            `json:"status,omitempty"`
}

type apiStatusError struct {
	StatusCode int
	Body       string
}

func (e *apiStatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("API request failed with status %d", e.StatusCode)
	}
	return fmt.Sprintf("API request failed with status %d: %s", e.StatusCode, e.Body)
}

func (c *apiClient) createMachineEnrollment(ctx context.Context, input machineEnrollment) (machineEnrollment, error) {
	// ID and status are server-owned lifecycle fields. Clearing them here keeps
	// the API boundary safe even if a future caller reuses a populated object.
	input.ID = ""
	input.Status = ""
	return c.requestMachineEnrollment(ctx, http.MethodPost, "/v1/machine-enrollments", input)
}

func (c *apiClient) getMachineEnrollment(ctx context.Context, id string) (machineEnrollment, bool, error) {
	registration, err := c.requestMachineEnrollment(ctx, http.MethodGet, "/v1/machine-enrollments/"+url.PathEscape(id), nil)
	var statusError *apiStatusError
	if errors.As(err, &statusError) && statusError.StatusCode == http.StatusNotFound {
		return machineEnrollment{}, false, nil
	}
	return registration, err == nil, err
}

func (c *apiClient) revokeMachineEnrollment(ctx context.Context, id string) error {
	_, err := c.requestMachineEnrollment(ctx, http.MethodDelete, "/v1/machine-enrollments/"+url.PathEscape(id), nil)
	var statusError *apiStatusError
	if errors.As(err, &statusError) && statusError.StatusCode == http.StatusNotFound {
		return nil
	}
	return err
}

func (c *apiClient) requestMachineEnrollment(ctx context.Context, method string, path string, payload any) (machineEnrollment, error) {
	authorization, err := c.machineEnrollmentAuthorization(ctx)
	if err != nil {
		return machineEnrollment{}, err
	}
	body, err := c.request(ctx, method, c.machineEnrollmentURL+path, payload, authorization)
	if err != nil {
		return machineEnrollment{}, err
	}
	if len(body) == 0 {
		return machineEnrollment{}, nil
	}
	var registration machineEnrollment
	if err := json.Unmarshal(body, &registration); err != nil {
		return machineEnrollment{}, fmt.Errorf("decode machine enrollment response: %w", err)
	}
	return registration, nil
}

func (c *apiClient) validateTransport() error {
	enrollmentEndpoint, err := parseHTTPURL(c.machineEnrollmentURL)
	if err != nil {
		return fmt.Errorf("machine enrollment URL: %w", err)
	}
	if c.machineEnrollmentToken != "" {
		return nil
	}
	if enrollmentEndpoint.Scheme != "https" {
		return errors.New("production machine enrollment requires HTTPS")
	}
	stepEndpoint, err := parseHTTPURL(c.stepCAURL)
	if err != nil {
		return fmt.Errorf("Step CA URL: %w", err)
	}
	if stepEndpoint.Scheme != "https" {
		return errors.New("production Step CA authentication requires HTTPS")
	}
	if c.insecureSkipVerify {
		return errors.New("production machine enrollment requires TLS certificate verification")
	}
	return nil
}

func parseHTTPURL(raw string) (*url.URL, error) {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "https" && endpoint.Scheme != "http") {
		return nil, errors.New("must be an absolute HTTP(S) URL")
	}
	return endpoint, nil
}

func (c *apiClient) machineEnrollmentAuthorization(ctx context.Context) (string, error) {
	if c.machineEnrollmentToken != "" {
		return c.machineEnrollmentToken, nil
	}
	if err := c.ensureAdminIdentity(ctx); err != nil {
		return "", err
	}
	return c.generateAdminJWT(c.stepCAURL + "/admin/admins")
}

func (c *apiClient) request(ctx context.Context, method string, endpoint string, payload any, authorization string) ([]byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("encode request body: %w", err)
		}
		bodyReader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("perform request: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, &apiStatusError{StatusCode: response.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	return body, nil
}

func (c *apiClient) requestStepCA(ctx context.Context, method string, path string, payload any) ([]byte, error) {
	return c.request(ctx, method, c.stepCAURL+path, payload, "")
}

func (c *apiClient) ensureAdminIdentity(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.adminSigner != nil && time.Until(c.adminCertExpiry) > 5*time.Minute {
		return nil
	}
	kid, err := c.lookupProvisionerKID(ctx)
	if err != nil {
		return err
	}
	encryptedKey, err := c.getEncryptedProvisionerKey(ctx, kid)
	if err != nil {
		return err
	}
	jwk, err := decryptProvisionerJWK(encryptedKey, c.adminPassword)
	if err != nil {
		return err
	}
	provisioningToken, err := c.generateProvisionerSignToken(jwk, kid)
	if err != nil {
		return err
	}
	adminKey, csr, err := generateAdminCSR(c.adminSubject)
	if err != nil {
		return err
	}
	signResponse, err := c.signAdminCSR(ctx, csr, provisioningToken)
	if err != nil {
		return err
	}
	certificateChain, expiry, err := parseCertificateChain(signResponse)
	if err != nil {
		return err
	}
	algorithm, err := signingAlgorithmForKey(adminKey)
	if err != nil {
		return err
	}
	c.adminSigner = adminKey
	c.adminSignerAlg = algorithm
	c.adminX5CCertChain = certificateChain
	c.adminCertExpiry = expiry
	return nil
}

func (c *apiClient) lookupProvisionerKID(ctx context.Context) (string, error) {
	body, err := c.requestStepCA(ctx, http.MethodGet, "/provisioners", nil)
	if err != nil {
		return "", fmt.Errorf("list Step CA provisioners: %w", err)
	}
	var response struct {
		Provisioners []map[string]any `json:"provisioners"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("decode Step CA provisioners: %w", err)
	}
	for _, provisioner := range response.Provisioners {
		name, _ := provisioner["name"].(string)
		provisionerType, _ := provisioner["type"].(string)
		if name != c.adminProvisioner || !strings.EqualFold(provisionerType, "JWK") {
			continue
		}
		key, ok := provisioner["key"].(map[string]any)
		if !ok {
			return "", fmt.Errorf("Step CA provisioner %q is missing key metadata", c.adminProvisioner)
		}
		kid, _ := key["kid"].(string)
		if strings.TrimSpace(kid) == "" {
			return "", fmt.Errorf("Step CA provisioner %q is missing its key ID", c.adminProvisioner)
		}
		return kid, nil
	}
	return "", fmt.Errorf("Step CA JWK provisioner %q was not found", c.adminProvisioner)
}

func (c *apiClient) getEncryptedProvisionerKey(ctx context.Context, kid string) (string, error) {
	body, err := c.requestStepCA(ctx, http.MethodGet, "/provisioners/"+url.PathEscape(kid)+"/encrypted-key", nil)
	if err != nil {
		return "", fmt.Errorf("get encrypted Step CA provisioner key: %w", err)
	}
	var response struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("decode encrypted Step CA provisioner key: %w", err)
	}
	if strings.TrimSpace(response.Key) == "" {
		return "", errors.New("encrypted Step CA provisioner key response was empty")
	}
	return response.Key, nil
}

func decryptProvisionerJWK(encryptedKey string, password string) (*jose.JSONWebKey, error) {
	decrypted, err := jose.Decrypt([]byte(encryptedKey), jose.WithPassword([]byte(password)))
	if err != nil {
		return nil, fmt.Errorf("decrypt Step CA provisioner key: %w", err)
	}
	var key jose.JSONWebKey
	if err := json.Unmarshal(decrypted, &key); err != nil {
		return nil, fmt.Errorf("decode Step CA provisioner key: %w", err)
	}
	if key.Key == nil {
		return nil, errors.New("decrypted Step CA JWK did not contain a private key")
	}
	return &key, nil
}

func (c *apiClient) generateProvisionerSignToken(key *jose.JSONWebKey, kid string) (string, error) {
	now := time.Now().UTC()
	jwtID, err := randutil.Hex(64)
	if err != nil {
		return "", fmt.Errorf("generate provisioning JWT ID: %w", err)
	}
	token, err := stepProvision.New(c.adminSubject,
		stepToken.WithJWTID(jwtID),
		stepToken.WithKid(kid),
		stepToken.WithIssuer(c.adminProvisioner),
		stepToken.WithAudience(c.stepCAURL+"/1.0/sign"),
		stepToken.WithValidity(now, now.Add(stepToken.DefaultValidity)),
		stepToken.WithSANS([]string{c.adminSubject}),
	)
	if err != nil {
		return "", fmt.Errorf("create Step CA provisioning token: %w", err)
	}
	algorithm := key.Algorithm
	if algorithm == "" {
		algorithm, err = signingAlgorithmForKey(key.Key)
		if err != nil {
			return "", err
		}
	}
	signed, err := token.SignedString(algorithm, key.Key)
	if err != nil {
		return "", fmt.Errorf("sign Step CA provisioning token: %w", err)
	}
	return signed, nil
}

func generateAdminCSR(subject string) (crypto.Signer, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate administrator private key: %w", err)
	}
	dnsNames, ipAddresses, emailAddresses, uris := splitSANs([]string{subject})
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: subject}, DNSNames: dnsNames,
		IPAddresses: ipAddresses, EmailAddresses: emailAddresses, URIs: uris,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, "", fmt.Errorf("create administrator certificate request: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	return key, string(encoded), nil
}

func splitSANs(values []string) ([]string, []net.IP, []string, []*url.URL) {
	dnsNames := make([]string, 0, len(values))
	ipAddresses := make([]net.IP, 0)
	emailAddresses := make([]string, 0)
	uris := make([]*url.URL, 0)
	for _, value := range values {
		value = strings.TrimSpace(value)
		if ip := net.ParseIP(value); ip != nil {
			ipAddresses = append(ipAddresses, ip)
			continue
		}
		if uri, err := url.Parse(value); err == nil && uri.Scheme != "" {
			uris = append(uris, uri)
			continue
		}
		if strings.Contains(value, "@") {
			emailAddresses = append(emailAddresses, value)
			continue
		}
		dnsNames = append(dnsNames, value)
	}
	return dnsNames, ipAddresses, emailAddresses, uris
}

func (c *apiClient) signAdminCSR(ctx context.Context, csr string, provisioningToken string) (map[string]any, error) {
	body, err := c.requestStepCA(ctx, http.MethodPost, "/1.0/sign", map[string]any{
		"csr": csr,
		"ott": provisioningToken,
	})
	if err != nil {
		return nil, fmt.Errorf("sign Step CA administrator certificate: %w", err)
	}
	var response map[string]any
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("decode Step CA sign response: %w", err)
	}
	return response, nil
}

func parseCertificateChain(signResponse map[string]any) ([]string, time.Time, error) {
	certificates := make([]string, 0)
	if rawChain, ok := signResponse["certChain"].([]any); ok {
		for _, rawCertificate := range rawChain {
			if certificate, ok := rawCertificate.(string); ok && strings.TrimSpace(certificate) != "" {
				certificates = append(certificates, certificate)
			}
		}
	}
	if len(certificates) == 0 {
		if certificate, ok := signResponse["crt"].(string); ok && strings.TrimSpace(certificate) != "" {
			certificates = append(certificates, certificate)
		}
	}
	if len(certificates) == 0 {
		return nil, time.Time{}, errors.New("Step CA sign response did not include a certificate chain")
	}
	encodedChain := make([]string, 0, len(certificates))
	var leafExpiry time.Time
	for index, certificatePEM := range certificates {
		block, _ := pem.Decode([]byte(certificatePEM))
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, time.Time{}, errors.New("Step CA sign response contained an invalid certificate")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("parse Step CA certificate: %w", err)
		}
		if index == 0 {
			leafExpiry = certificate.NotAfter
		}
		encodedChain = append(encodedChain, base64.StdEncoding.EncodeToString(certificate.Raw))
	}
	return encodedChain, leafExpiry, nil
}

func (c *apiClient) generateAdminJWT(audience string) (string, error) {
	jwtID, err := randutil.Hex(64)
	if err != nil {
		return "", fmt.Errorf("generate administrator JWT ID: %w", err)
	}
	now := time.Now().UTC()
	token, err := stepProvision.New(c.adminSubject,
		stepToken.WithJWTID(jwtID),
		stepToken.WithIssuer(stepAdminIssuer),
		stepToken.WithAudience(sanitizeAudience(audience)),
		stepToken.WithValidity(now, now.Add(stepToken.DefaultValidity)),
		stepToken.WithX5CCerts(c.adminX5CCertChain),
	)
	if err != nil {
		return "", fmt.Errorf("create Step CA administrator token: %w", err)
	}
	signed, err := token.SignedString(c.adminSignerAlg, c.adminSigner)
	if err != nil {
		return "", fmt.Errorf("sign Step CA administrator token: %w", err)
	}
	return signed, nil
}

func sanitizeAudience(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func signingAlgorithmForKey(key any) (string, error) {
	switch typedKey := key.(type) {
	case *ecdsa.PrivateKey:
		switch typedKey.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve %q", typedKey.Curve.Params().Name)
		}
	case *rsa.PrivateKey:
		return jose.DefaultRSASigAlgorithm, nil
	case ed25519.PrivateKey:
		return jose.EdDSA, nil
	case *jose.JSONWebKey:
		if typedKey.Algorithm != "" {
			return typedKey.Algorithm, nil
		}
		return signingAlgorithmForKey(typedKey.Key)
	default:
		return "", fmt.Errorf("unsupported signing key type %T", key)
	}
}
