package provider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsV4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	awsIAMAuthorizationScheme = "AWS-IAM"
	stsRequestBody            = "Action=GetCallerIdentity&Version=2011-06-15"
)

type apiClient struct {
	machineEnrollmentURL   string
	machineEnrollmentToken string
	awsRegion              string
	awsCredentials         aws.CredentialsProvider
	insecureSkipVerify     bool
	httpClient             *http.Client
	now                    func() time.Time
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

// awsIAMProof follows the established AWS IAM authentication pattern: the
// broker validates the signed context, sends this exact request to AWS STS, and
// authorizes the principal returned by GetCallerIdentity.
type awsIAMProof struct {
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Headers http.Header `json:"headers"`
	Body    string      `json:"body"`
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
	var requestBody []byte
	if payload != nil {
		var err error
		requestBody, err = json.Marshal(payload)
		if err != nil {
			return machineEnrollment{}, fmt.Errorf("encode request body: %w", err)
		}
	}
	endpoint := c.machineEnrollmentURL + path
	authorization, err := c.machineEnrollmentAuthorization(ctx, method, endpoint, requestBody)
	if err != nil {
		return machineEnrollment{}, err
	}
	body, err := c.request(ctx, method, endpoint, requestBody, authorization)
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

func (c *apiClient) machineEnrollmentAuthorization(ctx context.Context, method string, endpoint string, body []byte) (string, error) {
	if c.machineEnrollmentToken != "" {
		return c.machineEnrollmentToken, nil
	}
	proof, err := c.signAWSIAMProof(ctx, method, endpoint, body)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(proof)
	if err != nil {
		return "", fmt.Errorf("encode AWS IAM proof: %w", err)
	}
	return awsIAMAuthorizationScheme + " " + base64.RawURLEncoding.EncodeToString(encoded), nil
}

func (c *apiClient) signAWSIAMProof(ctx context.Context, method string, endpoint string, body []byte) (awsIAMProof, error) {
	if c.awsCredentials == nil {
		return awsIAMProof{}, errors.New("AWS credentials are not configured")
	}
	credentials, err := c.awsCredentials.Retrieve(ctx)
	if err != nil {
		return awsIAMProof{}, fmt.Errorf("retrieve ambient AWS credentials: %w", err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return awsIAMProof{}, fmt.Errorf("generate AWS IAM proof nonce: %w", err)
	}
	bodyDigest := sha256.Sum256(body)
	stsEndpoint, err := sts.NewDefaultEndpointResolverV2().ResolveEndpoint(
		ctx,
		sts.EndpointParameters{Region: aws.String(c.awsRegion)},
	)
	if err != nil {
		return awsIAMProof{}, fmt.Errorf("resolve AWS STS endpoint: %w", err)
	}
	stsEndpoint.URI.Path = "/"
	stsEndpoint.URI.RawQuery = ""
	stsEndpoint.URI.Fragment = ""
	stsURL := stsEndpoint.URI.String()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, stsURL, strings.NewReader(stsRequestBody))
	if err != nil {
		return awsIAMProof{}, fmt.Errorf("build AWS STS identity request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	request.Header.Set("X-Stegra-Audience", c.machineEnrollmentURL)
	request.Header.Set("X-Stegra-Request-Method", method)
	request.Header.Set("X-Stegra-Request-URL", endpoint)
	request.Header.Set("X-Stegra-Request-Body-SHA256", hex.EncodeToString(bodyDigest[:]))
	request.Header.Set("X-Stegra-Nonce", base64.RawURLEncoding.EncodeToString(nonce))
	stsBodyDigest := sha256.Sum256([]byte(stsRequestBody))
	signingTime := time.Now().UTC()
	if c.now != nil {
		signingTime = c.now().UTC()
	}
	if err := awsV4.NewSigner().SignHTTP(ctx, credentials, request, hex.EncodeToString(stsBodyDigest[:]), "sts", c.awsRegion, signingTime); err != nil {
		return awsIAMProof{}, fmt.Errorf("sign AWS STS identity request: %w", err)
	}
	headers := request.Header.Clone()
	headers.Set("Host", request.URL.Host)
	return awsIAMProof{Method: http.MethodPost, URL: stsURL, Headers: headers, Body: stsRequestBody}, nil
}

func (c *apiClient) request(ctx context.Context, method string, endpoint string, body []byte, authorization string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	if len(body) != 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("perform request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, &apiStatusError{StatusCode: response.StatusCode, Body: strings.TrimSpace(string(responseBody))}
	}
	return responseBody, nil
}
