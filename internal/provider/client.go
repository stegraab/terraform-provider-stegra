package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
)

type apiClient struct {
	machineEnrollmentURL string
	tokenSource          tokenSource
	insecureSkipVerify   bool
	httpClient           *http.Client
}

type tokenSource interface {
	Token(context.Context) (string, error)
}

type staticTokenSource string

func (s staticTokenSource) Token(context.Context) (string, error) {
	return string(s), nil
}

type stegraCLITokenSource struct {
	authURL string
	run     func(context.Context, string, ...string) ([]byte, error)
}

func (s *stegraCLITokenSource) Token(ctx context.Context) (string, error) {
	if s.authURL == "" {
		return "", errors.New("machine_enrollment_auth_url must be configured for production authentication")
	}
	run := s.run
	if run == nil {
		run = commandOutput
	}
	output, err := run(
		ctx,
		"stegra",
		"auth",
		"stegra",
		"--base-url",
		s.authURL,
		"--realm",
		"master",
		"--client-id",
		"stegra-cli",
		"--token-only",
	)
	if err != nil {
		return "", fmt.Errorf("obtain short-lived Stegra access token: %w", err)
	}
	var response struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(output, &response); err != nil {
		return "", errors.New("stegra auth returned invalid JSON")
	}
	if strings.TrimSpace(response.AccessToken) == "" {
		return "", errors.New("stegra auth returned no access token")
	}
	return strings.TrimSpace(response.AccessToken), nil
}

func commandOutput(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, arguments...).Output()
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
	var requestBody []byte
	if payload != nil {
		var err error
		requestBody, err = json.Marshal(payload)
		if err != nil {
			return machineEnrollment{}, fmt.Errorf("encode request body: %w", err)
		}
	}
	endpoint := c.machineEnrollmentURL + path
	authorization, err := c.machineEnrollmentAuthorization(ctx)
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
	if _, ok := c.tokenSource.(staticTokenSource); ok {
		return nil
	}
	if enrollmentEndpoint.Scheme != "https" {
		return errors.New("production machine enrollment requires HTTPS")
	}
	if c.insecureSkipVerify {
		return errors.New("production machine enrollment requires TLS certificate verification")
	}
	if source, ok := c.tokenSource.(*stegraCLITokenSource); ok {
		authEndpoint, err := parseHTTPURL(source.authURL)
		if err != nil {
			return fmt.Errorf("machine enrollment auth URL: %w", err)
		}
		if authEndpoint.Scheme != "https" {
			return errors.New("production machine enrollment authentication requires HTTPS")
		}
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
	if c.tokenSource == nil {
		return "", errors.New("machine enrollment authentication is not configured")
	}
	token, err := c.tokenSource.Token(ctx)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(token, "Bearer ") {
		return token, nil
	}
	return "Bearer " + token, nil
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
