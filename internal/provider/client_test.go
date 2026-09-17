package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMachineEnrollmentLifecycle(t *testing.T) {
	t.Parallel()
	registration := machineEnrollment{
		ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", AttestorType: "nutanix-vtpm",
		AttestorIdentity: "11111111-1111-4111-8111-111111111111",
		AttestorClaims: map[string]string{
			"vm_ext_id":       "22222222-2222-4222-8222-222222222222",
			"generation_uuid": "33333333-3333-4333-8333-333333333333",
			"vtpm_disk_id":    "44444444-4444-4444-8444-444444444444",
		},
		MachineIdentity: "host/example.internal", SSHPrincipals: []string{"example", "example.internal"},
		Status: "pending",
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer local-development-token" {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/v1/machine-enrollments":
			var input machineEnrollment
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if input.ID != "" || input.Status != "" {
				t.Errorf("computed fields leaked into create: %#v", input)
			}
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(registration)
		case request.Method == http.MethodGet && request.URL.Path == "/v1/machine-enrollments/"+registration.ID:
			_ = json.NewEncoder(writer).Encode(registration)
		case request.Method == http.MethodDelete && request.URL.Path == "/v1/machine-enrollments/"+registration.ID:
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := &apiClient{
		machineEnrollmentURL: server.URL, tokenSource: staticTokenSource("local-development-token"),
		httpClient: server.Client(),
	}
	created, err := client.createMachineEnrollment(context.Background(), registration)
	if err != nil || created.ID != registration.ID {
		t.Fatalf("create: registration=%#v err=%v", created, err)
	}
	read, found, err := client.getMachineEnrollment(context.Background(), registration.ID)
	if err != nil || !found || read.Status != "pending" {
		t.Fatalf("read: registration=%#v found=%v err=%v", read, found, err)
	}
	if err := client.revokeMachineEnrollment(context.Background(), registration.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

func TestMachineEnrollmentTransportSecurity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, enrollmentURL, localToken string
		insecure, wantError             bool
	}{
		{name: "production HTTPS", enrollmentURL: "https://enroll.example"},
		{name: "production enrollment HTTP", enrollmentURL: "http://enroll.example", wantError: true},
		{name: "production insecure TLS", enrollmentURL: "https://enroll.example", insecure: true, wantError: true},
		{name: "local HTTP", enrollmentURL: "http://127.0.0.1:8000", localToken: "local-token"},
		{name: "local HTTPS", enrollmentURL: "https://localhost:8000", localToken: "local-token", insecure: true},
		{name: "remote static token", enrollmentURL: "https://enroll.example", localToken: "local-token", wantError: true},
		{name: "invalid enrollment scheme", enrollmentURL: "file:///tmp/enrollment", localToken: "local-token", wantError: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var source tokenSource = &stegraCLITokenSource{authURL: "https://auth.example"}
			if test.localToken != "" {
				source = staticTokenSource(test.localToken)
			}
			client := &apiClient{
				machineEnrollmentURL: test.enrollmentURL, tokenSource: source,
				insecureSkipVerify: test.insecure,
			}
			err := client.validateTransport()
			if (err != nil) != test.wantError {
				t.Fatalf("validateTransport() error=%v wantError=%v", err, test.wantError)
			}
		})
	}
}

func TestStegraCLITokenSource(t *testing.T) {
	t.Parallel()
	var gotName string
	var gotArguments []string
	source := &stegraCLITokenSource{
		authURL: "https://auth.example.internal",
		run: func(_ context.Context, name string, arguments ...string) ([]byte, error) {
			gotName = name
			gotArguments = arguments
			return []byte(`{"access_token":"short-lived-token"}`), nil
		},
	}
	token, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if token != "short-lived-token" {
		t.Fatalf("token=%q", token)
	}
	if gotName != "stegra" {
		t.Fatalf("command=%q", gotName)
	}
	wantArguments := []string{
		"auth", "stegra", "--base-url", "https://auth.example.internal", "--realm", "public",
		"--client-id", "stegra-cli", "--token-only",
	}
	if len(gotArguments) != len(wantArguments) {
		t.Fatalf("arguments=%q", gotArguments)
	}
	for index := range wantArguments {
		if gotArguments[index] != wantArguments[index] {
			t.Fatalf("arguments=%q", gotArguments)
		}
	}
}

func TestStegraCLITokenSourceDoesNotExposeOutputOnFailure(t *testing.T) {
	t.Parallel()
	source := &stegraCLITokenSource{
		authURL: "https://auth.example.internal",
		run: func(context.Context, string, ...string) ([]byte, error) {
			return []byte(`{"access_token":"must-not-appear"}`), errors.New("exit status 1")
		},
	}
	_, err := source.Token(context.Background())
	if err == nil || err.Error() != "obtain short-lived Stegra access token: exit status 1" {
		t.Fatalf("error=%v", err)
	}
}

func TestOAuthClientCredentialsTokenSourceCachesToken(t *testing.T) {
	t.Parallel()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if err := request.ParseForm(); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{
			"grant_type": "client_credentials",
			"client_id":  "terraform-ci", "client_secret": "pipeline-secret",
		}
		for key, value := range want {
			if request.Form.Get(key) != value {
				t.Errorf("%s=%q", key, request.Form.Get(key))
			}
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"access_token": "short-lived-token", "expires_in": 300,
		})
	}))
	defer server.Close()
	now := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	source := &oauthClientCredentialsTokenSource{
		tokenEndpoint: server.URL, clientID: "terraform-ci", clientSecret: "pipeline-secret",
		httpClient: server.Client(), now: func() time.Time { return now },
	}
	for range 2 {
		token, err := source.Token(context.Background())
		if err != nil || token != "short-lived-token" {
			t.Fatalf("token=%q error=%v", token, err)
		}
	}
	if requests != 1 {
		t.Fatalf("requests=%d", requests)
	}
}

func TestOAuthClientCredentialsTokenSourceDoesNotExposeResponse(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "must-not-appear", http.StatusUnauthorized)
	}))
	defer server.Close()
	source := &oauthClientCredentialsTokenSource{
		tokenEndpoint: server.URL, clientID: "terraform-ci", clientSecret: "secret", httpClient: server.Client(),
	}
	_, err := source.Token(context.Background())
	if err == nil || err.Error() != "obtain short-lived OAuth access token: status 401" {
		t.Fatalf("error=%v", err)
	}
}

func TestInactiveMachineEnrollmentStatuses(t *testing.T) {
	t.Parallel()
	for _, status := range []string{"expired", "revoked"} {
		if !isInactiveMachineEnrollmentStatus(status) {
			t.Fatalf("expected %q to be inactive", status)
		}
	}
	for _, status := range []string{"pending", "attested", "issued"} {
		if isInactiveMachineEnrollmentStatus(status) {
			t.Fatalf("expected %q to be active", status)
		}
	}
}

func TestMachineEnrollmentRevocationIsOneWay(t *testing.T) {
	t.Parallel()
	if err := validateMachineEnrollmentRevocation(false, true); err != nil {
		t.Fatalf("revoke active enrollment: %v", err)
	}
	if err := validateMachineEnrollmentRevocation(true, true); err != nil {
		t.Fatalf("retain revoked enrollment: %v", err)
	}
	if err := validateMachineEnrollmentRevocation(true, false); err == nil {
		t.Fatal("expected in-place unrevocation to fail")
	}
}
