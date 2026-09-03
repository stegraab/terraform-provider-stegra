package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.step.sm/crypto/jose"
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
		if request.Header.Get("Authorization") != "local-development-token" {
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
		machineEnrollmentURL: server.URL, machineEnrollmentToken: "local-development-token",
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
		name, enrollmentURL, localToken, stepCAURL string
		insecure, wantError                        bool
	}{
		{name: "production HTTPS", enrollmentURL: "https://enroll.example", stepCAURL: "https://ca.example"},
		{name: "production enrollment HTTP", enrollmentURL: "http://enroll.example", stepCAURL: "https://ca.example", wantError: true},
		{name: "production Step CA HTTP", enrollmentURL: "https://enroll.example", stepCAURL: "http://ca.example", wantError: true},
		{name: "production insecure TLS", enrollmentURL: "https://enroll.example", stepCAURL: "https://ca.example", insecure: true, wantError: true},
		{name: "local HTTP", enrollmentURL: "http://127.0.0.1:8000", localToken: "local-token"},
		{name: "invalid enrollment scheme", enrollmentURL: "file:///tmp/enrollment", localToken: "local-token", wantError: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := &apiClient{
				machineEnrollmentURL: test.enrollmentURL, machineEnrollmentToken: test.localToken,
				stepCAURL: test.stepCAURL, insecureSkipVerify: test.insecure,
			}
			err := client.validateTransport()
			if (err != nil) != test.wantError {
				t.Fatalf("validateTransport() error=%v wantError=%v", err, test.wantError)
			}
		})
	}
}

func TestStepCAAdministratorJWTUsesValidationAudience(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := &apiClient{
		stepCAURL: "https://ca.example", adminSubject: "terraform-admin", adminSigner: key,
		adminSignerAlg: jose.ES256, adminX5CCertChain: []string{"Y2VydA=="},
		adminCertExpiry: time.Now().Add(time.Hour),
	}
	token, err := client.machineEnrollmentAuthorization(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected JWT format: %q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Audience string `json:"aud"`
		Subject  string `json:"sub"`
		Issuer   string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Audience != "https://ca.example/admin/admins" {
		t.Fatalf("audience=%q", claims.Audience)
	}
	if claims.Subject != "terraform-admin" || claims.Issuer != stepAdminIssuer {
		t.Fatalf("claims=%#v", claims)
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
