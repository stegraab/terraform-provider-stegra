package provider

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
		name, enrollmentURL, localToken string
		insecure, wantError             bool
	}{
		{name: "production HTTPS", enrollmentURL: "https://enroll.example"},
		{name: "production enrollment HTTP", enrollmentURL: "http://enroll.example", wantError: true},
		{name: "production insecure TLS", enrollmentURL: "https://enroll.example", insecure: true, wantError: true},
		{name: "local HTTP", enrollmentURL: "http://127.0.0.1:8000", localToken: "local-token"},
		{name: "invalid enrollment scheme", enrollmentURL: "file:///tmp/enrollment", localToken: "local-token", wantError: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := &apiClient{
				machineEnrollmentURL: test.enrollmentURL, machineEnrollmentToken: test.localToken,
				insecureSkipVerify: test.insecure,
			}
			err := client.validateTransport()
			if (err != nil) != test.wantError {
				t.Fatalf("validateTransport() error=%v wantError=%v", err, test.wantError)
			}
		})
	}
}

func TestAWSIAMProofIsBoundToMachineEnrollmentRequest(t *testing.T) {
	t.Parallel()
	body := []byte(`{"machine_identity":"host/example.internal"}`)
	client := &apiClient{
		machineEnrollmentURL: "https://ca.example/machine-enrollment",
		awsRegion:            "eu-north-1",
		awsCredentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
				SessionToken: "session-token",
			}, nil
		}),
		now: func() time.Time { return time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC) },
	}
	authorization, err := client.machineEnrollmentAuthorization(
		context.Background(), http.MethodPost,
		"https://ca.example/machine-enrollment/v1/machine-enrollments", body,
	)
	if err != nil {
		t.Fatal(err)
	}
	prefix := awsIAMAuthorizationScheme + " "
	if !strings.HasPrefix(authorization, prefix) {
		t.Fatalf("unexpected authorization scheme: %q", authorization)
	}
	encoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(authorization, prefix))
	if err != nil {
		t.Fatal(err)
	}
	var proof awsIAMProof
	if err := json.Unmarshal(encoded, &proof); err != nil {
		t.Fatal(err)
	}
	if proof.Method != http.MethodPost || proof.URL != "https://sts.eu-north-1.amazonaws.com/" || proof.Body != stsRequestBody {
		t.Fatalf("unexpected STS proof: %#v", proof)
	}
	expectedBodyDigest := sha256.Sum256(body)
	wants := map[string]string{
		"Host":                         "sts.eu-north-1.amazonaws.com",
		"X-Amz-Date":                   "20260907T120000Z",
		"X-Amz-Security-Token":         "session-token",
		"X-Stegra-Audience":            "https://ca.example/machine-enrollment",
		"X-Stegra-Request-Method":      http.MethodPost,
		"X-Stegra-Request-URL":         "https://ca.example/machine-enrollment/v1/machine-enrollments",
		"X-Stegra-Request-Body-SHA256": hex.EncodeToString(expectedBodyDigest[:]),
	}
	for header, want := range wants {
		if got := proof.Headers.Get(header); got != want {
			t.Errorf("%s=%q want %q", header, got, want)
		}
	}
	if len(proof.Headers.Get("X-Stegra-Nonce")) < 32 {
		t.Error("proof is missing a strong nonce")
	}
	signed := strings.ToLower(proof.Headers.Get("Authorization"))
	for _, header := range []string{
		"host", "x-amz-date", "x-amz-security-token", "x-stegra-audience",
		"x-stegra-nonce", "x-stegra-request-body-sha256", "x-stegra-request-method",
		"x-stegra-request-url",
	} {
		if !strings.Contains(signed, header) {
			t.Errorf("AWS signature does not cover %s: %q", header, signed)
		}
	}
}

func TestAWSIAMProofUsesFreshNonce(t *testing.T) {
	t.Parallel()
	client := &apiClient{
		machineEnrollmentURL: "https://ca.example/machine-enrollment",
		awsRegion:            "eu-north-1",
		awsCredentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "key", SecretAccessKey: "secret"}, nil
		}),
		now: func() time.Time { return time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC) },
	}
	first, err := client.signAWSIAMProof(context.Background(), http.MethodGet, "https://ca.example/one", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.signAWSIAMProof(context.Background(), http.MethodGet, "https://ca.example/one", nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.Headers.Get("X-Stegra-Nonce") == second.Headers.Get("X-Stegra-Nonce") {
		t.Fatal("AWS IAM proofs reused a nonce")
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

func TestEndpointMigrationDoesNotReplaceLegacyEnrollment(t *testing.T) {
	t.Parallel()
	if shouldReplaceMachineEnrollmentEndpoint(types.StringNull()) {
		t.Fatal("legacy state without an endpoint must be adopted in place")
	}
	if shouldReplaceMachineEnrollmentEndpoint(types.StringUnknown()) {
		t.Fatal("unknown legacy endpoint must not replace an enrollment")
	}
	if !shouldReplaceMachineEnrollmentEndpoint(types.StringValue("https://ca.example/machine-enrollment")) {
		t.Fatal("changing an endpoint already stored in state must replace the enrollment")
	}
}
