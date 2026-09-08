package provider

import (
	"context"
	"net/http"
	"os"
	"testing"

	frameworkprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestProviderOwnsMachineEnrollmentEndpoint(t *testing.T) {
	t.Parallel()
	var response frameworkprovider.SchemaResponse
	(&stegraProvider{}).Schema(context.Background(), frameworkprovider.SchemaRequest{}, &response)
	if _, found := response.Schema.Attributes["machine_enrollment_endpoint"]; !found {
		t.Fatal("machine_enrollment_endpoint must be configured once on the provider")
	}
	if _, found := response.Schema.Attributes["machine_enrollment_auth_url"]; !found {
		t.Fatal("machine_enrollment_auth_url must be configured once on the provider")
	}
}

func TestNormalizeURL(t *testing.T) {
	t.Parallel()
	if got := normalizeURL(" https://example.internal/path/ "); got != "https://example.internal/path" {
		t.Fatalf("normalizeURL()=%q", got)
	}
}

func TestRejectRedirects(t *testing.T) {
	t.Parallel()
	if err := rejectRedirects(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("rejectRedirects()=%v", err)
	}
}

func TestConfigString(t *testing.T) {
	t.Run("explicit value", func(t *testing.T) {
		value, ok := configString(types.StringValue("configured"), "STEGRA_TEST_VALUE", "default")
		if !ok || value != "configured" {
			t.Fatalf("value=%q ok=%v", value, ok)
		}
	})
	t.Run("environment fallback", func(t *testing.T) {
		t.Setenv("STEGRA_TEST_VALUE", "environment")
		value, ok := configString(types.StringNull(), "STEGRA_TEST_VALUE", "default")
		if !ok || value != "environment" {
			t.Fatalf("value=%q ok=%v", value, ok)
		}
	})
	t.Run("default fallback", func(t *testing.T) {
		_ = os.Unsetenv("STEGRA_TEST_UNSET")
		value, ok := configString(types.StringNull(), "STEGRA_TEST_UNSET", "default")
		if !ok || value != "default" {
			t.Fatalf("value=%q ok=%v", value, ok)
		}
	})
}

func TestKeycloakPasswordCredentials(t *testing.T) {
	t.Run("not configured", func(t *testing.T) {
		_ = os.Unsetenv("KEYCLOAK_USER")
		_ = os.Unsetenv("KEYCLOAK_PASSWORD")
		_, _, configured, err := keycloakPasswordCredentials()
		if err != nil || configured {
			t.Fatalf("configured=%v error=%v", configured, err)
		}
	})
	t.Run("configured", func(t *testing.T) {
		t.Setenv("KEYCLOAK_USER", "infrastructure-as-code-runner")
		t.Setenv("KEYCLOAK_PASSWORD", "secret")
		username, password, configured, err := keycloakPasswordCredentials()
		if err != nil || !configured || username != "infrastructure-as-code-runner" || password != "secret" {
			t.Fatalf("username=%q configured=%v error=%v", username, configured, err)
		}
	})
	t.Run("partial configuration", func(t *testing.T) {
		t.Setenv("KEYCLOAK_USER", "infrastructure-as-code-runner")
		_ = os.Unsetenv("KEYCLOAK_PASSWORD")
		_, _, _, err := keycloakPasswordCredentials()
		if err == nil {
			t.Fatal("expected an error")
		}
	})
}
