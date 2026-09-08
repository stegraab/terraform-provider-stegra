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
}

func TestProviderSupportsAWSProfileSelection(t *testing.T) {
	t.Parallel()
	var response frameworkprovider.SchemaResponse
	(&stegraProvider{}).Schema(context.Background(), frameworkprovider.SchemaRequest{}, &response)
	attribute, found := response.Schema.Attributes["aws_profile"]
	if !found {
		t.Fatal("aws_profile must be available for workspaces that select credentials through shared AWS profiles")
	}
	if attribute.IsSensitive() {
		t.Fatal("aws_profile is a non-secret selector and must not be marked sensitive")
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
