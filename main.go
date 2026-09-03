package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/stegraab/terraform-provider-stegra/internal/provider"
)

var version = "dev"

func main() {
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/stegraab/stegra",
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}
