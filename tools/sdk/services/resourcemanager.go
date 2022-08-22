package services

import "github.com/hashicorp/pandora/tools/sdk/resourcemanager"

type ResourceManagerServices struct {
	Services map[string]ResourceManagerService
}

type ResourceManagerService struct {
	Details              resourcemanager.ServiceSummary
	TerraformPackageName *string
	Terraform            resourcemanager.TerraformDetails
	TransportLayer       string
	Versions             map[string]ServiceVersion
}

type ServiceVersion struct {
	Details   resourcemanager.ServiceVersionDetails
	Resources map[string]Resource
}

type Resource struct {
	Operations resourcemanager.ApiOperationDetails
	Schema     resourcemanager.ApiSchemaDetails
}
