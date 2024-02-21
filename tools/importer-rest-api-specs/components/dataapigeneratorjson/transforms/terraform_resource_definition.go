// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package transforms

import (
	"fmt"

	"github.com/hashicorp/go-azure-helpers/lang/pointer"
	"github.com/hashicorp/pandora/tools/data-api-sdk/v1/models"
	"github.com/hashicorp/pandora/tools/sdk/dataapimodels"
)

func MapTerraformResourceDefinitionToRepository(resourceLabel string, input models.TerraformResourceDefinition) (*dataapimodels.TerraformResourceDefinition, error) {
	// TODO: ExampleUsage should probably go out into a file - perhaps `Resource-ExampleUsage.hcl`?
	output := dataapimodels.TerraformResourceDefinition{
		ApiVersion:                   input.APIVersion,
		Category:                     input.Documentation.Category,
		CreateMethod:                 mapTerraformMethodDefinitionToRepository(input.CreateMethod),
		DeleteMethod:                 mapTerraformMethodDefinitionToRepository(input.DeleteMethod),
		Description:                  input.Documentation.Description,
		DisplayName:                  input.DisplayName,
		ExampleUsage:                 input.Documentation.ExampleUsageHCL,
		Generate:                     input.Generate,
		GenerateIdValidationFunction: input.GenerateIDValidation,
		GenerateModel:                input.GenerateModel,
		GenerateSchema:               input.GenerateSchema,
		Label:                        resourceLabel,
		ReadMethod:                   mapTerraformMethodDefinitionToRepository(input.ReadMethod),
		Resource:                     input.ResourceName,
		ResourceIdName:               input.ResourceIDName,
		// todo remove Schema when https://github.com/hashicorp/pandora/issues/3346 is addressed
		SchemaModelName: fmt.Sprintf("%sSchema", input.SchemaModelName),
		// TODO: output tests here
		UpdateMethod: nil,
	}
	if input.UpdateMethod != nil {
		mapped := mapTerraformMethodDefinitionToRepository(*input.UpdateMethod)
		output.UpdateMethod = pointer.To(mapped)
	}

	return &output, nil
}
