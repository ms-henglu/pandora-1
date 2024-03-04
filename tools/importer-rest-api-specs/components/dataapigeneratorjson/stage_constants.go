// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dataapigeneratorjson

import (
	"fmt"
	"path/filepath"

	"github.com/hashicorp/pandora/tools/data-api-sdk/v1/models"
	"github.com/hashicorp/pandora/tools/importer-rest-api-specs/components/dataapigeneratorjson/transforms"
	"github.com/hashicorp/pandora/tools/importer-rest-api-specs/internal/logging"
)

var _ generatorStage = generateConstantStage{}

type generateConstantStage struct {
	// serviceName specifies the name of the Service within which the Constants exist.
	serviceName string

	// apiVersion specifies the APIVersion within the Service where the Constants exist.
	apiVersion string

	// apiResource specifies the APIResource within the APIVersion where the Constants exist.
	apiResource string

	// constants specifies the map of Constant Name (key) to SDKConstant (value) which should be
	// persisted.
	constants map[string]models.SDKConstant

	// resourceIDs specifies a map of Resource ID Name (key) to ResourceID (value) that should
	// be persisted.
	resourceIDs map[string]models.ResourceID
}

func (g generateConstantStage) name() string {
	return "Constants"
}

func (g generateConstantStage) generate(input *fileSystem) error {
	logging.Log.Debug("Generating Constants")

	for constantName, constantVal := range g.constants {
		logging.Log.Trace(fmt.Sprintf("Processing Constant %q", constantName))

		mapped, err := transforms.MapSDKConstantToRepository(constantName, constantVal)
		if err != nil {
			return fmt.Errorf("mapping SDKConstant %q: %+v", constantName, err)
		}

		// {workingDirectory}/Service/APIVersion/APIResource/Constant-{Name}.json
		path := filepath.Join(g.serviceName, g.apiVersion, g.apiResource, fmt.Sprintf("Constant-%s.json", constantName))
		logging.Log.Trace(fmt.Sprintf("Staging to %s", path))
		if err := input.stage(path, *mapped); err != nil {
			return fmt.Errorf("staging Constant %q: %+v", constantName, err)
		}
	}

	// ResourceIDs also contain Constants - so we need to pull those out and persist them too
	for resourceIdName, resourceId := range g.resourceIDs {
		logging.Log.Trace(fmt.Sprintf("Processing Constants within the Resource ID %q", resourceIdName))

		for constantName, constantVal := range resourceId.Constants {
			logging.Log.Trace(fmt.Sprintf("Processing Constant %q", constantName))

			mapped, err := transforms.MapSDKConstantToRepository(constantName, constantVal)
			if err != nil {
				return fmt.Errorf("mapping SDKConstant %q: %+v", constantName, err)
			}

			// {workingDirectory}/Service/APIVersion/APIResource/Constant-{Name}.json
			path := filepath.Join(g.serviceName, g.apiVersion, g.apiResource, fmt.Sprintf("Constant-%s.json", constantName))
			logging.Log.Trace(fmt.Sprintf("Staging to %s", path))
			if err := input.stage(path, *mapped); err != nil {
				return fmt.Errorf("staging Constant %q: %+v", constantName, err)
			}
		}
	}

	return nil
}
