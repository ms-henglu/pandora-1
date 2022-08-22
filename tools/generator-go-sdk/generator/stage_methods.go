package generator

import (
	"fmt"
	"strings"
)

func (s *ServiceGenerator) methods(data ServiceGeneratorData) error {
	transport := data.transportLayer
	if s.settings.TransportLayerOverride != nil && len(*s.settings.TransportLayerOverride) > 0 {
		transport = *s.settings.TransportLayerOverride
	}

	for operationName, operation := range data.operations {
		fileName := fmt.Sprintf("method_%s_%s.go", strings.ToLower(operationName), transport)
		var gen templaterForResource
		switch transport {
		case AutoRest:
			gen = methodsAutoRestTemplater{
				operationName: operationName,
				operation:     operation,
				constants:     data.constants,
			}
		case Pandora:
			gen = methodsPandoraTemplater{
				operationName: operationName,
				operation:     operation,
				constants:     data.constants,
			}
		}
		if err := s.writeToPathForResource(data.resourceOutputPath, fileName, gen, data); err != nil {
			return fmt.Errorf("templating methods (using %s): %+v", transport, err)
		}
	}

	return nil
}
