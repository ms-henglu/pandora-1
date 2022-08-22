package generator

import "fmt"

func (s *ServiceGenerator) clients(data ServiceGeneratorData) error {
	transport := data.transportLayer
	if s.settings.TransportLayerOverride != nil && len(*s.settings.TransportLayerOverride) > 0 {
		transport = *s.settings.TransportLayerOverride
	}

	switch transport {
	case AutoRest:
		if err := s.writeToPathForResource(data.resourceOutputPath, "client.go", clientsAutoRestTemplater{}, data); err != nil {
			return fmt.Errorf("templating client: %+v", err)
		}
	case Pandora:
		if err := s.writeToPathForResource(data.resourceOutputPath, "client.go", clientsPandoraTemplater{}, data); err != nil {
			return fmt.Errorf("templating client: %+v", err)
		}
	}

	return nil
}
