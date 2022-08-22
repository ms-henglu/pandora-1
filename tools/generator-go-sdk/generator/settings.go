package generator

type Settings struct {
	TransportLayerOverride *TransportLayer
}

type TransportLayer = string

const (
	AutoRest TransportLayer = "autorest"
	Pandora  TransportLayer = "pandora"
)
