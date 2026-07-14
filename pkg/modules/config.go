package modules

import (
	"github.com/eonedge/vulnscan/pkg/utils"
)

// ModuleConfig holds configuration for vulnerability modules
type ModuleConfig struct {
	CustomPayloads []utils.Payload
}

// LoadCustomPayloads loads custom payloads from a file
func LoadCustomPayloads(filePath string) ([]utils.Payload, error) {
	return utils.LoadPayloadsFromFile(filePath)
}
