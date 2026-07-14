package modules

import (
	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/modules/cmdi"
	"github.com/eonedge/vulnscan/pkg/modules/csrf"
	"github.com/eonedge/vulnscan/pkg/modules/lfi"
	"github.com/eonedge/vulnscan/pkg/modules/openredirect"
	"github.com/eonedge/vulnscan/pkg/modules/sqli"
	"github.com/eonedge/vulnscan/pkg/modules/ssrf"
	"github.com/eonedge/vulnscan/pkg/modules/ssti"
	"github.com/eonedge/vulnscan/pkg/modules/xss"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// ModuleFunc is a function type that implements the scanner.Module interface
type ModuleFunc struct {
	NameValue        string
	DescriptionValue string
	ScanFunc         func(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability
}

func (m *ModuleFunc) Name() string        { return m.NameValue }
func (m *ModuleFunc) Description() string  { return m.DescriptionValue }
func (m *ModuleFunc) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	return m.ScanFunc(client, endpoint)
}

// CreateVulnerability creates a new vulnerability instance with common fields
func CreateVulnerability(vulnType, url, parameter, payload, description, evidence string, severity scanner.Severity) scanner.Vulnerability {
	return scanner.Vulnerability{
		Type:        vulnType,
		Severity:    severity,
		URL:         url,
		Parameter:   parameter,
		Payload:     payload,
		Description: description,
		Evidence:    evidence,
		Timestamp:   utils.GetCurrentTime(),
	}
}

// GetAllModules returns all available vulnerability scanning modules
func GetAllModules() []scanner.Module {
	return []scanner.Module{
		sqli.NewSQLiModule(),
		xss.NewXSSModule(),
		cmdi.NewCMDIModule(),
		csrf.NewCSRFModule(),
		lfi.NewLFIModule(),
		openredirect.NewOpenRedirectModule(),
		ssrf.NewSSRFModule(),
		ssti.NewSSTIModule(),
	}
}

// GetModuleByName returns a module by its name
func GetModuleByName(name string) scanner.Module {
	modules := GetAllModules()
	for _, module := range modules {
		if module.Name() == name {
			return module
		}
	}
	return nil
}
