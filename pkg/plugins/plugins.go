package plugins

import (
	"fmt"
	"plugin"
	"sync"

	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// Plugin represents a loaded plugin module
type Plugin struct {
	Name        string
	Description string
	Path        string
	Module      scanner.Module
}

// PluginManager manages loading and accessing plugins
type PluginManager struct {
	plugins map[string]*Plugin
	mu      sync.RWMutex
	logger  *utils.Logger
}

// NewPluginManager creates a new plugin manager
func NewPluginManager() *PluginManager {
	return &PluginManager{
		plugins: make(map[string]*Plugin),
		logger:  utils.NewLogger(utils.INFO, "PLUGIN"),
	}
}

// LoadPlugin loads a plugin from a shared library file
func (pm *PluginManager) LoadPlugin(path string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.logger.Info("Loading plugin from %s", path)

	// Open the plugin
	p, err := plugin.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open plugin %s: %w", path, err)
	}

	// Look up the Module symbol
	symModule, err := p.Lookup("Module")
	if err != nil {
		return fmt.Errorf("plugin %s does not export 'Module' symbol: %w", path, err)
	}

	// Assert that the symbol implements the Module interface
	module, ok := symModule.(scanner.Module)
	if !ok {
		return fmt.Errorf("plugin %s 'Module' does not implement scanner.Module interface", path)
	}

	// Register the plugin
	plugin := &Plugin{
		Name:        module.Name(),
		Description: module.Description(),
		Path:        path,
		Module:      module,
	}

	pm.plugins[module.Name()] = plugin
	pm.logger.Info("Loaded plugin: %s (%s)", module.Name(), module.Description())

	return nil
}

// LoadPlugins loads multiple plugins from a directory
func (pm *PluginManager) LoadPlugins(dir string) error {
	// This would scan a directory for .so files and load them
	// For now, we'll just log that we're looking for plugins
	pm.logger.Info("Looking for plugins in %s", dir)
	return nil
}

// GetPlugin returns a plugin by name
func (pm *PluginManager) GetPlugin(name string) (*Plugin, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	plugin, exists := pm.plugins[name]
	return plugin, exists
}

// GetAllPlugins returns all loaded plugins
func (pm *PluginManager) GetAllPlugins() []*Plugin {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	plugins := make([]*Plugin, 0, len(pm.plugins))
	for _, p := range pm.plugins {
		plugins = append(plugins, p)
	}
	return plugins
}

// GetModules returns all plugin modules as scanner.Module slice
func (pm *PluginManager) GetModules() []scanner.Module {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	modules := make([]scanner.Module, 0, len(pm.plugins))
	for _, p := range pm.plugins {
		modules = append(modules, p.Module)
	}
	return modules
}

// UnloadPlugin unloads a plugin by name
func (pm *PluginManager) UnloadPlugin(name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.plugins[name]; !exists {
		return fmt.Errorf("plugin %s not found", name)
	}

	delete(pm.plugins, name)
	pm.logger.Info("Unloaded plugin: %s", name)

	return nil
}
