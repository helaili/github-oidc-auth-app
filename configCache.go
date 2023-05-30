package main

import (
	"strings"
	"sync"
)

type ConfigCache struct {
	cache map[string]*EntitlementConfig
	mu    sync.Mutex
}

func NewConfigCache() *ConfigCache {
	return &ConfigCache{make(map[string]*EntitlementConfig), sync.Mutex{}}
}

func (configCache *ConfigCache) GetConfig(login string) *EntitlementConfig {
	configCache.mu.Lock()
	defer configCache.mu.Unlock()
	return configCache.cache[strings.ToUpper(login)]
}

func (configCache *ConfigCache) SetConfig(login string, config *EntitlementConfig) {
	configCache.mu.Lock()
	defer configCache.mu.Unlock()
	configCache.cache[strings.ToUpper(login)] = config
}
