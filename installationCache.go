package main

import (
	"strings"
	"sync"
)

type InstallationCache struct {
	cache map[string]int64
	mu    sync.Mutex
}

func NewInstallationCache() *InstallationCache {
	return &InstallationCache{make(map[string]int64), sync.Mutex{}}
}

func (ic *InstallationCache) GetInstallationId(login string) int64 {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	return ic.cache[strings.ToUpper(login)]
}

func (ic *InstallationCache) SetInstallationId(login string, installationID int64) {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	ic.cache[strings.ToUpper(login)] = installationID
}
