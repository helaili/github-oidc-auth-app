package main

type Scope struct {
	Repositories []string          `yaml:"repositories,omitempty"`
	Permissions  map[string]string `yaml:"permissions,omitempty"`
}

func NewScope() *Scope {
	return &Scope{
		Repositories: []string{},
		Permissions:  make(map[string]string),
	}
}

func (cumulativeScope *Scope) merge(newScope Scope) {
	cumulativeScope.Repositories = append(cumulativeScope.Repositories, newScope.Repositories...)
	permissionRank := map[string]int{
		"read":  0,
		"write": 1,
		"admin": 2,
	}

	for key, value := range newScope.Permissions {
		if cumulativeScope.Permissions[key] == "" {
			cumulativeScope.Permissions[key] = value
		} else {
			// If the current permission is lower than the new permission, update the permission
			if permissionRank[cumulativeScope.Permissions[key]] < permissionRank[value] {
				cumulativeScope.Permissions[key] = value
			}
		}
	}
}
