package main

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/google/go-github/v52/github"
)

type Scope struct {
	Repositories []string                       `json:"repositories,omitempty"`
	Permissions  github.InstallationPermissions `json:"permissions,omitempty"`
}

func NewScope() *Scope {
	return &Scope{
		Repositories: []string{},
		Permissions:  github.InstallationPermissions{},
	}
}

func (scope *Scope) isEmpty() bool {
	noPermissionSet := true
	// Get the list of fields from the struct github.InstallationPermissions
	fields := reflect.VisibleFields(reflect.TypeOf(struct{ github.InstallationPermissions }{}))

	reflectScope := reflect.ValueOf(&scope.Permissions).Elem()

	for _, field := range fields {
		value := reflectScope.FieldByName(field.Name)

		// Has this filed been set?
		if value.IsValid() && !value.IsZero() {
			// Get the value of the field as a string
			valueString := value.Elem().String()
			if valueString != "" {
				// We have at least one permission set
				noPermissionSet = false
				break
			}
		}
	}
	return scope == nil || (len(scope.Repositories) == 0 && noPermissionSet)
}

func (scope *Scope) String() string {
	kvPairs := []string{}
	// Get the list of fields from the struct github.InstallationPermissions
	fields := reflect.VisibleFields(reflect.TypeOf(struct{ github.InstallationPermissions }{}))

	reflectScope := reflect.ValueOf(&scope.Permissions).Elem()

	for _, field := range fields {
		value := reflectScope.FieldByName(field.Name)

		// Has this filed been set?
		if value.IsValid() && !value.IsZero() {
			// Get the value of the field as a string
			valueString := value.Elem().String()
			if valueString != "" {
				kvPairs = append(kvPairs, fmt.Sprintf("%s: %s", field.Name, valueString))
			}
		}
	}

	return fmt.Sprintf("{repositories: [%s], permissions: {%s}}", strings.Join(scope.Repositories, ", "), strings.Join(kvPairs, ", "))
}

func (cumulativeScope *Scope) merge(additionalScope Scope) {
	cumulativeScope.Repositories = append(cumulativeScope.Repositories, additionalScope.Repositories...)

	permissionRank := map[string]int{
		"read":  0,
		"write": 1,
		"admin": 2,
	}

	// Get the list of fields from the struct github.InstallationPermissions
	fields := reflect.VisibleFields(reflect.TypeOf(struct{ github.InstallationPermissions }{}))

	reflectCumulativeScope := reflect.ValueOf(&cumulativeScope.Permissions).Elem()
	reflectadditionalScope := reflect.ValueOf(&additionalScope.Permissions).Elem()

	for _, field := range fields {
		newValue := reflectadditionalScope.FieldByName(field.Name)

		// Has this filed been set in the additional scope?
		if newValue.IsValid() && !newValue.IsZero() {
			// Get the value of the field as a string
			newValueString := newValue.Elem().String()

			// Get the same field within the cumulative scope
			cumulativeValue := reflectCumulativeScope.FieldByName(field.Name)

			// If the cumulative scope has not been set, set it to the new value
			if !cumulativeValue.IsValid() || cumulativeValue.IsZero() {
				cumulativeValue.Set(reflect.New(newValue.Type().Elem()))
				cumulativeValue.Elem().SetString(newValueString)
			} else { // Otherwise, compare the current value with the new value and update the cumulative value if the new one provides higher permissions
				cumulativeValueString := cumulativeValue.Elem().String()

				// If the current permission is lower than the new permission, update the permission
				if permissionRank[cumulativeValueString] < permissionRank[newValueString] {
					cumulativeValue.Elem().SetString(newValueString)
				}
			}
		}
	}
}
