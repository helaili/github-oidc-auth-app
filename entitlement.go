package main

type Entitlement struct {
	Actor       string `yaml:"actor,omitempty"`
	Environment string `yaml:"environment,omitempty"`
	EventName   string `yaml:"event_name,omitempty"`
	Ref         string `yaml:"ref,omitempty"`
	Repository  string `yaml:"repository,omitempty"`
	Owner       string `yaml:"repository_owner,omitempty"`
	Visibility  string `yaml:"repository_visibility,omitempty"`
	Workflow    string `yaml:"workflow,omitempty"`
	Scopes      Scope  `yaml:"scopes"`
}

func (e Entitlement) regexString() string {
	return "^actor:" + e.fieldValue(e.Actor) +
		",environment:" + e.fieldValue(e.Environment) +
		",event_name:" + e.fieldValue(e.EventName) +
		",ref:" + e.fieldValue(e.Ref) +
		",repository:" + e.fieldValue(e.Repository) +
		",repository_owner:" + e.fieldValue(e.Owner) +
		",repository_visibility:" + e.fieldValue(e.Visibility) +
		",workflow:" + e.fieldValue(e.Workflow) +
		"$"
}

func (e Entitlement) fieldValue(value string) string {
	if value == "" {
		return ".*"
	} else {
		return value
	}
}
