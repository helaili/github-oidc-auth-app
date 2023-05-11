package main

import "fmt"

type Entitlement struct {
	Actor             string `yaml:"actor,omitempty"`
	ActorId           int64  `yaml:"actor_id,omitempty"`
	Audience          string `yaml:"aud,omitempty"`
	BaseRef           string `yaml:"base_ref,omitempty"`
	Environment       string `yaml:"environment,omitempty"`
	EventName         string `yaml:"event_name,omitempty"`
	HeadRef           string `yaml:"head_ref,omitempty"`
	Issuer            string `yaml:"iss,omitempty"`
	JobWokflowRef     string `yaml:"job_workflow_ref,omitempty"`
	JobWokflowSha     string `yaml:"job_workflow_sha,omitempty"`
	Ref               string `yaml:"ref,omitempty"`
	RefType           string `yaml:"ref_type,omitempty"`
	Repository        string `yaml:"repository,omitempty"`
	RepositoryId      int64  `yaml:"repository_id,omitempty"`
	RepositoryOwner   string `yaml:"repository_owner,omitempty"`
	RepositoryOwnerId int64  `yaml:"repository_owner_id,omitempty"`
	RunAttempt        int64  `yaml:"run_attempt,omitempty"`
	RunId             int64  `yaml:"run_id,omitempty"`
	RunNumber         int64  `yaml:"run_number,omitempty"`
	RunnerEnvironment string `yaml:"runner_environment,omitempty"`
	Subject           string `yaml:"sub,omitempty"`
	Visibility        string `yaml:"repository_visibility,omitempty"`
	Workflow          string `yaml:"workflow,omitempty"`
	WorkflowRef       string `yaml:"workflow_ref,omitempty"`
	WorkflowSha       string `yaml:"workflow_sha,omitempty"`
	Scopes            Scope  `yaml:"scopes"`
}

func (e Entitlement) regexString() string {
	return "^actor:" + e.stringFieldValue(e.Actor) +
		",actor_id:" + e.numericFieldValue(e.ActorId) +
		",aud:" + e.stringFieldValue(e.Audience) +
		",base_ref:" + e.stringFieldValue(e.BaseRef) +
		",environment:" + e.stringFieldValue(e.Environment) +
		",event_name:" + e.stringFieldValue(e.EventName) +
		",head_ref:" + e.stringFieldValue(e.HeadRef) +
		",iss:" + e.stringFieldValue(e.Issuer) +
		",job_workflow_ref:" + e.stringFieldValue(e.JobWokflowRef) +
		",job_workflow_sha:" + e.stringFieldValue(e.JobWokflowSha) +
		",ref:" + e.stringFieldValue(e.Ref) +
		",ref_type:" + e.stringFieldValue(e.RefType) +
		",repository:" + e.stringFieldValue(e.Repository) +
		",repository_id:" + e.numericFieldValue(e.RepositoryId) +
		",repository_owner:" + e.stringFieldValue(e.RepositoryOwner) +
		",repository_owner_id:" + e.numericFieldValue(e.RepositoryOwnerId) +
		",repository_visibility:" + e.stringFieldValue(e.Visibility) +
		",run_attempt:" + e.numericFieldValue(e.RunAttempt) +
		",run_id:" + e.numericFieldValue(e.RunId) +
		",run_number:" + e.numericFieldValue(e.RunNumber) +
		",runner_environment:" + e.stringFieldValue(e.RunnerEnvironment) +
		",sub:" + e.stringFieldValue(e.Subject) +
		",workflow:" + e.stringFieldValue(e.Workflow) +
		",workflow_ref:" + e.stringFieldValue(e.WorkflowRef) +
		",workflow_sha:" + e.stringFieldValue(e.WorkflowSha) +
		"$"
}

func (e Entitlement) stringFieldValue(value string) string {
	if value == "" {
		return ".*"
	} else {
		return value
	}
}

func (e Entitlement) numericFieldValue(value int64) string {
	if value == 0 {
		return ".*"
	} else {
		return fmt.Sprint(value)
	}
}
