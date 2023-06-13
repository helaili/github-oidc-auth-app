package main

import "fmt"

type BasicEntitlement struct {
	Actor             string `json:"actor,omitempty"`
	ActorId           int64  `json:"actor_id,omitempty"`
	Audience          string `json:"aud,omitempty"`
	BaseRef           string `json:"base_ref,omitempty"`
	EventName         string `json:"event_name,omitempty"`
	HeadRef           string `json:"head_ref,omitempty"`
	Issuer            string `json:"iss,omitempty"`
	JobWokflowRef     string `json:"job_workflow_ref,omitempty"`
	JobWokflowSha     string `json:"job_workflow_sha,omitempty"`
	Ref               string `json:"ref,omitempty"`
	RefType           string `json:"ref_type,omitempty"`
	RunAttempt        int64  `json:"run_attempt,omitempty"`
	RunId             int64  `json:"run_id,omitempty"`
	RunNumber         int64  `json:"run_number,omitempty"`
	RunnerEnvironment string `json:"runner_environment,omitempty"`
	Subject           string `json:"sub,omitempty"`
	Visibility        string `json:"repository_visibility,omitempty"`
	Workflow          string `json:"workflow,omitempty"`
	WorkflowRef       string `json:"workflow_ref,omitempty"`
	WorkflowSha       string `json:"workflow_sha,omitempty"`
	Scopes            Scope  `json:"scopes"`
}

type Entitlement struct {
	BasicEntitlement
	Environment       string `json:"environment,omitempty"`
	Repository        string `json:"repository,omitempty"`
	RepositoryId      int64  `json:"repository_id,omitempty"`
	RepositoryOwner   string `json:"repository_owner,omitempty"`
	RepositoryOwnerId int64  `json:"repository_owner_id,omitempty"`
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
