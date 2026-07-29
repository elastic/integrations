package main

import (
	"fmt"

	. "github.com/efd6/dispear"
)

func main() {
	DESCRIPTION("Pipeline for processing Cloud Security Posture's IOA events.")

	categorization()

	BLANK()

	converts()

	BLANK()

	ecsMappings()

	BLANK()

	cleanup()

	Generate()

}

func categorization() {
	BLANK().COMMENT("Event categorization")

	SET("event.kind").
		TAG("set_event_kind_alert").
		VALUE("alert")
	APPEND("event.category", "configuration").
		TAG("append_event_category_configuration")
	APPEND("event.type", []string{"info", "change"}).
		TAG("append_info_change_type")
}

func converts() {
	BLANK().COMMENT("Converts")

	for _, change := range []struct {
		src string
		typ string
	}{
		{src: "crowdstrike.policy_severity", typ: "long"},
		{src: "crowdstrike.source_ip_address", typ: "ip"},
		{src: "crowdstrike.user_identity_mfa_authenticated", typ: "boolean"},
		{src: "crowdstrike.read_only", typ: "boolean"},
		{src: "crowdstrike.management_event", typ: "boolean"},
	} {
		CONVERT("", change.src, change.typ).
			IGNORE_MISSING(true).
			ON_FAILURE(
				REMOVE(change.src).
					IGNORE_FAILURE(true),
				APPEND("error.message", errorMessage),
			)
	}
	CONVERT("", "crowdstrike.policy_id", "string").
		IGNORE_MISSING(true)

	DATE("event.created", "crowdstrike.event_created", "ISO8601").
		IF(`ctx.crowdstrike?.event_created != null && ctx.crowdstrike.event_created != ''`).
		ON_FAILURE(
			APPEND("error.message", errorMessage),
		)
}

func ecsMappings() {
	BLANK().COMMENT("ECS mappings")

	for _, copy := range []struct {
		src string
		dst string
	}{
		{src: "event.created", dst: "@timestamp"},
		{src: "crowdstrike.policy_statement", dst: "rule.name"},
	} {
		SET(copy.dst).
			TAG(fmt.Sprintf("set_%s_from_%s", copy.dst, copy.src)).
			COPY_FROM(copy.src).
			IGNORE_EMPTY(true)
	}

	for _, change := range []struct {
		from string
		to   string
	}{
		{from: "crowdstrike.event_id", to: "event.id"},
		{from: "crowdstrike.event_name", to: "event.action"},
		{from: "crowdstrike.event_source", to: "source.domain"},
		{from: "crowdstrike.user_identity_principal_id", to: "user.id"},
		{from: "crowdstrike.user_identity_user_name", to: "user.name"},
		{from: "crowdstrike.policy_description", to: "rule.description"},
		{from: "crowdstrike.policy_statement", to: "message"},
		{from: "crowdstrike.cloud_provider", to: "cloud.provider"},
		{from: "crowdstrike.policy_id", to: "rule.id"},
		{from: "crowdstrike.source_ip_address", to: "source.ip"},
		{from: "crowdstrike.cloud_service_friendly", to: "cloud.service.name"},
		{from: "crowdstrike.account", to: "cloud.account.id"},
		{from: "crowdstrike.cloud_region", to: "cloud.region"},
	} {
		RENAME(change.from, change.to).
			IGNORE_MISSING(true)
	}

	APPEND("threat.tactic.name", `{{{crowdstrike.mitre_attack_tactic}}}`).
		IF(`ctx.crowdstrike?.mitre_attack_tactic != null`).
		ALLOW_DUPLICATES(false)
	APPEND("threat.technique.name", `{{{crowdstrike.mitre_attack_technique}}}`).
		IF(`ctx.crowdstrike?.mitre_attack_technique != null`).
		ALLOW_DUPLICATES(false)

	USER_AGENT("", "crowdstrike.user_agent").
		IGNORE_MISSING(true)

	SCRIPT().
		COMMENT("Override severity set in default.yml as Cloud Security has a different range.").
		TAG("set_severity_name_from_crowdstrike_policy_severity").
		IF(`ctx.crowdstrike?.policy_severity instanceof long`).
		SOURCE(`
		  long severity = ctx.crowdstrike.policy_severity;
		  if (severity == 0) {
		    ctx.crowdstrike.SeverityName = 'critical';
		  } else if (severity == 1) {
		    ctx.crowdstrike.SeverityName = 'high';
		  } else if (severity == 2) {
		    ctx.crowdstrike.SeverityName = 'medium';
		  } else if (severity == 3) {
		    ctx.crowdstrike.SeverityName = 'informational';
		  }
		`)
	SCRIPT().
		TAG("set_event_severity_from_severity_name").
		IF(`ctx.crowdstrike?.SeverityName instanceof String && ctx.crowdstrike.SeverityName != ''`).
		PARAMS(map[string]any{
			"low":           21,
			"info":          21,
			"informational": 21,
			"medium":        47,
			"high":          73,
			"critical":      99,
		}).
		SOURCE(`
		  ctx.event = ctx.event ?: [:];
		  Integer score = params[ctx.crowdstrike.SeverityName.toLowerCase()];
		  if (score != null) {
		    ctx.event.severity = score;
		  }
		`)
}

func cleanup() {
	BLANK().COMMENT("Cleanup.")

	REMOVE(
		"crowdstrike.mitre_attack_tactic",
		"crowdstrike.mitre_attack_technique",
		"crowdstrike.event_created",
		"crowdstrike.user_agent",
	).IGNORE_MISSING(true)

	BLANK()

	BLANK().COMMENT("error handling")

	SET("event.kind").
		TAG("set_pipeline_error_into_event_kind").
		IF(`ctx.error?.message != null`).
		VALUE("pipeline_error")
	APPEND("tags", "preserve_original_event").
		TAG("append_preserve_original_event_into_tags").
		IF(`ctx.error?.message != null`).
		ALLOW_DUPLICATES(false)

	ON_FAILURE(
		SET("event.kind").VALUE("pipeline_error"),
		APPEND("tags", "preserve_original_event").ALLOW_DUPLICATES(false),
		APPEND("error.message", errorMessage),
	)
}

const errorMessage = `Processor {{{_ingest.on_failure_processor_type}}} with tag {{{_ingest.on_failure_processor_tag}}} in pipeline {{{_ingest.on_failure_pipeline}}} failed with message: {{{_ingest.on_failure_message}}}`
