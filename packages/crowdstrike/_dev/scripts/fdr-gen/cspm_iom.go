// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"strings"

	. "github.com/efd6/dispear"
)

func main() {
	DESCRIPTION("Pipeline for processing Cloud Security Posture's IOM and CloudSecurityIOMEvaluation events.")

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
	BLANK().COMMENT("Handle passed CloudSecurityIOMEvaluation events.")
	SET("event.kind").
		TAG("set_event_kind_event").
		IF(`ctx.crowdstrike?.status != null && ctx.crowdstrike.status.equalsIgnoreCase('Passed')`).
		VALUE("event")
	APPEND("event.category", "configuration").
		TAG("append_event_category_configuration")
	APPEND("event.type", []string{"info"}).
		TAG("append_info_type")
}

func converts() {
	BLANK().COMMENT("Converts")

	for _, change := range []struct {
		src string
		typ string
	}{
		{src: "crowdstrike.Severity", typ: "integer"},
		{src: "crowdstrike.cloud_asset_type", typ: "long"},
		{src: "crowdstrike.legacyPolicyId", typ: "long"},
		{src: "crowdstrike.resource.legacyPolicyId", typ: "long"},
		{src: "crowdstrike.revision", typ: "long"},
		{src: "crowdstrike.policy_severity", typ: "long"},
		{src: "crowdstrike.internal_only", typ: "boolean"},
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

	for _, src := range []string{
		"crowdstrike.ResourceCreateTime",
		"crowdstrike.created",
		"crowdstrike.firstDetected",
		"crowdstrike.lastDetected",
		"crowdstrike.resource.captured",
	} {
		DATE(src, src, "ISO8601").
			IF(fmt.Sprintf(`ctx.%s != null && ctx.%s != ''`, safeDotted(src), src)).
			ON_FAILURE(
				APPEND("error.message", errorMessage),
			)
	}

	JSON("crowdstrike.ResourceAttributes", "crowdstrike.ResourceAttributes").
		TAG("decode_crowdstrike_ResourceAttributes").
		IF(`ctx.crowdstrike?.ResourceAttributes instanceof String`).
		ON_FAILURE(
			REMOVE("crowdstrike.ResourceAttributes").
				IGNORE_MISSING(true),
		)
}

func ecsMappings() {
	BLANK().COMMENT("ECS mappings")

	for _, copy := range []struct {
		src string
		dst string
	}{
		{src: "crowdstrike.created", dst: "@timestamp"},
		{src: "crowdstrike.policy_statement", dst: "rule.name"},
	} {
		SET(copy.dst).
			TAG(fmt.Sprintf("set_%s_from_%s", copy.dst, copy.src)).
			COPY_FROM(copy.src).
			IGNORE_EMPTY(true)
	}

	BLANK()
	BLANK().COMMENT("Renames")
	for _, change := range []struct {
		from string
		to   string
	}{
		{from: "crowdstrike.severity", to: "crowdstrike.SeverityName"},
		{from: "crowdstrike.policy_statement", to: "message"},
	} {
		RENAME(change.from, change.to).
			IGNORE_MISSING(true)
	}

	SET("message").
		TAG("set_message_from_crowdstrike_ruleName").
		COMMENT("CloudSecurityIOMEvaluation events use `ruleName`").
		COPY_FROM("crowdstrike.ruleName").
		IGNORE_EMPTY(true)

	for _, copy := range []struct {
		src string
		dst string
	}{
		{src: "crowdstrike.mitre_attack_tactics_name", dst: "threat.tactic.name"},
		{src: "crowdstrike.mitre_attack_tactics_url", dst: "threat.tactic.reference"},
		{src: "crowdstrike.threat.tactic.name", dst: "threat.tactic.name"},
		{src: "crowdstrike.threat.tactic.id", dst: "threat.tactic.id"},
		{src: "crowdstrike.threat.tactic.reference", dst: "threat.tactic.reference"},
		{src: "crowdstrike.threat.technique.name", dst: "threat.technique.name"},
		{src: "crowdstrike.threat.technique.id", dst: "threat.technique.id"},
		{src: "crowdstrike.threat.technique.reference", dst: "threat.technique.reference"},
	} {
		APPEND(copy.dst, fmt.Sprintf(`{{{%s}}}`, copy.src)).
			TAG(fmt.Sprintf("append_%s_from_%s", copy.dst, copy.src)).
			IF(fmt.Sprintf(`ctx.%s != null`, safeDotted(copy.src))).
			ALLOW_DUPLICATES(false)
	}

	for _, change := range []struct {
		from    string
		to      string
		cond    string
		comment string
	}{
		{from: "crowdstrike.cloudplatform", to: "cloud.provider", comment: "CloudSecurityIOMEvaluation events use `resource.cloudProvider`, IOM events use `cloudplatform`"},
		{from: "crowdstrike.resource.cloudProvider", to: "cloud.provider", cond: `ctx.cloud?.provider == null`},
		{from: "crowdstrike.policy_id", to: "rule.id", comment: "CloudSecurityIOMEvaluation events use `ruleId`, IOM events use `policy_id`"},
		{from: "crowdstrike.ruleId", to: "rule.id", cond: `ctx.rule?.id == null`},
		{from: "crowdstrike.ruleName", to: "rule.name", cond: `ctx.rule?.name == null`},
		{from: "crowdstrike.CloudService", to: "cloud.service.name"},
		{from: "crowdstrike.AccountId", to: "cloud.account.id", comment: "CloudSecurityIOMEvaluation events use `resource.accountId`, IOM events use `AccountId`"},
		{from: "crowdstrike.resource.accountId", to: "cloud.account.id", cond: `ctx.cloud?.account?.id == null`},
		{from: "crowdstrike.region", to: "cloud.region", comment: "CloudSecurityIOMEvaluation events use `resource.region`, IOM events use `region`"},
		{from: "crowdstrike.resource.region", to: "cloud.region", cond: `ctx.cloud?.region == null`},
	} {
		r := RENAME(change.from, change.to).
			IGNORE_MISSING(true)
		if change.cond != "" {
			r.IF(change.cond)
		}
		if change.comment != "" {
			r.COMMENT(change.comment)
		}
		APPEND(change.to, fmt.Sprintf(`{{{%s}}}`, change.from)).
			TAG(fmt.Sprintf("append_%s_from_%s", change.to, change.from)).
			IF(fmt.Sprintf(`ctx.%s != null`, safeDotted(change.from))).
			ALLOW_DUPLICATES(false)
	}

	SCRIPT().
		COMMENT("Override severity set in default.yml as Cloud Security has a different range.").
		TAG("set_severity_name_from_crowdstrike_Severity").
		IF(`ctx.crowdstrike?.Severity instanceof int`).
		SOURCE(`
		  int severity = ctx.crowdstrike.Severity;
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

	BLANK()

	SCRIPT().
		TAG("parse_all_benchmark_ids_to_list").
		DESCRIPTION("Parse all benchmark IDs and create a list.").
		SOURCE(`
		  for (entry in ctx.crowdstrike.entrySet()) {
		    def key = entry.getKey().toString();
		    if (key.endsWith("benchmark_ids")) {
		      def val = entry.getValue();
		      if (val instanceof String) {
		        def result = [];
		        String cleaned = /[\\{\\}\\s]/.matcher(val).replaceAll('');
		        def parts = cleaned.splitOnToken(",");
		        for (def part : parts) {
		          result.add(part);
		        }
		        ctx.crowdstrike[key] = result;
		      }
		    }
		  }
		`)
}

func safeDotted(s string) string {
	return strings.ReplaceAll(s, ".", "?.")
}

func cleanup() {
	BLANK().COMMENT("Cleanup.")

	REMOVE(
		"crowdstrike.Disposition",
		"crowdstrike.Finding",
		"crowdstrike.CloudPlatform",
		"crowdstrike.PolicyId",
		"crowdstrike.PolicyStatement",
		"crowdstrike.Region",
		"crowdstrike.ResourceUrl",
		"crowdstrike.mitre_attack_tactics_name",
		"crowdstrike.mitre_attack_tactics_url",
		"crowdstrike.threat.framework",
		"crowdstrike.threat.technique.id",
		"crowdstrike.threat.technique.name",
		"crowdstrike.threat.technique.reference",
		"crowdstrike.threat.tactic.id",
		"crowdstrike.threat.tactic.name",
		"crowdstrike.threat.tactic.reference",
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
