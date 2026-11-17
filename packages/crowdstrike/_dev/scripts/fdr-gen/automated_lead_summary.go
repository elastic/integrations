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
	DESCRIPTION("Pipeline for Automated Lead Summary external API events.")

	eventCategorizationFields()

	BLANK()

	messageFields()

	BLANK()

	timestampFields()

	BLANK()

	scoreFields()

	BLANK()

	threatgraphIndicatorConversions()

	BLANK()

	ecsMappings()

	BLANK()

	errorHandling()

	Generate()
}

func eventCategorizationFields() {
	SET("event.kind").
		TAG("set_event_kind_automated_lead").
		VALUE("alert")
	APPEND("event.category", "threat").
		TAG("append_event_category_threat")
	APPEND("event.type", "indicator").
		TAG("append_event_type_indicator")
}

func messageFields() {
	SET("message").
		TAG("set_message_from_name").
		COPY_FROM("crowdstrike.Name").
		IGNORE_EMPTY(true)
	SET("message").
		TAG("set_message_from_description").
		COPY_FROM("crowdstrike.Description").
		IGNORE_EMPTY(true).
		IF(`ctx.message == null || ctx.message == ''`)
}

func timestampFields() {
	for _, t := range []struct {
		field string
		tag   string
		dst   string
	}{
		{field: "SignalStartTimestamp", tag: "signal_start_timestamp", dst: "event.start"},
		{field: "SignalEndTimestamp", tag: "signal_end_timestamp", dst: "event.end"},
		{field: "SignalUpdatedTimestamp", tag: "signal_updated_timestamp"},
	} {
		src := "crowdstrike." + t.field
		DATE(src, src, "UNIX", "UNIX_MS").
			TAG("date_"+t.tag).
			IF(fmt.Sprintf(`ctx.crowdstrike?.%s != null && ctx.crowdstrike.%s != 0`, t.field, t.field)).
			ON_FAILURE(
				REMOVE(src).
					TAG("remove_"+t.tag).
					IGNORE_MISSING(true),
				APPEND("error.message", errorMessageQuoted),
			)
		if t.dst != "" {
			SET(t.dst).
				TAG(fmt.Sprintf("set_%s_from_%s", strings.ReplaceAll(t.dst, ".", "_"), t.tag)).
				COPY_FROM(src).
				IGNORE_EMPTY(true)
		}
	}

	FOREACH("crowdstrike.ThreatgraphIndicators",
		DATE("_ingest._value.SignalAssociationTimestamp", "_ingest._value.SignalAssociationTimestamp", "UNIX", "UNIX_MS").
			TAG("date_threatgraph_indicators_signal_association_timestamp").
			ON_FAILURE(
				REMOVE("_ingest._value.SignalAssociationTimestamp").
					TAG("remove_crowdstrike_threatgraph_indicators_signal_association_timestamp_array").
					IGNORE_MISSING(true),
				APPEND("error.message", errorMessageQuoted),
			),
	).
		TAG("date_crowdstrike_threatgraph_indicators_signal_association_timestamp_array").
		IF(`ctx.crowdstrike?.ThreatgraphIndicators instanceof List`)
}

func scoreFields() {
	CONVERT("", "crowdstrike.Score", "long").
		TAG("convert_score_to_long").
		IGNORE_MISSING(true).
		IF(`ctx.crowdstrike?.Score != null`).
		ON_FAILURE(
			REMOVE("crowdstrike.Score").
				TAG("remove_score").
				IGNORE_MISSING(true),
			APPEND("error.message", errorMessageQuoted),
		)
	SCRIPT().
		LANG("painless").
		TAG("set_event_risk_score_and_severity_from_score").
		IF(`ctx.crowdstrike?.Score instanceof long`).
		SOURCE(`
        long score = ctx.crowdstrike.Score;
        ctx.event = ctx.event ?: [:];
        ctx.event.risk_score = (double) score;
        if (score < 40) {
          ctx.event.severity = 21;
        } else if (score < 60) {
          ctx.event.severity = 47;
        } else if (score < 80) {
          ctx.event.severity = 73;
        } else {
          ctx.event.severity = 99;
        }
		`)
}

func threatgraphIndicatorConversions() {
	for _, c := range []struct {
		field string
		typ   string
		tag   string
	}{
		{field: "PatternId", typ: "string", tag: "pattern_id"},
		{field: "TemplateInstanceId", typ: "string", tag: "template_instance_id"},
		{field: "Severity", typ: "long", tag: "severity"},
		{field: "PatternDisposition", typ: "long", tag: "pattern_disposition"},
	} {
		conv := CONVERT("", "_ingest._value."+c.field, c.typ).
			TAG("convert_threatgraph_indicators_" + c.tag + "_to_" + c.typ).
			IGNORE_MISSING(true)
		if c.typ != "string" {
			conv.ON_FAILURE(
				REMOVE("_ingest._value."+c.field).
					TAG("remove_crowdstrike_threatgraph_indicators_"+c.tag+"_array").
					IGNORE_MISSING(true),
				APPEND("error.message", errorMessageQuoted),
			)
		}
		FOREACH("crowdstrike.ThreatgraphIndicators", conv).
			TAG("convert_threatgraph_indicators_" + c.tag + "_to_" + c.typ + "_array").
			IF(`ctx.crowdstrike?.ThreatgraphIndicators instanceof List`)
	}
}

func ecsMappings() {
	RENAME("crowdstrike.CompositeId", "event.id").
		TAG("rename_composite_id_to_event_id").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.FalconHostLink", "event.reference").
		TAG("rename_falcon_host_link").
		IGNORE_MISSING(true)

	for _, a := range []struct {
		dst   string
		value string
		tag   string
	}{
		{dst: "threat.indicator.id", value: `{{{_ingest._value.IndicatorId}}}`, tag: "indicator_id"},
		{dst: "threat.indicator.name", value: `{{{_ingest._value.DisplayName}}}`, tag: "indicator_name"},
		{dst: "threat.indicator.description", value: `{{{_ingest._value.Description}}}`, tag: "indicator_description"},
	} {
		FOREACH("crowdstrike.ThreatgraphIndicators",
			APPEND(a.dst, a.value).
				TAG("append_threat_"+a.tag).
				ALLOW_DUPLICATES(false),
		).
			TAG("foreach_threatgraph_indicators_" + a.tag).
			IF(`ctx.crowdstrike?.ThreatgraphIndicators instanceof List`)
	}

	SCRIPT().
		LANG("painless").
		TAG("set_host_and_process_from_first_threatgraph_indicator").
		IF(`ctx.crowdstrike?.ThreatgraphIndicators instanceof List && !ctx.crowdstrike.ThreatgraphIndicators.isEmpty()`).
		SOURCE(`
        def indicator = ctx.crowdstrike.ThreatgraphIndicators[0];
        if (indicator.HostId != null && indicator.HostId != '') {
          ctx.host = ctx.host ?: [:];
          ctx.host.id = indicator.HostId;
        }
        if (indicator.Hostname != null && indicator.Hostname != '') {
          ctx.host = ctx.host ?: [:];
          ctx.host.name = indicator.Hostname;
        }
        if (indicator.ProcessId != null && indicator.ProcessId != '') {
          ctx.process = ctx.process ?: [:];
          ctx.process.entity_id = indicator.ProcessId;
        }
		`)

	FOREACH("crowdstrike.ThreatgraphIndicators",
		APPEND("related.hosts", `{{{_ingest._value.Hostname}}}`).
			TAG("append_related_hosts_from_hostname").
			ALLOW_DUPLICATES(false),
	).
		TAG("foreach_threatgraph_indicators_related_hosts").
		IF(`ctx.crowdstrike?.ThreatgraphIndicators instanceof List`)
}

func errorHandling() {
	ON_FAILURE(
		APPEND("error.message", errorMessageQuoted),
		SET("event.kind").
			VALUE("pipeline_error"),
		APPEND("tags", "preserve_original_event").
			ALLOW_DUPLICATES(false),
	)
}

const errorMessageQuoted = `Processor "{{{ _ingest.on_failure_processor_type }}}" with tag "{{{ _ingest.on_failure_processor_tag }}}" in pipeline "{{{ _ingest.on_failure_pipeline }}}" failed with message "{{{ _ingest.on_failure_message }}}"`
