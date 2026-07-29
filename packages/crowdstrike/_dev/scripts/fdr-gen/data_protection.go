package main

import (
	"fmt"

	. "github.com/efd6/dispear"
)

func main() {
	DESCRIPTION("Pipeline for processing Data Protection Detection Summary events.")

	BLANK()

	eventCategorizationFields()

	BLANK()

	fieldTypeConversions()

	BLANK()

	timestampFields()

	BLANK()

	ecsMappings()

	BLANK()

	cleanup()

	BLANK()

	errorHandling()

	Generate()
}

func eventCategorizationFields() {
	BLANK().COMMENT("event categorization fields")

	SET("event.kind").
		TAG("set event kind to alert").
		VALUE("alert")
	APPEND("event.category", "malware").
		TAG("append malware category")
	APPEND("event.type", "info").
		TAG("append info type")

}

func fieldTypeConversions() {
	BLANK().COMMENT("converts")

	for _, src := range []struct {
		field  string
		typ    string
		remove bool
	}{
		{field: "crowdstrike.DataVolume", typ: "long", remove: false},
		{field: "crowdstrike.ContentPatterns.ConfidenceLevel", typ: "long", remove: true},
		{field: "crowdstrike.ContentPatterns.MatchCount", typ: "long", remove: true},
		{field: "crowdstrike.FilesEgressedCount", typ: "long", remove: true},
		{field: "crowdstrike.UserNotified", typ: "boolean", remove: true},
		{field: "crowdstrike.UserMapped", typ: "boolean", remove: true},
		{field: "crowdstrike.IsClipboard", typ: "boolean", remove: true},
	} {
		CONVERT("", src.field, src.typ).
			IGNORE_MISSING(true).
			ON_FAILURE(
				errorHandlers(src.remove, src.field)...,
			)
	}
}

func errorHandlers(remove bool, f string) []Renderer {
	var h []Renderer
	if remove {
		h = []Renderer{REMOVE(f)}
	}
	return append(h, APPEND("error.message", errorMessage))
}

func timestampFields() {
	BLANK().COMMENT("timestamps")

	for _, time := range []struct {
		src     string
		dst     string
		comment string
	}{
		{src: "EventTimestamp", dst: "crowdstrike.EventTimestamp"},
		{src: "SessionStartTimestamp", dst: "event.start", comment: "Anomaly-based detections contains SessionStartTimestamp and SessionEndTimestamp fields"},
		{src: "SessionEndTimestamp", dst: "event.end"},
	} {
		d := DATE(time.dst, "crowdstrike."+time.src, "UNIX").
			IF(fmt.Sprintf(`ctx.crowdstrike?.%s != null`, time.src)).
			TIMEZONE("UTC").ON_FAILURE(
			APPEND("error.message", errorMessage),
		)
		if time.comment != "" {
			d.COMMENT(time.comment)
		}
	}

	SCRIPT().
		TAG("script to set event duration").
		DESCRIPTION("Determine event.duration from event start and end date.").
		IF(`ctx.event?.start != null && ctx.event.end != null`).
		SOURCE(`
          Instant event_start = ZonedDateTime.parse(ctx.event.start).toInstant();
          Instant event_end = ZonedDateTime.parse(ctx.event.end).toInstant();
          ctx.event['duration'] = ChronoUnit.NANOS.between(event_start, event_end);
		`).
		ON_FAILURE(
			APPEND("error.message", errorMessage),
		)
}

func ecsMappings() {
	BLANK().COMMENT("ECS mappings")

	SET("threat.framework").
		VALUE("MITRE ATT&CK")

	for _, field := range []struct {
		value string
		cond  string
	}{
		{cond: "allowed", value: "success"},
		{cond: "blocked", value: "failure"},
		{value: "unknown"},
	} {
		s := SET("event.outcome").
			TAG(fmt.Sprintf("set event.outcome %s", field.value)).
			VALUE(field.value)
		if field.cond != "" {
			s.IF(fmt.Sprintf(`ctx.crowdstrike?.ResponseAction == '%s'`, field.cond))
		} else {
			s.OVERRIDE(false)
		}
	}

	for _, copy := range []struct {
		src string
		dst string
	}{
		{src: "crowdstrike.Description", dst: "message"},
		{src: "crowdstrike.Name", dst: "event.action"},
		{src: "crowdstrike.FalconHostLink", dst: "event.reference"},
		{src: "crowdstrike.ContentSha", dst: "file.hash.sha256"},
		{src: "crowdstrike.Filename", dst: "file.name"},
		{src: "crowdstrike.DataVolume", dst: "file.size"},
		{src: "crowdstrike.Hostname", dst: "host.name"},
		{src: "crowdstrike.Policy.ID", dst: "rule.id"},
		{src: "crowdstrike.Policy.Name", dst: "rule.name"},
		{src: "crowdstrike.UserSid", dst: "user.id"},
		{src: "crowdstrike.UserName", dst: "user.name"},
	} {
		SET(copy.dst).
			TAG(fmt.Sprintf("set %s from %s", copy.dst, copy.src)).
			COPY_FROM(copy.src).
			IGNORE_EMPTY(true)
	}

	APPEND("related.hash", `{{{file.hash.sha256}}}`).
		TAG("append file hash sha256 to related hash").
		IF(`ctx.file?.hash?.sha256 != null`)

	SCRIPT().
		TAG(`extract file extension from filename`).
		IF(`ctx.crowdstrike?.Filename != null`).
		SOURCE(`
          def idx = ctx.crowdstrike.Filename.lastIndexOf('.');
          if (idx != -1) {
            ctx.file = ctx.file ?: [:];
            ctx.file.extension = ctx.crowdstrike.Filename.substring(idx + 1).toLowerCase();
          }
		`).
		ON_FAILURE(
			APPEND("error.message", errorMessage),
		)

	LOWERCASE("host.os.platform", "crowdstrike.Platform").
		IGNORE_MISSING(true)

	for _, copy := range []struct {
		dst string
		src string
	}{
		{dst: "threat.tactic.name", src: "Tactic"},
		{dst: "threat.tactic.id", src: "TacticID"},
		{dst: "threat.technique.name", src: "Technique"},
		{dst: "threat.technique.id", src: "TechniqueID"},
	} {
		FOREACH("crowdstrike.MitreAttack",
			APPEND(copy.dst, fmt.Sprintf(`{{{_ingest._value.%s}}}`, copy.src)).
				TAG(fmt.Sprintf("append crowdstrike.MitreAttack.%s into %s", copy.dst, copy.src)).
				ALLOW_DUPLICATES(false),
		).
			TAG(fmt.Sprintf("foreach of crowdstrike.MitreAttack for %s", copy.src)).
			IF(`ctx.crowdstrike?.MitreAttack instanceof List`)
	}
}

func cleanup() {
	BLANK().COMMENT("clean up")

	REMOVE(
		"crowdstrike.ContentSha",
		"crowdstrike.DataVolume",
		"crowdstrike.Description",
		"crowdstrike.EgressEventId",
		"crowdstrike.FalconHostLink",
		"crowdstrike.Filename",
		"crowdstrike.Hostname",
		"crowdstrike.MitreAttack",
		"crowdstrike.Name",
		"crowdstrike.Platform",
		"crowdstrike.Policy",
		"crowdstrike.SessionStartTimestamp",
		"crowdstrike.SessionEndTimestamp",
		"crowdstrike.Tactic",
		"crowdstrike.TacticId",
		"crowdstrike.Technique",
		"crowdstrike.TechniqueId",
		"crowdstrike.UserSid",
		"crowdstrike.UserName",
	).
		TAG("remove custom duplicate fields").
		IGNORE_MISSING(true)
}

func errorHandling() {
	BLANK().COMMENT("error handling")

	SET("event.kind").
		TAG("set pipeline error into event.kind").
		IF(`ctx.error?.message != null`).
		VALUE("pipeline_error")
	APPEND("tags", "preserve_original_event").
		TAG("append preserve_original_event into tags").
		IF(`ctx.error?.message != null`).
		ALLOW_DUPLICATES(false)

	ON_FAILURE(
		APPEND("error.message", `Processor '{{{ _ingest.on_failure_processor_type }}}' `+
			`{{{#_ingest.on_failure_processor_tag}}}with tag '{{{ _ingest.on_failure_processor_tag }}}' `+
			`{{{/_ingest.on_failure_processor_tag}}}failed with message '{{{ _ingest.on_failure_message }}}'`,
		),
		SET("event.kind").
			TAG("set pipeline error into event.kind").
			VALUE("pipeline_error"),
		APPEND("tags", "preserve_original_event").
			TAG("append preserve_original_event into tags").
			ALLOW_DUPLICATES(false),
	)
}

const errorMessage = `Processor {{{_ingest.on_failure_processor_type}}} with tag {{{_ingest.on_failure_processor_tag}}} in pipeline {{{_ingest.on_failure_pipeline}}} failed with message: {{{_ingest.on_failure_message}}}`
