// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"

	. "github.com/efd6/dispear"
)

func main() {
	DESCRIPTION("Pipeline for processing FileIntegrityMonitorRuleMatched and FileIntegrityMonitorRuleMatchedEnriched events from Falcon FileVantage.")

	BLANK()

	eventCategorizationFields()

	BLANK()

	fieldValueMappings()

	BLANK()

	fieldTypeConversions()

	BLANK()

	timestampFields()

	BLANK()

	ecsMappings()

	BLANK()

	renameEventHandling()

	BLANK()

	FileIntegrityMonitorRuleMatchedRenames()
	BLANK()

	cleanup()

	BLANK()

	errorHandling()

	Generate()
}

func fieldValueMappings() {
	BLANK().COMMENT("field values mapping")

	SCRIPT().
		TAG("script set object type").
		IF(`ctx.crowdstrike?.ObjectType != null`).
		PARAMS(map[string]any{
			"obj_types": map[string]any{
				"1": "FILE",
				"2": "FOLDER",
				"3": "VALUE",
				"4": "KEY",
			}}).
		SOURCE(`
		def type = params.get('obj_types')[ctx.crowdstrike.ObjectType];
		if (type != null) {
			ctx.crowdstrike.ObjectType = type;
		}
		`).
		ON_FAILURE(
			APPEND("error.message", errorMessage),
		)
	SCRIPT().
		TAG("script set operation type").
		IF(`ctx.crowdstrike?.ObjectAccessOperationType != null`).
		PARAMS(map[string]any{
			"op_types": map[string]any{
				"1": "CREATE",
				"2": "WRITE",
				"3": "DELETE",
				"4": "SET",
				"5": "RENAME",
				"6": "ATTRIBUTES_CHANGED",
				"7": "PERMISSIONS_CHANGED",
				"8": "OPEN_WRITE",
			}}).
		SOURCE(`
		def type = params.get('op_types')[ctx.crowdstrike.ObjectAccessOperationType];
		if (type != null) {
			ctx.crowdstrike.ObjectAccessOperationType = type;
		}
		`).
		ON_FAILURE(
			APPEND("error.message", errorMessage),
		)
}

func eventCategorizationFields() {
	BLANK().COMMENT("event categorization fields")

	SET("event.kind").
		TAG("set event kind to event").
		VALUE("event")
	APPEND("event.category", "file").
		TAG("append file to event category").
		IF("ctx.crowdstrike?.ObjectType != null && (ctx.crowdstrike.ObjectType == '1' || ctx.crowdstrike.ObjectType == '2')").
		ALLOW_DUPLICATES(false)
	APPEND("event.category", "registry").
		TAG("append registry to event category").
		IF("ctx.crowdstrike?.ObjectType != null && (ctx.crowdstrike.ObjectType == '3' || ctx.crowdstrike.ObjectType == '4')").
		ALLOW_DUPLICATES(false)
	BLANK().COMMENT("fall back to file category for Enriched events")
	APPEND("event.category", "file").
		TAG("append file to event category").
		IF("ctx.event.category == null")

	SCRIPT().
		TAG("script set event type").
		IF(`ctx.crowdstrike?.ObjectAccessOperationType != null`).
		PARAMS(map[string]any{
			"op_types": map[string]any{
				"1": "creation",
				"2": "change",
				"3": "deletion",
				"4": "change",
				"5": "change",
				"6": "change",
				"7": "change",
				"8": "access",
			}}).
		SOURCE(`
          def type = params.get('op_types')[ctx.crowdstrike.ObjectAccessOperationType];
          if (type != null) {
            ctx.event = ctx.event ?: [:];
            ctx.event.type = [type];
          }
		`).
		ON_FAILURE(
			APPEND("error.message", errorMessage),
		)
	BLANK().COMMENT("fall back to change type for Enriched events")
	APPEND("event.type", "change").
		TAG("append change to event type").
		IF("ctx.event.type == null")
}

func fieldTypeConversions() {
	BLANK().COMMENT("converts")

	for _, src := range []struct {
		field  string
		typ    string
		remove bool
	}{
		{field: "crowdstrike.ContentDiff.Exists", typ: "boolean", remove: true},
		{field: "crowdstrike.Suppression.Suppressed", typ: "boolean", remove: true},
		{field: "crowdstrike.PolicyRuleSeverity", typ: "long", remove: true},
		{field: "crowdstrike.FileSize", typ: "long", remove: false},
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
		src string
		dst string
	}{
		{src: "RuleModifiedTimeStamp", dst: "crowdstrike.RuleModifiedTimeStamp"},
	} {
		DATE(time.dst, "crowdstrike."+time.src, "UNIX", "UNIX_MS").
			IF(fmt.Sprintf(`ctx.crowdstrike?.%s != null && ctx.crowdstrike.%s != ''`, time.src, time.src)).
			TIMEZONE("UTC").ON_FAILURE(
			errorHandlers(true, "crowdstrike."+time.src)...,
		)
	}
}

func ecsMappings() {
	BLANK().COMMENT("ECS mappings")

	for _, copy := range []struct {
		src string
		dst string
	}{
		{src: "crowdstrike.User.ID", dst: "user.id"},
		{src: "crowdstrike.User.Name", dst: "user.name"},
		{src: "crowdstrike.Host.Name", dst: "host.hostname"},
		{src: "crowdstrike.Policy.RuleBasePath", dst: "rule.name"},
		{src: "crowdstrike.Policy.RuleGroupName", dst: "rule.ruleset"},
		{src: "crowdstrike.ContentDiff.SHA256", dst: "file.hash.sha256"},
		{src: "crowdstrike.PolicyRuleID", dst: "rule.id"},
		{src: "crowdstrike.PolicyRuleGroupID", dst: "rule.ruleset"},
		{src: "crowdstrike.FileSize", dst: "file.size"},
		{src: "crowdstrike.NewOwner", dst: "file.owner"},
		{src: "crowdstrike.NewGroup", dst: "file.group"},
	} {
		SET(copy.dst).
			TAG(fmt.Sprintf("set %s from %s", copy.dst, copy.src)).
			COPY_FROM(copy.src).
			IGNORE_EMPTY(true)
	}

	for _, field := range []string{
		"FileAttributesNew",
		"NewFileAttributesLinux",
	} {
		APPEND("file.attributes", fmt.Sprintf("{{{crowdstrike.%s}}}", field)).
			TAG(fmt.Sprintf("append crowdstrike.%s into file attributes", field)).
			IF(fmt.Sprintf("ctx.crowdstrike?.%s != null", field)).
			ALLOW_DUPLICATES(false)
	}
	APPEND("related.hash", `{{{file.hash.sha256}}}`).
		TAG("append file hash sha256 into related hash").
		IF(`ctx.file?.hash?.sha256 != null`).
		ALLOW_DUPLICATES(false)

	SCRIPT().
		TAG("script set event severity from PolicyRuleSeverity").
		IF(`ctx.crowdstrike?.PolicyRuleSeverity != null`).
		SOURCE(`
		ctx.event = ctx.event ?: [:];
		def severity = ctx.crowdstrike.PolicyRuleSeverity;
		if (severity == 1) {
			ctx.event.severity = 21;
		} else if (severity == 2) {
			ctx.event.severity = 47;
		} else if (severity == 3) {
			ctx.event.severity = 73;
		} else if (severity == 4) {
			ctx.event.severity = 99;
		}
		`).
		ON_FAILURE(
			APPEND("error.message", errorMessage),
		)
}

func renameEventHandling() {
	BLANK().COMMENT("rename event handling for files and registry")

	SET("file.path").
		TAG("set file path from ObjectNameNew for rename events").
		COPY_FROM("crowdstrike.ObjectNameNew").
		IF(`ctx.crowdstrike?.ObjectAccessOperationType == 'RENAME' && (ctx.crowdstrike.ObjectType == 'FILE' || ctx.crowdstrike.ObjectType == 'FOLDER')`).
		IGNORE_EMPTY(true)

	SET("file.Ext.original.path").
		TAG("set file original path from ObjectName for rename events").
		COPY_FROM("crowdstrike.ObjectName").
		IF(`ctx.crowdstrike?.ObjectAccessOperationType == 'RENAME' && (ctx.crowdstrike.ObjectType == 'FILE' || ctx.crowdstrike.ObjectType == 'FOLDER')`).
		IGNORE_EMPTY(true)

	SET("registry.path").
		TAG("set registry path from ObjectNameNew for rename events").
		COPY_FROM("crowdstrike.ObjectNameNew").
		IF(`ctx.crowdstrike?.ObjectAccessOperationType == 'RENAME' && (ctx.crowdstrike.ObjectType == 'VALUE' || ctx.crowdstrike.ObjectType == 'KEY')`).
		IGNORE_EMPTY(true)

	SET("file.path").
		TAG("set file path from ObjectName for non-rename events").
		COPY_FROM("crowdstrike.ObjectName").
		IF(`ctx.crowdstrike?.ObjectAccessOperationType != 'RENAME' && (ctx.crowdstrike.ObjectType == 'FILE' || ctx.crowdstrike.ObjectType == 'FOLDER') && ctx.file?.path == null`).
		IGNORE_EMPTY(true)

	SET("registry.path").
		TAG("set registry path from ObjectName for non-rename events").
		COPY_FROM("crowdstrike.ObjectName").
		IF(`ctx.crowdstrike?.ObjectAccessOperationType != 'RENAME' && (ctx.crowdstrike.ObjectType == 'VALUE' || ctx.crowdstrike.ObjectType == 'KEY') && ctx.registry?.path == null`).
		IGNORE_EMPTY(true)

	SET("file.type").
		TAG("set file type to dir for folders").
		VALUE("dir").
		IF(`ctx.crowdstrike?.ObjectType == 'FOLDER' && ctx.file?.path != null`).
		IGNORE_EMPTY(true)
	SET("file.type").
		TAG("set file type to file for files").
		VALUE("file").
		IF(`ctx.crowdstrike?.ObjectType == 'FILE' && ctx.file?.path != null && ctx.file?.type == null`).
		IGNORE_EMPTY(true)

	BLANK().COMMENT("file.path parsing and file.Ext.original.path parsing are handled by default.yml pipeline")
	BLANK()

	SCRIPT().
		TAG("parse registry path to extract registry key and value").
		DESCRIPTION("Parse registry path to extract registry key and value").
		IF(`ctx.registry?.path != null && ctx.registry.path.length() > 0`).
		SOURCE(`
		def path = ctx.registry.path;
		def idx = path.lastIndexOf('\\');
		if (idx >= 0) {
			ctx.registry = ctx.registry ?: [:];
			ctx.registry.key = path.substring(0, idx);
			ctx.registry.value = path.substring(idx+1);
		} else {
			ctx.registry = ctx.registry ?: [:];
			ctx.registry.key = path;
		}
		// Clean up registry.key: remove \REGISTRY\(USER|MACHINE)\ prefix
		if (ctx.registry.key != null) {
			def key = ctx.registry.key;
			if (key.startsWith('\\REGISTRY\\USER\\')) {
				ctx.registry.key = key.substring('\\REGISTRY\\USER\\'.length());
			} else if (key.startsWith('\\REGISTRY\\MACHINE\\')) {
				ctx.registry.key = key.substring('\\REGISTRY\\MACHINE\\'.length());
			}
		}
		`).
		ON_FAILURE(
			APPEND("error.message", errorMessage),
		)
}

func FileIntegrityMonitorRuleMatchedRenames() {
	BLANK().COMMENT("FileIntegrityMonitorRuleMatched renames")

	RENAME("crowdstrike.PolicyIdentifier", "crowdstrike.Policy.ID").
		TAG("rename PolicyIdentifier to Policy ID").
		IGNORE_MISSING(true)
}

func cleanup() {
	BLANK().COMMENT("clean up")

	REMOVE(
		"crowdstrike.User",
		"crowdstrike.Host.Name",
		"crowdstrike.Policy.RuleBasePath",
		"crowdstrike.Policy.RuleGroupName",
		"crowdstrike.ContentDiff.SHA256",
		"crowdstrike.PolicyRuleID",
		"crowdstrike.PolicyRuleGroupID",
		"crowdstrike.FileSize",
		"crowdstrike.NewOwner",
		"crowdstrike.NewGroup",
		"crowdstrike.ObjectName",
		"crowdstrike.ObjectNameNew",
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
