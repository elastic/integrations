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
	DESCRIPTION("Pipeline for processing Epp Detection Summary events.")

	BLANK()

	fieldTypeConversions()

	BLANK()

	timestampFields()

	BLANK()

	eventCategorizationFields()

	BLANK()

	ecsMappings()

	BLANK()

	errorHandling()

	Generate()
}

func fieldTypeConversions() {
	BLANK().COMMENT("EppDetectionSummaryEvent converts")

	for _, src := range []struct {
		field  string
		typ    string
		cond   string
		remove bool
	}{
		{
			field:  "crowdstrike.CloudIndicator",
			typ:    "boolean",
			cond:   "ctx.crowdstrike?.CloudIndicator != null && ctx.crowdstrike?.CloudIndicator != ''",
			remove: true,
		},
		{
			field:  "crowdstrike.PatternDispositionValue",
			typ:    "long",
			cond:   "ctx.crowdstrike?.PatternDispositionValue != null && ctx.crowdstrike?.PatternDispositionValue != ''",
			remove: true,
		},
		{
			field:  "crowdstrike.LocalIP",
			typ:    "ip",
			cond:   "ctx.crowdstrike?.LocalIP != null && ctx.crowdstrike.LocalIP != ''",
			remove: true,
		},
		{
			field:  "crowdstrike.LocalIPv6",
			typ:    "ip",
			cond:   "ctx.crowdstrike?.LocalIPv6 != null && ctx.crowdstrike.LocalIPv6 != ''",
			remove: true,
		},
	} {
		fieldName := strings.ReplaceAll(strings.ReplaceAll(src.field, "crowdstrike.", ""), ".", "_")
		CONVERT("", src.field, src.typ).
			TAG(fmt.Sprintf("convert_%s_to_%s", fieldName, src.typ)).
			IF(src.cond).
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
		field      string
		foreachTag string
		dateTag    string
	}{
		{
			field:      "crowdstrike.FilesAccessed",
			foreachTag: "foreach_crowdstrike_FilesAccessed",
			dateTag:    "date__ingest__value_Timestamp",
		},
		{
			field:      "crowdstrike.FilesWritten",
			foreachTag: "foreach_crowdstrike_FilesWritten",
			dateTag:    "date__ingest__value_Timestamp",
		},
	} {
		FOREACH(time.field,
			DATE("_ingest._value.Timestamp", "_ingest._value.Timestamp", "UNIX").
				TAG(time.dateTag).
				ON_FAILURE(
					REMOVE("_ingest._value.Timestamp").IGNORE_FAILURE(true),
					APPEND("error.message", errorMessage),
				),
		).
			TAG(time.foreachTag).
			IF(fmt.Sprintf("ctx.crowdstrike?.%s instanceof List", strings.ReplaceAll(time.field, "crowdstrike.", "")))
	}
}

func eventCategorizationFields() {
	BLANK().COMMENT("event categorization fields")

	SET("event.kind").
		TAG("set_event_kind_to_alert").
		VALUE("alert")
	APPEND("event.category", "malware").
		TAG("append_malware_category")
	APPEND("event.type", "info").
		TAG("append_info_type")
}

func ecsMappings() {
	BLANK().COMMENT("ECS field mappings")

	RENAME("crowdstrike.LocalIP", "source.ip").
		TAG("rename_crowdstrike_LocalIP_to_source_ip").
		IF("ctx.crowdstrike?.LocalIP != null && ctx.crowdstrike.LocalIP != \"\"").
		IGNORE_MISSING(true)

	CONVERT("", "crowdstrike.ProcessId", "string").
		TAG("convert_crowdstrike_ProcessId_to_string").
		IF("ctx.crowdstrike?.ProcessId != null && !(ctx.crowdstrike.ProcessId instanceof String)").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.ProcessId", "process.entity_id").
		TAG("rename_crowdstrike_ProcessId_to_process_pid").
		IF("ctx.process?.entity_id == null").
		IGNORE_MISSING(true)

	SPLIT("", "crowdstrike.HostGroups", ",").
		TAG("split_crowdstrike_HostGroups").
		IGNORE_MISSING(true)

	RENAME("crowdstrike.ParentImageFileName", "process.parent.name").
		TAG("rename_crowdstrike_ParentImageFileName_to_process_parent_executable").
		IF("ctx.process?.parent?.name == null").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.ParentImageFilePath", "process.parent.executable").
		TAG("rename_crowdstrike_ParentImageFilePath_to_process_parent_executable").
		IF("ctx.process?.parent?.executable == null").
		IGNORE_MISSING(true)

	RENAME("crowdstrike.Description", "message").
		TAG("rename_crowdstrike_Description_to_message").
		IGNORE_MISSING(true)
	SET("rule.description").
		TAG("set_rule_description_from_message").
		COPY_FROM("message").
		IF("ctx.message != null")

	SET("process.name").
		TAG("set_process_name_from_crowdstrike_FileName").
		COPY_FROM("crowdstrike.FileName").
		IGNORE_EMPTY(true)
	SET("process.executable").
		TAG("set_process_executable_from_crowdstrike_FilePath").
		COPY_FROM("crowdstrike.FilePath").
		IGNORE_EMPTY(true)

	for _, hash := range []struct {
		src string
		dst string
		tag string
	}{
		{src: "crowdstrike.SHA256String", dst: "file.hash.sha256", tag: "rename_crowdstrike_SHA256String_to_file_hash_sha256"},
		{src: "crowdstrike.MD5String", dst: "file.hash.md5", tag: "rename_crowdstrike_MD5String_to_file_hash_md5"},
		{src: "crowdstrike.SHA1String", dst: "file.hash.sha1", tag: "rename_crowdstrike_SHA1String_to_file_hash_sha1"},
	} {
		RENAME(hash.src, hash.dst).
			TAG(hash.tag).
			IGNORE_MISSING(true)
	}

	for _, hash := range []struct {
		field string
		tag   string
	}{
		{field: "file.hash.sha1", tag: "append_file_hash_sha1_to_related_hash"},
		{field: "file.hash.sha256", tag: "append_file_hash_sha256_to_related_hash"},
		{field: "file.hash.md5", tag: "append_file_hash_md5_to_related_hash"},
	} {
		APPEND("related.hash", fmt.Sprintf(`{{{%s}}}`, hash.field)).
			TAG(hash.tag).
			IF(fmt.Sprintf("ctx.%s != null && ctx.%s != \"\"", hash.field, hash.field)).
			ALLOW_DUPLICATES(false)
	}

	RENAME("crowdstrike.FileName", "file.name").
		TAG("rename_crowdstrike_FileName_to_file_name").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.FilePath", "file.path").
		TAG("rename_crowdstrike_FilePath_to_file_path").
		IGNORE_MISSING(true)

	RENAME("crowdstrike.Name", "rule.name").
		TAG("rename_crowdstrike_Name_to_rule_name").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.DetectId", "rule.id").
		TAG("rename_crowdstrike_DetectId_to_rule_id").
		IGNORE_MISSING(true)

	APPEND("host.mac", `{{{crowdstrike.MACAddress}}}`).
		TAG("append_crowdstrike_MACAddress_into_host_mac").
		IF("ctx.crowdstrike?.MACAddress != null && ctx.crowdstrike.MACAddress != \"\"").
		ALLOW_DUPLICATES(false)
	UPPERCASE("", "host.mac").
		TAG("uppercase_host_mac").
		IF("ctx.host?.mac != null").
		IGNORE_MISSING(true)
}

func errorHandling() {
	BLANK().COMMENT("error handling")

	ON_FAILURE(
		APPEND("error.message", `Processor "{{{ _ingest.on_failure_processor_type }}}" with tag "{{{ _ingest.on_failure_processor_tag }}}" in pipeline "{{{ _ingest.on_failure_pipeline }}}" failed with message "{{{ _ingest.on_failure_message }}}"`),
		SET("event.kind").
			TAG("set_pipeline_error_into_event_kind").
			VALUE("pipeline_error"),
		APPEND("tags", "preserve_original_event").
			TAG("append_preserve_original_event_into_tags").
			ALLOW_DUPLICATES(false),
	)
}

const errorMessage = `Processor {{{_ingest.on_failure_processor_type}}} with tag {{{_ingest.on_failure_processor_tag}}} in pipeline {{{_ingest.on_failure_pipeline}}} failed with message: {{{_ingest.on_failure_message}}}`
