// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	// For long_fields.json.
	_ "embed"

	. "github.com/efd6/dispear"
)

//go:embed long_fields.json
var longFieldsData []byte

func main() {
	DESCRIPTION("Pipeline for processing CrowdStrike FDR logs")

	messageDecoding()

	BLANK()

	BLANK().COMMENT("Non-sensor Events")
	PIPELINE("data_protection_detection_summary").
		IF(`ctx.crowdstrike?.ExternalApiType == 'Event_DataProtectionDetectionSummaryEvent'`)
		//   # Non-sensor Events
		// - pipeline:
		//     name: '{{ IngestPipeline "data_protection_detection_summary" }}'
		//     tag: data_protection_detection_summary
		//     if: ctx.crowdstrike?.ExternalApiType == 'Event_DataProtectionDetectionSummaryEvent'

	PIPELINE("epp_detection_summary").
		IF(`ctx.crowdstrike?.ExternalApiType == 'Event_EppDetectionSummaryEvent'`)
	BLANK().COMMENT("File Integrity Monitor Rule Matched events")
	PIPELINE("fim_rule_matched").
		IF(`ctx.crowdstrike?.ExternalApiType == 'Event_FileIntegrityMonitorRuleMatchedEnriched' || ctx.crowdstrike?.event_simpleName == 'FileIntegrityMonitorRuleMatched'`)
	PIPELINE("automated_lead_summary").
		IF(`ctx.crowdstrike?.ExternalApiType == 'Event_AutomatedLeadSummaryEvent'`)
	BLANK()

	BLANK().COMMENT("Handle case changes.")
	for _, old := range []string{
		"crowdstrike.GrandParentCommandLine",
		"crowdstrike.GrandParentImageFileName",
		"crowdstrike.GrandParentImageFilePath",
	} {
		new := strings.ReplaceAll(old, "GrandParent", "Grandparent")
		RENAME(old, new).
			IGNORE_MISSING(true).
			IGNORE_FAILURE(true)

	}

	BLANK()

	severityFields()

	BLANK()

	eppDetectionSummaryFields()

	BLANK()

	DATE("crowdstrike.FirstDiscoveredDate", "crowdstrike.FirstDiscoveredDate", "UNIX").
		COMMENT("Handle additional added fields.").
		IF(notNullEmpytOrNone("ctx.crowdstrike?.FirstDiscoveredDate"))
	for _, conv := range []struct{ field, typ, cond string }{
		{field: "crowdstrike.CurrentLocalIP", typ: "ip", cond: "ctx.crowdstrike?.CurrentLocalIP != null && ctx.crowdstrike?.CurrentLocalIP != ''"},
		{field: "crowdstrike.aipCount", typ: "integer", cond: "ctx.crowdstrike?.aipCount != null && ctx.crowdstrike?.aipCount != ''"},
		{field: "crowdstrike.discovererCount", typ: "integer", cond: "ctx.crowdstrike?.discovererCount != null && ctx.crowdstrike?.discovererCount != ''"},
		{field: "crowdstrike.localipCount", typ: "integer", cond: "ctx.crowdstrike?.localipCount != null && ctx.crowdstrike?.localipCount != ''"},
	} {
		CONVERT("", conv.field, conv.typ).IF(conv.cond)
	}

	BLANK()

	fingerPrinting()

	BLANK()
	PIPELINE("categorize").
		COMMENT("Categorization").
		IGNORE_MISSING(true)

	BLANK()
	BLANK().COMMENT(`Derive event.outcome from crowdstrike.Status.
CrowdStrike Status uses NTSTATUS codes; severity is in bits 30-31:
  0 = success, 1 = informational, 2 = warning, 3 = error.
Status 0 represents success. Non-zero success-severity codes (e.g. STATUS_PENDING),
warning, and informational represent unknown. Error represent failure.`)

	SCRIPT().
		TAG("set_event_outcome_from_Status").
		DESCRIPTION("Set event.outcome from crowdstrike.Status using NTSTATUS severity bits.").
		IF(`ctx.crowdstrike?.Status != null && ctx.crowdstrike.Status != '' && (ctx.event?.outcome == null || ctx.event.outcome == 'unknown')`).
		SOURCE(`
        long status = Long.parseLong(ctx.crowdstrike.Status);

        ctx.event = ctx.event ?: [:];
        if (status == 0L) {
          ctx.event.outcome = 'success';
          return;
        }
        // NTSTATUS severity in bits 30-31
        def severity = (int) ((status >>> 30) & 0x3L);
        if (severity == 3) {
          ctx.event.outcome = 'failure';
        } else {
          // informational, warning, or non-zero success-class (PENDING/TIMEOUT)
          ctx.event.outcome = 'unknown';
        }
		`).
		ON_FAILURE(
			APPEND("error.message", errorMessage),
		)

	BLANK()
	BLANK().COMMENT("Cached event category for category-dependent processors")
	for _, typ := range []string{
		"File",
		"Library",
		"Network",
		"Process",
		"Driver",
	} {
		SET(fmt.Sprintf("_temp.is%s", typ)).
			IF(fmt.Sprintf("ctx.event?.category?.contains('%s') == true", strings.ToLower(typ))).
			VALUE(true)
	}

	BLANK()
	BLANK().COMMENT("Event fields.")
	SET("event.id").
		DESCRIPTION("Concat the fields used in fingerprint.").
		IF(`ctx.crowdstrike?.id != null || ctx.crowdstrike?.aid != null || ctx.crowdstrike?.cid != null`).
		VALUE(`{{{#crowdstrike.id}}}{{{ crowdstrike.id }}}{{{/crowdstrike.id}}}|{{{#crowdstrike.aid}}}{{{ crowdstrike.aid }}}{{{/crowdstrike.aid}}}|{{{#crowdstrike.cid}}}{{{ crowdstrike.cid }}}{{{/crowdstrike.cid}}}`).
		OVERRIDE(false)
	SET("event.action").
		TAG("set_event_action_from_event_simpleName").
		COPY_FROM("crowdstrike.event_simpleName").
		IGNORE_EMPTY(true)
	RENAME("crowdstrike.SuspiciousHandleOpenReason", "event.reason").
		IGNORE_MISSING(true)

	BLANK()
	BLANK().COMMENT("Prepare data.")
	SCRIPT().
		TAG("convert_count_fields_to_long").
		DESCRIPTION("Convert all count fields to number.").
		SOURCE(`
          for (entry in ctx.crowdstrike.entrySet()) {
            def key = entry.getKey().toString();
            if (key.contains("Count") || key.contains("Port")) {
              try {
                ctx.crowdstrike[key] = Long.parseLong(entry.getValue().toString());
              } catch (Exception e) {
              }
            }
          }
		`)
	SCRIPT().
		TAG("remove_empty_hashes").
		DESCRIPTION("Remove all 0's hashes.").
		PARAMS(map[string]any{
			"MD5HashData":    "md5",
			"SHA1HashData":   "sha1",
			"SHA256HashData": "sha256",
		}).
		SOURCE(`
          def hashIsEmpty(String hash) {
            if (hash == null || hash == "") {
              return true;
            }

            Pattern emptyHashRegex = /^0*$/;
            def matcher = emptyHashRegex.matcher(hash);

            return matcher.matches();
          }

          def hashes = new HashMap();
          def related = [
            "hash": new ArrayList()
          ];
          for (entry in params.entrySet()) {
            def key = entry.getKey().toString();
            def value = ctx.crowdstrike[key];
            if (hashIsEmpty(value)) {
              ctx.crowdstrike.remove(key);
              continue;
            }

            hashes[entry.getValue().toString()] = value;
            related.hash.add(value);
          }

          ctx._temp = ctx._temp ?: [:];
          ctx._temp.hashes = hashes;
          if (related.hash.length > 0) {
            ctx.related = related;
          }
		`)

	BLANK()

	observerFields()

	BLANK()

	hostFields()

	BLANK()

	osFields()

	BLANK()

	serviceFields()

	BLANK()

	processFields()

	BLANK()

	libraryFields()

	BLANK()

	registryFields()

	BLANK()

	userFields()

	BLANK()

	networkFields()

	BLANK()

	urlFields()

	BLANK()

	ipGeolocationLookup()

	BLANK()

	autonomousSystemLookup()

	BLANK()

	dnsFields()

	BLANK()

	smbFields()

	BLANK()

	fileFields()

	BLANK()

	deviceFields()

	BLANK()

	cloudAssetFields()

	BLANK()

	threatFields()

	BLANK()

	packageFields()

	BLANK()

	crowdstrikeFields()

	BLANK()

	SCRIPT().
		TAG("script_process_interactive_logon_type").
		DESCRIPTION("Set process.interactive from crowdstrike.LogonType whenever a process object is present in the event. Placed after all other process processors so that any processor that creates a process object (TargetProcessId, ContextProcessId, etc.) has already run. Logon types 2 (Interactive), 10 (RemoteInteractive), 11 (CachedInteractive), and 12 (CachedRemoteInteractive) indicate an interactive shell session; all other types are non-interactive.").
		IF(`
		  ctx.crowdstrike?.LogonType instanceof String &&
		  ctx.crowdstrike.LogonType != '' &&
		  ctx.process != null
		`).
		SOURCE(`
        // Logon type reference: 2=Interactive, 3=Network, 4=Batch, 5=Service,
        // 7=Unlock, 8=NetworkCleartext, 9=NewCredentials, 10=RemoteInteractive,
        // 11=CachedInteractive, 12=CachedRemoteInteractive, 13=CachedUnlock
        def logonType = ctx.crowdstrike.LogonType;
        ctx.process.interactive = (logonType == '2' || logonType == '10' || logonType == '11' || logonType == '12');
		`).
		ON_FAILURE(
			APPEND("error.message", "Failed to set process.interactive from LogonType: {{{_ingest.on_failure_message}}}"),
		)

	BLANK()

	cleanup()

	Generate()
}

func messageDecoding() {
	BLANK().COMMENT("Message decoding.")

	REMOVE(
		"ecs.version",
		"event.dataset",
		"event.module",
		"observer.type",
		"observer.vendor",
	).TAG(
		"remove_static_constant_keyword_fields",
	).IGNORE_MISSING(true)

	REMOVE(
		"organization",
		"division",
		"team",
	).
		TAG("remove_agentless_metadata").
		IF("ctx.organization instanceof String && ctx.division instanceof String && ctx.team instanceof String").
		DESCRIPTION("Removes the fields added by Agentless as metadata, as they can collide with ECS fields.").
		IGNORE_MISSING(true)

	RENAME("message", "event.original").
		IF("ctx.event?.original == null").
		DESCRIPTION("Renames the original `message` field to `event.original` to store a copy of the original message. The `event.original` field is not touched if the document already has one; it may happen when Logstash sends the document.").
		IGNORE_MISSING(true)
	REMOVE("message").
		IF("ctx.event?.original != null").
		DESCRIPTION("The `message` field is no longer required if the document has an `event.original` field.").
		IGNORE_MISSING(true)
	JSON("crowdstrike", "event.original").
		ON_FAILURE(
			APPEND("error.message", "Processor {{{_ingest.on_failure_processor_type}}} with tag {{{_ingest.on_failure_processor_tag}}} in pipeline {{{_ingest.on_failure_pipeline}}} failed with message: {{{_ingest.on_failure_message}}}"),
		)

	REMOVE(
		"metadata.host.aid",
		"metadata.user.UserSid_readable",
	).
		TAG("remove_metadata_host_aid_and_user_sid").
		IGNORE_MISSING(true)
	RENAME("metadata", "crowdstrike.info").
		IGNORE_MISSING(true).
		ON_FAILURE(
			APPEND("error.message", errorMessage),
		)

	CONVERT("_temp.utc_timestamp", "crowdstrike.UTCTimestamp", "long").
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	for _, src := range []struct {
		field   string
		formats []string
		cond    string
	}{
		{field: "_temp.utc_timestamp", formats: []string{"UNIX"}, cond: "ctx._temp?.utc_timestamp instanceof long && ctx._temp.utc_timestamp < (long)1e10"},
		{field: "crowdstrike.UTCTimestamp", formats: []string{"UNIX_MS", "ISO8601"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.UTCTimestamp")},
		{field: "crowdstrike.timestamp", formats: []string{"UNIX_MS", "ISO8601"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.timestamp")},
		{field: "crowdstrike.CreationTimeStamp", formats: []string{"UNIX", "ISO8601"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.CreationTimeStamp")},
		{field: "crowdstrike.Time", formats: []string{"ISO8601", "UNIX"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.Time")},
		{field: "crowdstrike._time", formats: []string{"ISO8601", "UNIX"}, cond: notNullEmpytOrNone("ctx.crowdstrike?._time")},
	} {

		DATE("event.created", src.field, src.formats...).
			IF("ctx.event?.created == null && " + src.cond).
			IGNORE_FAILURE(true)
	}
	SET("@timestamp").
		COPY_FROM("event.created").
		IF("ctx.event?.created != null")
	SET("@timestamp").
		COPY_FROM("_ingest.timestamp").
		IF(`ctx["@timestamp"] == null`)

	for _, src := range []struct {
		field string
		cond  string
	}{
		{field: "BatchTimestamp"},
		{field: "BrowserExtensionInstalledTimestamp"},
		{field: "ContextTimeStamp", cond: `ctx.crowdstrike?.ContextTimeStamp != null && ctx.crowdstrike?.ContextTimeStamp != ""`},
		{field: "StartTime"},
		{field: "EndTime"},
	} {
		s := SCRIPT().
			DESCRIPTION(fmt.Sprintf("Conditionally convert %s from Windows NT timestamp format to UNIX", src.field)).
			TAG(fmt.Sprintf("script_date_%s_from_nt", src.field)).
			SOURCE(ntTimeToUnix(fmt.Sprintf("ctx.crowdstrike?.%s", src.field)))
		if src.cond != "" {
			s.IF(src.cond)
		}
		field := fmt.Sprintf("crowdstrike.%s", src.field)
		DATE(field, field, "UNIX").
			IF(notNullEmpytOrNone(fmt.Sprintf("ctx.crowdstrike?.%s", src.field)))
	}
	for _, src := range []struct {
		field   string
		formats []string
		cond    string
	}{
		{field: "crowdstrike.scores.modified_time", formats: []string{"ISO8601", "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.scores?.modified_time")},
		{field: "crowdstrike.ChangeTime", formats: []string{"UNIX"}, cond: "ctx.crowdstrike?.ChangeTime != null && ctx.crowdstrike.ChangeTime != ''"},
	} {
		DATE(src.field, src.field, src.formats...).
			IF(src.cond).
			ON_FAILURE(
				REMOVE(src.field),
				APPEND("error.message", errorMessage),
			)
	}

	RENAME("crowdstrike.message", "message").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.event_type", "crowdstrike.EventType").
		IF("ctx.crowdstrike?.EventType == null").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.host_hidden_status", "crowdstrike.HostHiddenStatus").
		IF("ctx.crowdstrike?.HostHiddenStatus == null").
		IGNORE_MISSING(true)

	for _, src := range []string{
		"crowdstrike.scores.os",
		"crowdstrike.scores.overall",
		"crowdstrike.scores.sensor",
	} {
		CONVERT("", src, "long").
			IGNORE_MISSING(true).
			ON_FAILURE(
				REMOVE(src).
					IGNORE_MISSING(true),
				APPEND("error.message", errorMessage),
			)
	}
}

func ntTimeToUnix(f string) string {
	const script = `
        if (%[1]s == null) {
          return;
        }
        long timestamp;
        if (%[2]s instanceof long) {
          timestamp = (long)%[2]s;
        } else if (%[2]s instanceof String) {
          if (!%[2]s.contains('.')) {
            timestamp = Long.parseLong(%[2]s);
          }
        }
        if (timestamp > 0x0100000000000000L) { // See https://devblogs.microsoft.com/oldnewthing/20030905-02/?p=42653 for constant.
          %[2]s = (timestamp / 10000000) - 11644473600L;
        }`
	return fmt.Sprintf(script, f, strings.ReplaceAll(f, "?", ""))
}

func severityFields() {
	BLANK().COMMENT(`Assign severities to conform to security rules values

21 = Low
47 = Medium
73 = High
99 = Critical

Leave crowdstrike values in place, since they have their own semantics.`)
	CONVERT("", "crowdstrike.alert.severity", "long").
		IF(`ctx.crowdstrike?.alert?.severity != null && !(ctx.crowdstrike.alert.severity instanceof long)`).
		ON_FAILURE(
			REMOVE("crowdstrike.alert.severity"),
			APPEND("error.message", errorMessage),
		)
	SCRIPT().
		DESCRIPTION("Script to set event.severity.").
		TAG("script_set_crowdstrike_alert_severity").
		IF("ctx.crowdstrike?.alert?.severity instanceof long && ctx.crowdstrike.alert.severityName == null").
		SOURCE(`
          long severity = ctx.crowdstrike.alert.severity;
          if (0 <= severity && severity < 20) {
            ctx.crowdstrike.alert.severityName = "info";
          } if (20 <= severity && severity < 40) {
            ctx.crowdstrike.alert.severityName = "low";
          } if (40 <= severity && severity < 60) {
            ctx.crowdstrike.alert.severityName = "medium";
          } if (60 <= severity && severity < 80) {
            ctx.crowdstrike.alert.severityName = "high";
          } if (80 <= severity && severity <= 100) {
            ctx.crowdstrike.alert.severityName = "critical";
          }
		`).
		ON_FAILURE(
			APPEND("error.message", errorMessage),
		)
	SCRIPT().
		IF("ctx.crowdstrike?.SeverityName instanceof String").
		TAG("script_set_event_severity").
		SOURCE(`
          ctx.event = ctx.event ?: [:];
          String name = ctx.crowdstrike.SeverityName;
          if (name.equalsIgnoreCase("low") || name.equalsIgnoreCase("info") || name.equalsIgnoreCase("informational")) {
            ctx.event.severity = 21;
          } else if (name.equalsIgnoreCase("medium")) {
            ctx.event.severity = 47;
          } else if (name.equalsIgnoreCase("high")) {
            ctx.event.severity = 73;
          } else if (name.equalsIgnoreCase("critical")) {
            ctx.event.severity = 99;
          }
		`).
		ON_FAILURE(
			APPEND("error.message", errorMessage),
		)
}

func eppDetectionSummaryFields() {
	BLANK().COMMENT("EppDetectionSummaryEvent renames")
	for _, change := range []struct{ from, to string }{
		{from: "crowdstrike.Hostname", to: "crowdstrike.ComputerName"},
		{from: "crowdstrike.LogonDomain", to: "crowdstrike.MachineDomain"},
		{from: "crowdstrike.AgentId", to: "crowdstrike.SensorId"},
		{from: "crowdstrike.Name", to: "crowdstrike.DetectName"},
	} {
		RENAME(change.from, change.to).
			IGNORE_MISSING(true).
			IGNORE_FAILURE(true)
	}
}

func cspmFields() {
	BLANK().COMMENT(`CSPM fields — run before fingerprint so @timestamp and rule/resource identity
are final for Cloud Security events.`)

	BLANK().COMMENT("Can be both string and int, fields are mapped as keyword.")
	for _, src := range []string{
		"crowdstrike.service",
		"crowdstrike.cloudplatform",
	} {
		CONVERT("", src, "string").
			IGNORE_MISSING(true)
	}

	BLANK()

	RENAME("crowdstrike.resource", "crowdstrike.resource_name").
		DESCRIPTION("Rename crowdstrike.resource in case concrete value field is mapped as object.").
		IF(`ctx.crowdstrike?.resource instanceof String`)

	REMOVE("cloud").
		IGNORE_MISSING(true)

	BLANK()

	PIPELINE("cspm_iom").
		IF(`` +
			`(ctx.crowdstrike?.disposition != null && ctx.crowdstrike.disposition.equalsIgnoreCase('Failed')) ||` +
			`(ctx.crowdstrike?.event_simpleName != null && ctx.crowdstrike.event_simpleName.equalsIgnoreCase('CloudSecurityIOMEvaluation'))`,
		)

	PIPELINE("cspm_ioa").
		IF(`ctx.crowdstrike?.vertex_type != null && ctx.crowdstrike.vertex_type.equalsIgnoreCase('ioa')`)
}

func fingerPrinting() {
	REMOVE("_id").COMMENT(`AWS S3 input does _id-Based Deduplication and generates "_id" by default.
When "Data Deduplication" is not enabled, this field must be removed.
https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-aws-s3#_document_id_generation`).
		TAG("remove_id_based_deduplication").
		DESCRIPTION("When data deduplication is disabled, even the _id-Based Deduplication needs to be removed.").
		IF("ctx._conf?.enable_deduplication == false").
		IGNORE_MISSING(true)

	BLANK()

	BLANK().COMMENT(`Classify FDR object type for the fingerprint discriminator.
Object-key layout places the type mid-path, e.g.
  c9ec061c00000000-ec39fe72/fdrv2/aidmaster/<uuid>/part-00000.gz
  <cid>/data/<uuid>/part-00000.gz
so match path segments rather than basename alone.`)

	SET("_temp.path").
		COPY_FROM("log.file.path").
		IGNORE_EMPTY(true)
	SET("_temp.path").
		IF("ctx._temp?.path == null").
		COPY_FROM("aws.s3.object.key").
		IGNORE_EMPTY(true)
	SET("_temp.type").
		IF("ctx._temp?.path != null").
		VALUE("data")
	SET("_temp.type").
		IF(`ctx._temp?.path != null && (ctx._temp.path == 'aidmaster' || ctx._temp.path.endsWith('/aidmaster') || ctx._temp.path.contains('/aidmaster/'))`).
		VALUE("aidmaster")
	SET("_temp.type").
		IF(`ctx._temp?.path != null && (ctx._temp.path == 'userinfo' || ctx._temp.path.endsWith('/userinfo') || ctx._temp.path.contains('/userinfo/'))`).
		VALUE("userinfo")

	cspmFields()

	BLANK().COMMENT("Resolve a stable CSPM resource identity for fingerprinting.")
	SCRIPT().
		TAG("script_cspm_resource_id_for_fingerprint").
		IF("ctx.rule?.id != null").
		SOURCE(`
        ctx._temp = ctx._temp ?: [:];
        if (ctx.crowdstrike?.ResourceId != null && ctx.crowdstrike.ResourceId != '') {
          ctx._temp.cspm_resource_id = ctx.crowdstrike.ResourceId.toString();
        } else if (ctx.crowdstrike?.resource?.resourceId != null && ctx.crowdstrike.resource.resourceId != '') {
          ctx._temp.cspm_resource_id = ctx.crowdstrike.resource.resourceId.toString();
        } else if (ctx.crowdstrike?.crn != null && ctx.crowdstrike.crn != '') {
          ctx._temp.cspm_resource_id = ctx.crowdstrike.crn.toString();
        } else if (ctx.event?.id != null && ctx.event.id != '') {
          // IOA: cspm_ioa renames crowdstrike.event_id -> event.id
          ctx._temp.cspm_resource_id = ctx.event.id.toString();
        }
		`)

	FINGERPRINT("_id",
		"@timestamp",
		"crowdstrike.id",
		"crowdstrike.aid",
		"crowdstrike.cid",
		"_temp.type",
		"rule.id",
		"_temp.cspm_resource_id",
	).
		TAG("fingerprint_crowdstrike_fdr").
		DESCRIPTION("When deduplication is enabled, fingerprint a set of crowdstrike fields to prevent the same event from being indexed more than once. CSPM events also include rule.id and resource id so distinct findings that share timestamp/cid stay unique.").
		IF("ctx._conf?.enable_deduplication == true").
		IGNORE_MISSING(true)
}

func observerFields() {
	BLANK().COMMENT("Observer fields.")

	SET("observer.serial_number").
		COPY_FROM("crowdstrike.aid").
		IGNORE_EMPTY(true)
	SPLIT("", "crowdstrike.aip", `\s+`).
		IGNORE_MISSING(true)
	CONVERT("", "crowdstrike.aip", "ip").
		IGNORE_MISSING(true).
		ON_FAILURE(
			REMOVE("crowdstrike.aip"),
		)
	RENAME("crowdstrike.aip", "observer.ip").
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	SET("observer.address").
		COPY_FROM("observer.ip").
		IGNORE_EMPTY(true)
	for _, src := range []string{
		"crowdstrike.AgentVersion",
		"crowdstrike.ConfigBuild",
	} {
		RENAME(src, "observer.version").
			IGNORE_MISSING(true).
			IGNORE_FAILURE(true)
	}
	FOREACH("observer.ip",
		APPEND("related.ip",
			`{{{_ingest._value}}}`,
		).
			ALLOW_DUPLICATES(false),
	).IF(`ctx.observer?.ip != null && ctx.observer.ip instanceof List`)
}

func hostFields() {
	BLANK().COMMENT("Host fields.")

	RENAME("crowdstrike.aid", "host.id").
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	for _, src := range []string{
		"crowdstrike.ComputerName",
		"crowdstrike.hostname",
	} {
		RENAME(src, "host.hostname").
			IGNORE_MISSING(true).
			IGNORE_FAILURE(true)
	}
	SET("host.name").
		COPY_FROM("host.hostname").
		IGNORE_EMPTY(true).
		IGNORE_FAILURE(true)
	APPEND("related.hosts", `{{{crowdstrike.info.host.ComputerName}}}`).
		IF(`ctx.crowdstrike?.info?.host?.ComputerName != null`).
		ALLOW_DUPLICATES(false)
	RENAME("crowdstrike.info.host.ComputerName", "host.name").
		IF(`ctx.host?.name == null`).
		IGNORE_MISSING(true)
	APPEND("related.hosts", `{{{host.name}}}`).
		IF(`ctx.host?.name != null`).
		ALLOW_DUPLICATES(false)
	for _, change := range []struct {
		from, to string
	}{
		{from: "crowdstrike.City", to: "host.geo.city_name"},
		{from: "crowdstrike.Continent", to: "host.geo.continent_name"},
		{from: "crowdstrike.Country", to: "host.geo.country_name"},
		{from: "crowdstrike.Timezone", to: "host.geo.timezone"},
		{from: "crowdstrike.MachineDomain", to: "host.domain"},
	} {
		RENAME(change.from, change.to).
			IGNORE_MISSING(true).
			IGNORE_FAILURE(true)
	}
	CONVERT("_temp.aip", "crowdstrike.info.host.aip", "ip").
		IF(`ctx.crowdstrike?.info?.host?.aip != null && ctx.crowdstrike.info.host.aip != ""`).
		IGNORE_FAILURE(true)
	REMOVE("crowdstrike.info.host.aip").
		IF(`ctx._temp?.aip != null`)
	for _, dst := range []string{
		"host.ip",
		"related.ip",
	} {
		APPEND(dst, `{{{_temp.aip}}}`).
			IF(`ctx._temp?.aip != null`).
			ALLOW_DUPLICATES(false)
	}
}

func osFields() {
	BLANK().COMMENT("OS fields.")

	for _, os := range []struct {
		typ           string
		eventPlatform string
	}{
		{typ: "linux", eventPlatform: "Lin"},
		{typ: "macos", eventPlatform: "Mac"},
		{typ: "windows", eventPlatform: "Win"},
		{typ: "ios", eventPlatform: "iOS"},
	} {
		SET("host.os.type").
			IF(fmt.Sprintf(`ctx.crowdstrike?.event_platform != null && ctx.crowdstrike.event_platform == %q`, os.eventPlatform)).
			VALUE(os.typ)
	}
	for _, src := range []string{
		"crowdstrike.OSVersionString",
		"crowdstrike.Version",
	} {
		RENAME(src, "host.os.version").
			IGNORE_MISSING(true).
			IGNORE_FAILURE(true)
	}
}

func serviceFields() {
	BLANK().COMMENT("Service fields.")

	SET("service.name").
		IF(`ctx._temp?.isDriver == true`).
		COPY_FROM("crowdstrike.ServiceDisplayName").
		IGNORE_EMPTY(true)
}

func processFields() {
	BLANK().COMMENT("Process fields.")
	RENAME("crowdstrike.CommandLine", "process.command_line").
		IGNORE_MISSING(true)
	SCRIPT().
		TAG("split_command_line").
		DESCRIPTION("Implements Windows-like SplitCommandLine").
		IF(`ctx.process?.command_line != null && ctx.process.command_line != "" && ctx.host?.os?.type != null`).
		SOURCE(`
            // appendBSBytes appends n '\\' bytes to b and returns the resulting slice.
            def appendBSBytes(StringBuilder b, int n) {
               for (; n > 0; n--) {
                 b.append('\\');
               }
               return b;
            }

            // readNextArg splits command line string into next
            // argument and command line remainder offset.
            def readNextArg(String line, int offset) {
              def b = new StringBuilder();
              boolean inquote;
              int nslash;
              for (; offset < line.length(); offset++) {
                def c = line.charAt(offset);
                if (c == (char)' ' || c == (char)0x09) {
                  if (!inquote) {
                    return [
                      "arg":  appendBSBytes(b, nslash).toString(),
                      "offset": offset+1
                    ];
                  }
                } else if (c == (char)'"') {
                  b = appendBSBytes(b, nslash/2);
                  if (nslash%2 == 0) {
                    // use "Prior to 2008" rule from
                    // http://daviddeley.com/autohotkey/parameters/parameters.htm
                    // section 5.2 to deal with double double quotes
                    if (inquote && offset+1 < line.length() && line.charAt(offset+1) == (char)'"') {
                      b.append(c);
                      offset++;
                    }
                    inquote = !inquote;
                  } else {
                    b.append(c);
                  }
                  nslash = 0;
                  continue;
                } else if (c == (char)'\\') {
                  nslash++;
                  continue;
                }
                b = appendBSBytes(b, nslash);
                nslash = 0;
                b.append(c);
              }
              return [
                "arg":  appendBSBytes(b, nslash).toString(),
                "offset": line.length()
              ];
            }

            // commandLineToArgv splits a command line into individual argument
            // strings, following the Windows conventions documented
            // at http://daviddeley.com/autohotkey/parameters/parameters.htm#WINARGV
            // Original implementation found at: https://github.com/golang/go/commit/39c8d2b7faed06b0e91a1ad7906231f53aab45d1
            def commandLineToArgv(String line) {
              def args = new ArrayList();
              for (int i = 0; i < line.length();) {
                if (line.charAt(i) == (char)' ' || line.charAt(i) == (char)0x09) {
                  i++;
                  continue;
                }
                def next = readNextArg(line, i);
                i = next.offset;
                if (next.arg == '') {
                  // Empty strings will be removed later so don't bother adding them.
                  continue;
                }
                args.add(next.arg);
              }
              return args;
            }

            ctx.process.args = commandLineToArgv(ctx.process.command_line);
            ctx.process.args_count = ctx.process.args.length;
		`)

	SCRIPT().
		TAG("script_command_history_to_process_command_line").
		DESCRIPTION("Split crowdstrike.CommandHistory on U+00B6 PILCROW SIGN into an array and assign the result to both crowdstrike.CommandHistory and process.command_line. Placed after split_command_line so that processor only runs on string-valued command lines from crowdstrike.CommandLine.").
		IF(`
		  ctx.crowdstrike?.event_simpleName == 'CommandHistory' &&
		  ctx.crowdstrike?.CommandHistory instanceof String &&
		  ctx.crowdstrike.CommandHistory != ''
		`).
		SOURCE(`
        def history = ctx.crowdstrike.CommandHistory;
        def commands = new ArrayList();
        def remaining = history;
        int idx = remaining.indexOf("¶");
        while (idx >= 0) {
          def cmd = remaining.substring(0, idx).trim();
          if (!cmd.isEmpty()) {
            commands.add(cmd);
          }
          remaining = remaining.substring(idx + 1);
          idx = remaining.indexOf("¶");
        }
        if (!remaining.trim().isEmpty()) {
          commands.add(remaining.trim());
        }
        ctx.crowdstrike.CommandHistory = commands;
        ctx.process = ctx.process ?: [:];
        ctx.process.command_line = commands;
		`).
		ON_FAILURE(
			APPEND("error.message", "Failed to parse CommandHistory: {{{_ingest.on_failure_message}}}"),
		)
	SET("process.user.name").
		TAG("set_process_user_name_command_history").
		DESCRIPTION("Map crowdstrike.UserName to process.user.name for CommandHistory events.").
		IF(`ctx.crowdstrike?.event_simpleName == 'CommandHistory' && ctx.crowdstrike?.UserName instanceof String && ctx.crowdstrike.UserName != ''`).
		COPY_FROM("crowdstrike.UserName").
		IGNORE_EMPTY(true)
	RENAME("crowdstrike.ImageFileName", "process.executable").
		IF(`ctx._temp?.isLibrary != true && ctx._temp?.isDriver != true`).
		IGNORE_MISSING(true)
	SCRIPT().
		TAG("process_name").
		DESCRIPTION("Calculate process.name").
		IF(`ctx.process?.executable != null && ctx.process.executable != ""`).
		SOURCE(`
          def executable = ctx.process.executable;
          def exe_arr = [];
          def name = executable;
          if(executable.substring(0,1) == "\\") {
            name = executable.splitOnToken("\\")[-1];
          } else if(executable.substring(0,1) == "/") {
            name = executable.splitOnToken("/")[-1];
          }
          ctx.process.put("name", name);
		`)

	BLANK()
	SCRIPT().
		COMMENT(`This handles a special case occurs in Linux-based containerized environments
when the "runc" process clones itself to get into its own namespace.
The child process would have its executable path set to "/"
and consequently, the process name would not be set.
For more details, see https://terenceli.github.io/%E6%8A%80%E6%9C%AF/2021/12/28/runc-internals-3.`).
		TAG("parse_process_name_from_command_line").
		DESCRIPTION("Extract process.name from command line if not already present.").
		IF(`
          ctx.process?.executable == '/' &&
          (ctx.process.name == null || ctx.process.name == '') &&
          (ctx.process.args instanceof List && ctx.process.args.length > 0)
		`).
		SOURCE(`
          ctx.process.name = ctx.process.args[0];

          // Clean up path separators.
          int lastSlash = ctx.process.name.lastIndexOf("/");
          if (lastSlash != -1) {
            ctx.process.name = ctx.process.name.substring(lastSlash + 1);
          }
		`)

	CONVERT("", "crowdstrike.ExitCode", "long").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.ExitCode", "process.exit_code").
		IGNORE_MISSING(true)
	for _, src := range []string{
		"crowdstrike.ProcessStartTime",
		"crowdstrike.ProcessEndTime",
	} {
		CONVERT("", src, "string").
			IGNORE_MISSING(true)
	}

	SCRIPT().
		TAG("process_uptime").
		DESCRIPTION("Calculate process.uptime").
		IF(`
          ctx.crowdstrike?.ProcessStartTime != null && ctx.crowdstrike?.ProcessStartTime != "" &&
          ctx.crowdstrike?.ProcessEndTime != null && ctx.crowdstrike?.ProcessEndTime != ""
		`).
		SOURCE(`
          float s = Float.parseFloat(ctx.crowdstrike?.ProcessStartTime);
          float e = Float.parseFloat(ctx.crowdstrike?.ProcessEndTime);
          if (e >= s) {
            if (ctx.process == null) {
              ctx.process = [:];
            }
            ctx.process.uptime = (long) ((e-s)/1000L);
          }
		`)
	SCRIPT().
		TAG("parse_raw_pids").
		DESCRIPTION("Parse raw process id's so that they roll over if out of 32-bit range").
		SOURCE(`
          def parsePid(String pid) {
            try {
              return Long.parseUnsignedLong(pid);
            } catch (Exception e) {
              return pid;
            }
          }
          if (ctx.crowdstrike?.RawProcessId != null) {
            ctx.crowdstrike.RawProcessId = parsePid(ctx.crowdstrike.RawProcessId);
          }
          if (ctx.crowdstrike?.EtwRawProcessId != null) {
            ctx.crowdstrike.EtwRawProcessId = parsePid(ctx.crowdstrike.EtwRawProcessId);
          }
		`)

	for _, timestamp := range []struct {
		name string
	}{
		{name: "Start"},
		{name: "End"},
	} {
		id := strings.ToLower(timestamp.name)
		field := fmt.Sprintf("crowdstrike.Process%sTime", timestamp.name)
		painField := fmt.Sprintf("ctx.crowdstrike?.Process%sTime", timestamp.name)
		DATE(field, field, "UNIX").
			TAG(fmt.Sprintf("date_process_%s_time", id)).
			IF(notNullEmpytOrNone(painField))
		RENAME(field, fmt.Sprintf("process.%s", id)).
			IF(painField + ` != ""`).
			IGNORE_MISSING(true)
	}

	RENAME("crowdstrike.RawProcessId", "process.pid").
		IGNORE_MISSING(true)

	for _, change := range []struct {
		from string
		to   string
		cond string
	}{
		{
			from: "crowdstrike.TargetProcessId",
			to:   "process.entity_id",
			cond: `ctx.crowdstrike?.TargetProcessId != null && !(ctx.crowdstrike.TargetProcessId instanceof String)`,
		},
		{
			from: "crowdstrike.ParentProcessId",
			to:   "process.parent.entity_id",
			cond: `ctx.crowdstrike?.ParentProcessId != null && !(ctx.crowdstrike.ParentProcessId instanceof String)`,
		},
	} {
		CONVERT("", change.from, "string").
			IF(change.cond).
			IGNORE_MISSING(true)
		RENAME(change.from, change.to).
			IGNORE_MISSING(true)
	}

	SET("process.name").
		IF(`ctx._temp?.isNetwork == true`).
		COPY_FROM("crowdstrike.ContextBaseFileName").
		IGNORE_EMPTY(true)
	RENAME("crowdstrike.ParentBaseFileName", "process.parent.name").
		IGNORE_MISSING(true)
	CONVERT("", "crowdstrike.ProcessGroupId", "long").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.ProcessGroupId", "process.pgid").
		IGNORE_MISSING(true)
	SET("process.entity_id").
		IF(`ctx.process?.entity_id == null`).
		COPY_FROM("crowdstrike.ContextProcessId").
		IGNORE_EMPTY(true)
	CONVERT("", "crowdstrike.ContextThreadId", "long").
		IF(`ctx.process?.thread?.id == null`).
		IGNORE_MISSING(true)
	RENAME("crowdstrike.ContextThreadId", "process.thread.id").
		IF(`ctx.process?.thread?.id == null`).
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	RENAME("crowdstrike.EtwRawProcessId", "process.pid").
		IF(`ctx.process?.pid == null`).
		IGNORE_MISSING(true)
	CONVERT("", "crowdstrike.EtwRawThreadId", "long").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.EtwRawThreadId", "process.thread.id").
		IF(`ctx.process?.thread?.id == null`).
		IGNORE_MISSING(true)

	RENAME("crowdstrike.ServiceDisplayName", "process.title").
		IGNORE_MISSING(true)
	RENAME("_temp.hashes", "process.hash").
		IF(`
          ctx.event?.action != null &&
          (ctx.event.action.contains("Process") || ctx.event.action.contains("Service")) &&
          ctx._temp?.hashes != null && ctx._temp?.hashes.size() > 0
		`)
	SCRIPT().
		TAG("integrity_level").
		IF(`ctx.crowdstrike?.IntegrityLevel != null`).
		PARAMS(map[string]any{
			"levels": map[string]any{
				"0":     "UNTRUSTED",
				"4096":  "LOW",
				"8192":  "MEDIUM",
				"8448":  "MEDIUM_PLUS",
				"12288": "HIGH",
				"16384": "SYSTEM",
				"20480": "PROTECTED",
			},
		}).
		SOURCE(`
          String level = params.get('levels')[ctx.crowdstrike.IntegrityLevel];
          if (level != null) {
            ctx.process = ctx.process ?: [:];
            ctx.process.Ext = ctx.process.Ext ?: [:];
            ctx.process.Ext.token = ctx.process.Ext.token ?: [:];
            ctx.process.Ext.token.integrity_level_name = level;
          }
		`)
	SET("process.pe.original_file_name").
		IF(`ctx._temp?.isProcess == true && ctx.host?.os?.type == 'windows'`).
		COPY_FROM("crowdstrike.OriginalFilename").
		IGNORE_EMPTY(true)
	CONVERT("process.group_leader.entity_id", "process.pgid", "string").
		IF(`ctx._temp?.isProcess == true && ctx.host?.os?.type == 'linux'`).
		IGNORE_MISSING(true)

	for _, copy := range []struct {
		dst  string
		src  string
		cond string
	}{
		{dst: "process.real_user.id", src: "crowdstrike.RUID"},
		{dst: "user.Ext.real.id", src: "process.real_user.id"},
		{dst: "process.real_group.id", src: "crowdstrike.RGID", cond: `ctx.host?.os?.type == 'linux'`},
		{dst: "group.Ext.real.id", src: "process.real_group.id"},
		{dst: "process.group.id", src: "crowdstrike.GID", cond: `ctx.host?.os?.type == 'linux'`},
		{dst: "group.id", src: "process.group.id"},
	} {
		s := SET(copy.dst).COPY_FROM(copy.src).IGNORE_EMPTY(true)
		if copy.cond != "" {
			s.IF(copy.cond)
		}
	}
}

func libraryFields() {
	BLANK().COMMENT("Library fields.")

	SET("dll.pe.original_file_name").
		IF(`(ctx._temp?.isLibrary == true || ctx._temp?.isDriver == true) && ctx.host?.os?.type == 'windows'`).
		COPY_FROM("crowdstrike.OriginalFilename").
		IGNORE_EMPTY(true)
	for _, change := range []struct {
		from string
		to   string
		cond string
	}{
		{from: "process.name", to: "dll.name", cond: `ctx._temp?.isLibrary == true && ctx.host?.os?.type == 'windows'`},
		{from: "process.executable", to: "dll.path", cond: `ctx._temp?.isLibrary == true && ctx.host?.os?.type == 'windows'`},
		{from: "crowdstrike.MD5HashData", to: "dll.hash.md5", cond: `(ctx._temp?.isLibrary == true || ctx._temp?.isDriver == true) && ctx.host?.os?.type == 'windows'`},
		{from: "crowdstrike.SHA1HashData", to: "dll.hash.sha1", cond: `ctx._temp?.isLibrary == true && ctx.host?.os?.type == 'windows'`},
		{from: "crowdstrike.SHA256HashData", to: "dll.hash.sha256", cond: `(ctx._temp?.isLibrary == true || ctx._temp?.isDriver == true) && ctx.host?.os?.type == 'windows'`},
	} {
		RENAME(change.from, change.to).
			IF(change.cond).
			IGNORE_MISSING(true)
	}
	CONVERT("dll.Ext.size", "crowdstrike.ModuleSize", "long").
		IF(`ctx.crowdstrike?.ModuleSize != '' && ctx.host?.os?.type == 'windows'`).
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	SCRIPT().
		TAG(`script_set_dll_name`).
		IF(`
           (ctx._temp?.isLibrary == true || ctx._temp?.isDriver == true) &&
           ctx.crowdstrike?.ImageFileName != null &&
           ctx.host?.os?.type == 'windows'
		`).
		SOURCE(`
           int idx = ctx.crowdstrike.ImageFileName.lastIndexOf('\\');
           if (idx >= 0) {
             ctx.dll = ctx.dll ?: [:];
             ctx.dll.name = ctx.crowdstrike.ImageFileName.substring(idx+1);
           }
		`).
		IGNORE_FAILURE(true)
	RENAME("crowdstrike.ImageFileName", "dll.path").
		IF(`
          (ctx.event?.action == 'ClassifiedModuleLoad' || ctx._temp?.isDriver == true) &&
          ctx.host?.os?.type == 'windows'
		`).
		IGNORE_MISSING(true)
	SCRIPT().
		TAG(`script_set_process_name`).
		IF(`ctx._temp?.isLibrary == true && ctx.crowdstrike?.TargetImageFileName != null && ctx.host?.os?.type == 'windows'`).
		SOURCE(`
          int idx = ctx.crowdstrike.TargetImageFileName.lastIndexOf('\\');
          if (idx >= 0) {
            ctx.process = ctx.process ?: [:];
            ctx.process.name = ctx.crowdstrike.TargetImageFileName.substring(idx+1);
          }
		`).
		IGNORE_FAILURE(true)
	RENAME("crowdstrike.TargetImageFileName", "process.executable").
		IF(`ctx._temp?.isLibrary == true && ctx.host?.os?.type == 'windows'`).
		IGNORE_MISSING(true)
	SCRIPT().
		TAG(`script_set_process_name`).
		IF(`
          ctx.event?.action == 'ClassifiedModuleLoad' &&
          ctx.crowdstrike?.ImageSignatureLevel != null &&
          ctx.crowdstrike.ImageSignatureLevel != '' &&
          ctx.crowdstrike?.ImageSignatureType != null &&
          ctx.crowdstrike.ImageSignatureType != ''
		`).
		SOURCE(`
          long signatureLevel = Long.parseLong(ctx.crowdstrike.ImageSignatureLevel);
          long signatureType = Long.parseLong(ctx.crowdstrike.ImageSignatureType);
          ctx.dll = ctx.dll ?: [:];
          ctx.dll.code_signature = ctx.dll.code_signature ?: [:];
          if (signatureType == 0) {
            ctx.dll.code_signature.exists = false;
            ctx.dll.code_signature.trusted = false;
          } else if (signatureType >= 1 && (signatureLevel == 0 || signatureLevel == 1)) {
            ctx.dll.code_signature.exists = true;
            ctx.dll.code_signature.trusted = false;
          } else if (signatureType >= 1 && signatureLevel >= 2) {
            ctx.dll.code_signature.exists = true;
            ctx.dll.code_signature.trusted = true;
          }
		`).
		ON_FAILURE(
			APPEND("error.message", errorMessage),
		)
	SET("dll.code_signature.subject_name").
		IF(`ctx._temp?.isDriver == true && ctx.host?.os?.type == 'windows'`).
		COPY_FROM("crowdstrike.CertificatePublisher").
		IGNORE_EMPTY(true)
}

func registryFields() {
	BLANK().COMMENT("Registry fields.")

	APPEND("registry.data.strings", `{{{crowdstrike.RegStringValue}}}`).
		IF(`ctx.crowdstrike?.RegStringValue != null && ctx.crowdstrike.RegStringValue != ''`).
		ALLOW_DUPLICATES(false)
	SET("registry.path").
		IF(`ctx.crowdstrike?.RegObjectName != null && ctx.crowdstrike.RegObjectName != '' && ctx.crowdstrike?.RegValueName != null && ctx.crowdstrike.RegValueName != ''`).
		VALUE(`{{{crowdstrike.RegObjectName}}}\{{{crowdstrike.RegValueName}}}`)
	SET("registry.path").
		IF(`ctx.crowdstrike?.RegValueName == null || ctx.crowdstrike.RegValueName == ''`).
		COPY_FROM("crowdstrike.RegObjectName").
		IGNORE_EMPTY(true)
	SET("registry.value").
		COPY_FROM("crowdstrike.RegValueName").
		IGNORE_EMPTY(true)
	GSUB("registry.key", "crowdstrike.RegObjectName", `^\\REGISTRY\\(?:USER|MACHINE)\\`, "").
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)

	SCRIPT().
		TAG("script_set_event_type").
		IF(`ctx.crowdstrike?.RegOperationType != null`).
		PARAMS(map[string]any{
			"op_types": map[string]any{
				"1": map[string]any{
					"type": "change",
				},
				"2": map[string]any{
					"type": "deletion",
				},
				"3": map[string]any{
					"type": "creation",
				},
				"4": map[string]any{
					"type": "deletion",
				},
				"5": map[string]any{
					"type": "change",
				},
				"6": map[string]any{
					"type": "info",
				},
				"7": map[string]any{
					"type": "change",
				},
				"8": map[string]any{
					"type": "access",
				},
				"9": map[string]any{
					"type": "access",
				},
			}}).
		SOURCE(`
          def op = params.get('op_types')[ctx.crowdstrike.RegOperationType];
          if (op != null) {
            ctx.event = ctx.event ?: [:];
            ctx.event.type = [];
            ctx.event.type.add(op.type);
          }
		`)
	SCRIPT().
		TAG("script set registry data type").
		IF(`ctx.crowdstrike?.RegType != null`).
		PARAMS(map[string]any{
			"data_types": map[string]any{
				"0":  "REG_NONE",
				"1":  "REG_SZ",
				"2":  "REG_EXPAND_SZ",
				"3":  "REG_BINARY",
				"4":  "REG_DWORD",
				"5":  "REG_DWORD_BIG_ENDIAN",
				"6":  "REG_LINK",
				"7":  "REG_MULTI_SZ",
				"8":  "REG_RESOURCE_LIST",
				"9":  "REG_FULL_RESOURCE_DESCRIPTOR",
				"10": "REG_RESOURCE_REQUIREMENTS_LIST",
				"11": "REG_QWORD",
			}}).
		SOURCE(`
          String data_type = params.get('data_types')[ctx.crowdstrike.RegType];
          if (data_type != null) {
            ctx.registry = ctx.registry ?: [:];
            ctx.registry.data = ctx.registry.data ?: [:];
            ctx.registry.data.type = data_type;
          }
		`)
}

func userFields() {
	BLANK().COMMENT("User fields.")

	RENAME("crowdstrike.UID", "user.id").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.info.user.UserName", "user.name").
		IF(`ctx.crowdstrike?.info?.user?.UserName != null && ctx.user?.name == null`).
		IGNORE_MISSING(true)
	SPLIT("_temp.info_user_parts", "crowdstrike.info.user.User", `\\{1,2}`).
		IF(`ctx.crowdstrike?.info?.user?.User != null`)
	SET("user.domain").
		IF(`ctx._temp?.info_user_parts != null && ctx._temp.info_user_parts.size() == 2`).
		VALUE(`{{{_temp.info_user_parts.0}}}`).
		IGNORE_EMPTY(true).
		IGNORE_FAILURE(true)
	RENAME("crowdstrike.info.user.User", "user.name").
		IF(`ctx.crowdstrike?.info?.user?.User != null && ctx.user?.name == null`).
		IGNORE_MISSING(true)
	RENAME("crowdstrike.GID", "user.group.id").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.UserSid", "user.id").
		IF(`ctx.user?.id == null || ctx.user.id == ""`).
		IGNORE_MISSING(true)
	SET("user.id").
		IF(`ctx.user?.id == null && ctx._temp?.isFile == true`).
		COPY_FROM("crowdstrike.FileOperatorSid").
		IGNORE_EMPTY(true)
	APPEND("user.roles", "admin").
		IF(`ctx.crowdstrike?.UserIsAdmin == "1"`)
	RENAME("crowdstrike.User.Name", "user.name").
		IF(`ctx.crowdstrike?.User instanceof Map && ctx.crowdstrike.User.Name != null && ctx.user?.name == null`).
		IGNORE_MISSING(true)
	RENAME("crowdstrike.User.ID", "user.id").
		IF(`ctx.crowdstrike?.User instanceof Map && ctx.crowdstrike.User.ID != null && ctx.user?.id == null`).
		IGNORE_MISSING(true)
	REMOVE("crowdstrike.User").
		DESCRIPTION("Remove User field if it still exist as Map.").
		IF(`ctx.crowdstrike?.User instanceof Map`).
		IGNORE_MISSING(true)
	RENAME("crowdstrike.UserName", "user.name").
		IF(`ctx.crowdstrike?.UserName != null && ctx.user?.name == null`).
		IGNORE_MISSING(true)
	RENAME("crowdstrike.User", "user.name").
		IF(`ctx.crowdstrike?.User instanceof String && ctx.user?.name == null`).
		IGNORE_MISSING(true)
	SPLIT("_temp.user_parts", "crowdstrike.UserPrincipal", "@").
		IF(`ctx.crowdstrike?.UserPrincipal != null`)
	RENAME("crowdstrike.UserPrincipal", "user.email").
		IGNORE_MISSING(true)
	SET("user.domain").
		IF(`ctx.user?.domain == null && ctx._temp?.user_parts != null && ctx._temp.user_parts.size() == 2`).
		VALUE(`{{{_temp.user_parts.1}}}`).
		IGNORE_EMPTY(true).
		IGNORE_FAILURE(true)
	APPEND("user.domain", `{{{_temp.user_parts.1}}}`).
		IF(`ctx._temp?.user_parts != null && ctx._temp.user_parts.size() == 2`).
		ALLOW_DUPLICATES(false).
		IGNORE_FAILURE(true)
	SET("user.full_name").
		IF(`ctx._temp?.user_parts != null && ctx._temp.user_parts.size() == 2`).
		VALUE(`{{{_temp.user_parts.0}}}`).
		IGNORE_EMPTY(true).
		IGNORE_FAILURE(true)
	SET("_temp.is_active_directory_event").
		TAG("set_temp_is_active_directory_event").
		IF(`ctx.event?.action instanceof String && ctx.event.action.startsWith('ActiveDirectory')`).
		VALUE(true)
	SET("user.name").
		IF(`ctx._temp?.is_active_directory_event == true`).
		COPY_FROM("crowdstrike.SourceAccountSamAccountName").
		IGNORE_EMPTY(true)
	SET("user.email").
		IF(`
          ctx._temp?.is_active_directory_event == true &&
          ctx.crowdstrike?.SourceAccountUserName instanceof String && ctx.crowdstrike.SourceAccountUserName.contains('@')
		`).
		COPY_FROM("crowdstrike.SourceAccountUserName").
		IGNORE_EMPTY(true)
	SET("user.id").
		IF(`ctx._temp?.is_active_directory_event == true`).
		COPY_FROM("crowdstrike.SourceEndpointAccountObjectSid").
		IGNORE_EMPTY(true)
	SET("user.domain").
		IF(`ctx._temp?.is_active_directory_event == true`).
		COPY_FROM("crowdstrike.SourceAccountDomain").
		IGNORE_EMPTY(true)
	SET("user.name").
		IF(`ctx._temp?.is_active_directory_event == true && ctx.user?.name == null`).
		COPY_FROM("crowdstrike.SamAccountName").
		IGNORE_EMPTY(true)
	SET("user.id").
		IF(`ctx._temp?.is_active_directory_event == true && ctx.user?.id == null`).
		COPY_FROM("crowdstrike.AccountObjectSid").
		IGNORE_EMPTY(true)
	SET("user.domain").
		IF(`ctx._temp?.is_active_directory_event == true && ctx.user?.domain == null`).
		COPY_FROM("crowdstrike.AccountDomain").
		IGNORE_EMPTY(true)
	SET("user.name").
		IF(`ctx.event?.action == 'TokenImpersonated'`).
		COPY_FROM("crowdstrike.OriginalUserName").
		IGNORE_EMPTY(true)
	SET("user.id").
		IF(`ctx.event?.action == 'TokenImpersonated'`).
		COPY_FROM("crowdstrike.OriginalUserSid").
		IGNORE_EMPTY(true)
	SET("user.target.name").
		IF(`ctx.event?.action == 'TokenImpersonated'`).
		COPY_FROM("crowdstrike.ImpersonatedUserName").
		IGNORE_EMPTY(true)
	SET("user.name").
		IF(`ctx.event?.action == 'SudoCommandAttempt'`).
		COPY_FROM("crowdstrike.OriginalUserName").
		IGNORE_EMPTY(true)
	SET("user.name").
		IF(`(ctx.user?.name == null || ctx.user.name == '') && ctx.event?.action == 'SudoCommandAttempt'`).
		VALUE("root")
	SET("user.id").
		IF(`ctx.event?.action == 'SudoCommandAttempt'`).
		COPY_FROM("crowdstrike.OriginalUserID").
		IGNORE_EMPTY(true)
	SET("user.id").
		IF(`ctx.user?.id == null && ctx.event?.action == 'SudoCommandAttempt'`).
		VALUE(0)
	SET("user.target.name").
		IF(`ctx.event?.action == 'SudoCommandAttempt'`).
		COPY_FROM("crowdstrike.NewUsername").
		IGNORE_EMPTY(true)
	SET("user.target.name").
		IF(`(ctx.user?.target?.name == null || ctx.user.target.name == '') && ctx.event?.action == 'SudoCommandAttempt'`).
		VALUE("root")
	SET("user.target.id").
		IF(`ctx.event?.action == 'SudoCommandAttempt'`).
		COPY_FROM("crowdstrike.NewUserID").
		IGNORE_EMPTY(true)
	SET("user.target.id").
		IF(`ctx.user?.target?.id == null && ctx.event?.action == 'SudoCommandAttempt'`).
		VALUE(0)
	for _, field := range []struct {
		cond  string
		value string
	}{
		{value: `{{{user.name}}}`, cond: `ctx.user?.name != null`},
		{value: `{{{crowdstrike.info.user.User}}}`, cond: `ctx.crowdstrike?.info?.user?.User != null`},
		{value: `{{{user.full_name}}}`, cond: `ctx.user?.full_name != null`},
		{value: `{{{user.target.name}}}`, cond: `ctx.user?.target?.name != null`},
		{value: `{{{user.email}}}`, cond: `ctx.user?.email != null`},
		{value: `{{{user.id}}}`, cond: `ctx.user?.id != null`},
	} {
		APPEND("related.user", field.value).
			IF(field.cond).
			ALLOW_DUPLICATES(false).
			IGNORE_FAILURE(true)
	}
}

func networkFields() {
	BLANK().COMMENT("Networking fields.")

	for i, dir := range []string{
		"outbound",
		"inbound",
	} {
		SET("network.direction").
			TAG(fmt.Sprintf("set_network_direction_%s", dir)).
			IF(fmt.Sprintf(`ctx.crowdstrike?.ConnectionDirection == "%d"`, i)).
			VALUE(dir)
	}
	SET("network.direction").
		TAG("set_network_direction_unknown").
		IF(`ctx.network?.direction == null && ctx.crowdstrike?.ConnectionDirection != null && ctx.crowdstrike.ConnectionDirection != ""`).
		VALUE("unknown")

	for _, v := range []int{4, 6} {
		local := fmt.Sprintf("crowdstrike.LocalAddressIP%d", v)
		isNonEmptyList := fmt.Sprintf(`ctx.crowdstrike?.LocalAddressIP%[1]d instanceof List && ctx.crowdstrike.LocalAddressIP%[1]d.length > 0`, v)
		SPLIT("", local, `\s+`).
			IF(fmt.Sprintf(`ctx.crowdstrike?.LocalAddressIP%d != null`, v))
		CONVERT("", local, "ip").
			IF(isNonEmptyList).
			ON_FAILURE(
				APPEND("error.message", errorMessage),
			)
		CONVERT("", fmt.Sprintf("crowdstrike.RemoteAddressIP%d", v), "ip").
			IGNORE_MISSING(true)
		FOREACH(local,
			APPEND("related.ip", `{{{_ingest._value}}}`).
				ALLOW_DUPLICATES(false),
		).IF(isNonEmptyList)
	}

	for _, pipe := range []struct {
		name    string
		cond    string
		comment string
	}{
		{
			name: "outbound_network",
			cond: `ctx.network?.direction != 'inbound'`,
			comment: `The condition for this processor is all non-inbound, but the pipeline operates assuming the
traffic is outbound. In cases where there is no information we make this assumption rather
than dropping the data on the floor.`,
		},
		{
			name: "inbound_network",
			cond: `ctx.network?.direction == 'inbound'`,
		},
	} {
		p := PIPELINE(pipe.name).
			IF(pipe.cond)
		if pipe.comment != "" {
			p.COMMENT(pipe.comment)
		}
	}

	RENAME("crowdstrike.Protocol", "network.iana_number").
		IGNORE_MISSING(true)
	SCRIPT().
		TAG("network_transport_lookup").
		IF(`ctx.network?.iana_number != null`).
		SOURCE(`
          def iana_number = ctx.network.iana_number;
          if (iana_number == '0') {
              ctx.network.transport = 'hopopt';
          } else if (iana_number == '1') {
              ctx.network.transport = 'icmp';
          } else if (iana_number == '2') {
              ctx.network.transport = 'igmp';
          } else if (iana_number == '6') {
              ctx.network.transport = 'tcp';
          } else if (iana_number == '8') {
              ctx.network.transport = 'egp';
          } else if (iana_number == '17') {
              ctx.network.transport = 'udp';
          } else if (iana_number == '47') {
              ctx.network.transport = 'gre';
          } else if (iana_number == '50') {
              ctx.network.transport = 'esp';
          } else if (iana_number == '58') {
              ctx.network.transport = 'ipv6-icmp';
          } else if (iana_number == '112') {
              ctx.network.transport = 'vrrp';
          } else if (iana_number == '132') {
              ctx.network.transport = 'sctp';
          }
	`)

	COMMUNITY_ID("").
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)

	for _, src := range []string{
		"source",
		"destination",
	} {
		APPEND("related.ip", fmt.Sprintf(`{{{%s.ip}}}`, src)).
			IF(fmt.Sprintf(`ctx.%[1]s?.ip != null && ctx.%[1]s.ip != ""`, src)).
			ALLOW_DUPLICATES(false)
	}

	RENAME("crowdstrike.MAC", "source.mac").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.PhysicalAddress", "source.mac").
		IF(`ctx.source?.mac == null`).
		IGNORE_MISSING(true)
	UPPERCASE("", "source.mac").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.DownloadServer", "server.address").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.DownloadPath", "url.path").
		IGNORE_MISSING(true)
}

func urlFields() {
	BLANK().COMMENT("URL fields.")

	SET("url.path").
		IF(`ctx.url?.path != null && !ctx.url.path.startsWith("/")`).
		VALUE(`/{{{url.path}}}`)
	REGISTERED_DOMAIN("server", "server.address").
		IGNORE_MISSING(true)
	for _, prot := range []struct {
		scheme string
		cond   string
	}{
		{scheme: "https", cond: `ctx.crowdstrike?.DownloadPort == 443`},
		{scheme: "http", cond: `ctx.crowdstrike?.DownloadPort != null && ctx.crowdstrike.DownloadPort != 443`},
	} {
		SET("url.scheme").
			IF(prot.cond).
			VALUE(prot.scheme)
	}
	SET("url.full").
		IF(`ctx.url?.scheme != null && ctx.server?.address != null && ctx.url?.path != null`).
		VALUE(`{{{url.scheme}}}://{{{server.address}}}{{{url.path}}}`)
	URI_PARTS("", "url.full").
		IF(`ctx.url?.full != null`)
	REGISTERED_DOMAIN("url", "url.domain").
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
}

func ipGeolocationLookup() {
	BLANK().COMMENT("IP Geolocation Lookup.")

	for _, ip := range []struct {
		src       string
		firstOnly bool
	}{
		{src: "observer"},
		{src: "source", firstOnly: true},
		{src: "destination"},
	} {
		g := GEOIP(fmt.Sprintf("%s.geo", ip.src), fmt.Sprintf("%s.ip", ip.src)).
			IF(fmt.Sprintf(`ctx.%s?.ip != null && ctx._conf?.enable_geoip_%s_ip == true`, ip.src, ip.src)).
			IGNORE_MISSING(true)
		if ip.firstOnly {
			g.FIRST_ONLY(true)
		}
	}
}

func autonomousSystemLookup() {
	BLANK().COMMENT("IP Autonomous System (AS) Lookup")

	for _, ip := range []struct {
		src       string
		firstOnly bool
	}{
		{src: "source", firstOnly: true},
		{src: "destination"},
	} {
		g := GEOIP(ip.src+".as", ip.src+".ip").
			IF(fmt.Sprintf(`ctx.%s?.ip != null && ctx._conf?.enable_geoip_%s_ip == true`, ip.src, ip.src)).
			DATABASE_FILE("GeoLite2-ASN.mmdb").
			PROPERTIES("asn", "organization_name").
			IGNORE_MISSING(true)
		if ip.firstOnly {
			g.FIRST_ONLY(true)
		}
		RENAME(ip.src+".as.asn", ip.src+".as.number").
			IGNORE_MISSING(true)
		RENAME(ip.src+".as.organization_name", ip.src+".as.organization.name").
			IGNORE_MISSING(true)
	}
}

func dnsFields() {
	BLANK().COMMENT("DNS fields.")

	SET("_temp.is_dns_request").
		TAG("set_temp_is_dns_request").
		IF(`ctx.event?.action != null && ctx.event.action.toLowerCase().contains('dnsrequest')`).
		VALUE(true)
	isDNS := `ctx._temp?.is_dns_request == true`
	SET("dns.type").
		IF(isDNS).
		VALUE("query")
	SET("network.protocol").
		IF(isDNS).
		VALUE("dns")
	REGISTERED_DOMAIN("dns.question", "crowdstrike.DomainName").
		IF(isDNS).
		IGNORE_MISSING(true)
	RENAME("dns.question.domain", "dns.question.name").
		IF(isDNS).
		IGNORE_MISSING(true)
	RENAME("crowdstrike.DomainName", "dns.question.name").
		IF(`ctx._temp?.is_dns_request == true && ctx.dns?.question?.name == null`).
		IGNORE_MISSING(true)
	SCRIPT().
		TAG("dns_request_type_to_name").
		DESCRIPTION("Map decimal DNS request type to its name.").
		PARAMS(map[string]any{
			"1":     "A",
			"2":     "NS",
			"5":     "CNAME",
			"6":     "SOA",
			"12":    "PTR",
			"13":    "HINFO",
			"15":    "MX",
			"16":    "TXT",
			"17":    "RP",
			"18":    "AFSDB",
			"24":    "SIG",
			"25":    "KEY",
			"28":    "AAAA",
			"29":    "LOC",
			"33":    "SRV",
			"35":    "NAPTR",
			"36":    "KX",
			"37":    "CERT",
			"39":    "DNAME",
			"42":    "APL",
			"43":    "DS",
			"44":    "SSHFP",
			"45":    "IPSECKEY",
			"46":    "RRSIG",
			"47":    "NSEC",
			"48":    "DNSKEY",
			"49":    "DHCID",
			"50":    "NSEC3",
			"51":    "NSEC3PARAM",
			"52":    "TLSA",
			"53":    "SMIMEA",
			"55":    "HIP",
			"59":    "CDS",
			"60":    "CDNSKEY",
			"61":    "OPENPGPKEY",
			"62":    "CSYNC",
			"63":    "ZONEMD",
			"64":    "SVCB",
			"65":    "HTTPS",
			"108":   "EUI48",
			"109":   "EUI64",
			"249":   "TKEY",
			"250":   "TSIG",
			"256":   "URI",
			"257":   "CAA",
			"32768": "TA",
			"32769": "DLV",
		}).
		IF(`ctx._temp?.is_dns_request == true && ctx.crowdstrike?.RequestType != null && !ctx.crowdstrike.RequestType.isEmpty()`).
		SOURCE(`
              def t = params[ctx.crowdstrike.RequestType];
              if (t != null) {
                if (ctx.dns?.question == null) {
                  ctx.dns.question = new HashMap();
                }
                ctx.dns.question.type = t;
                ctx.crowdstrike.remove("RequestType");
              }
			`)
}

func smbFields() {
	BLANK().COMMENT("SMB fields.")

	REGISTERED_DOMAIN("destination", "crowdstrike.DomainName").
		IF(`ctx.event?.action != null && ctx.event.action.contains("SmbServerShareOpenedEtw")`).
		IGNORE_MISSING(true)
	RENAME("crowdstrike.DomainName", "destination.domain").
		IF(`ctx.event?.action != null && ctx.destination?.domain == null && ctx.event.action.contains("SmbServerShareOpenedEtw")`).
		IGNORE_MISSING(true)
}

func fileFields() {
	BLANK().COMMENT("File fields.")

	BLANK().COMMENT(`Handle crowdstrike.File when it arrives as a nested object (e.g., DataEgressEnriched events)
instead of the expected keyword value. Extracts sub-fields to ECS and crowdstrike.FileType.Type.`)

	SCRIPT().
		TAG("handle_crowdstrike_File_as_object").
		IF(`ctx.crowdstrike?.File instanceof Map`).
		SOURCE(`
        def fileMap = ctx.crowdstrike.File;
        ctx.file = ctx.file ?: [:];
        if (ctx.file.name == null && fileMap.Name != null) ctx.file.name = fileMap.Name;
        if (ctx.file.extension == null && fileMap.Extension != null) ctx.file.extension = fileMap.Extension;
        if (ctx.file.path == null) ctx.file.path = fileMap.NormalizedAbsolutePath ?: fileMap.AbsolutePath;
        def fileType = [:];
        if (fileMap.FileTypeID != null) fileType.ID = fileMap.FileTypeID;
        if (fileMap.FileTypeName != null) fileType.Name = fileMap.FileTypeName;
        if (fileMap.FileTypeDescription != null) fileType.Description = fileMap.FileTypeDescription;
        if (fileMap.FileTypeCategoryID != null) fileType.CategoryID = fileMap.FileTypeCategoryID;
        if (fileMap.FileTypeCategoryName != null) fileType.CategoryName = fileMap.FileTypeCategoryName;
        if (!fileType.isEmpty()) {
          ctx.crowdstrike.FileType = ctx.crowdstrike.FileType ?: [:];
          ctx.crowdstrike.FileType.Type = fileType;
        }
        ctx.crowdstrike.remove('File');
		`)

	SET("file.pe.original_file_name").
		IF(`ctx._temp?.isFile == true && ctx.host?.os?.type == 'windows'`).
		COPY_FROM("crowdstrike.OriginalFilename").
		IGNORE_EMPTY(true)
	CONVERT("", "crowdstrike.Size", "long").
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	RENAME("crowdstrike.Size", "file.size").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.FileIdentifier", "file.inode").
		IGNORE_MISSING(true)
	SET("file.Ext.original.path").
		IF(`ctx.event?.action == 'NewExecutableRenamed' || ctx.event?.action == 'FileRenameInfo'`).
		COPY_FROM("crowdstrike.SourceFileName").
		IGNORE_EMPTY(true)
	RENAME("crowdstrike.SourceFileName", "file.path").
		IGNORE_MISSING(true)
	RENAME("crowdstrike.TargetFileName", "file.path").
		IF(`ctx.file?.path == null`).
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	SET("file.path").
		IF(`ctx.event?.action == 'NewExecutableRenamed' || ctx.event?.action == 'FileRenameInfo'`).
		COPY_FROM("crowdstrike.TargetFileName").
		IGNORE_EMPTY(true)
	isDataEgressOrProtection := `ctx.file?.path == null && ctx.event?.action instanceof String && (ctx.event.action == 'DataEgress' || ctx.event.action.startsWith('DataProtection'))`
	SET("file.path").
		IF(isDataEgressOrProtection).
		COPY_FROM("crowdstrike.NormalizedPath").
		IGNORE_EMPTY(true)
	SET("file.path").
		IF(isDataEgressOrProtection).
		COPY_FROM("crowdstrike.AssessedFileName").
		IGNORE_EMPTY(true)
	SET("file.hash.sha256").
		IF(`ctx.file?.hash?.sha256 == null && ctx.event?.action instanceof String && (ctx.event.action == 'DataEgress' || ctx.event.action.startsWith('DataProtection'))`).
		COPY_FROM("crowdstrike.ContentSHA256HashData").
		IGNORE_EMPTY(true)
	APPEND("related.hash", `{{{file.hash.sha256}}}`).
		IF(`ctx.file?.hash?.sha256 != null`).
		ALLOW_DUPLICATES(false)
	RENAME("crowdstrike.DiskParentDeviceInstanceId", "file.device").
		IGNORE_MISSING(true)
	SET("file.type").
		IF(`ctx.file?.path != null && ctx.file.type == null && ctx.event?.action != null && !ctx.event.action.contains("Directory")`).
		VALUE("file")
	SET("file.type").
		IF(`ctx.file?.path != null && ctx.event?.action != null && (ctx.event.action.contains("Directory") || ctx.file.path.endsWith("\\") || ctx.file.path.endsWith("/"))`).
		VALUE("dir")
	SCRIPT().
		TAG("parse_file_path").
		DESCRIPTION("Adds file information.").
		IF(`ctx.file?.path != null && ctx.file.path.length() > 1`).
		SOURCE(`
          def removeSuffix(String s, String suffix) {
            if (s != null && suffix != null && s.endsWith(suffix)) {
              return s.substring(0, s.length() - suffix.length());
            }
            return s;
          }

          def path = removeSuffix(ctx.file.path, "/");
          path = removeSuffix(path, "\\");
          def idx = path.lastIndexOf("\\");
          if (idx == -1) {
            idx = path.lastIndexOf("/");
          }
          if (idx > -1) {
            if (ctx.file == null) {
                ctx.file = new HashMap();
            }
            ctx.file.name = path.substring(idx+1);
            ctx.file.directory = path.substring(0, idx);

            def extIdx = ctx.file.name.lastIndexOf(".");
            if (extIdx > -1 && ctx.file.type == "file") {
              ctx.file.extension = ctx.file.name.substring(extIdx+1);
            }
          }
          if (path.indexOf(':') == 1) {
            ctx.file.drive_letter = path.substring(0, 1).toUpperCase();
          }
		`)
	SCRIPT().
		TAG("parse_file_ext_original_path").
		DESCRIPTION("Adds file.Ext.original.* information.").
		IF(`ctx.file?.Ext?.original?.path != null && ctx.file.Ext.original.path.length() > 1`).
		SOURCE(`
          def removeSuffix(String s, String suffix) {
            if (s != null && suffix != null && s.endsWith(suffix)) {
              return s.substring(0, s.length() - suffix.length());
            }
            return s;
          }

          def path = removeSuffix(ctx.file.Ext.original.path, "/");
          path = removeSuffix(path, "\\");
          def idx = path.lastIndexOf("\\");
          if (idx == -1) {
            idx = path.lastIndexOf("/");
          }
          if (idx > -1) {
            ctx.file.Ext.original.name = path.substring(idx+1);
          }
		`)
	RENAME("_temp.hashes", "file.hash").
		IF(`ctx.event?.action != null && (ctx.event.action.contains("File") || ctx.event.action.contains("Directory") || ctx.event.action.contains("Executable")) && ctx._temp?.hashes != null && ctx._temp?.hashes.size() > 0`)
	SET("process.name").
		IF(`ctx.event?.action != null && ctx.event.action.endsWith('Written')`).
		COPY_FROM("crowdstrike.ContextBaseFileName").
		IGNORE_EMPTY(true)
	SET("process.executable").
		IF(`ctx.event?.action != null && ctx.event.action.endsWith('Written') && ctx.host?.os?.type == 'windows'`).
		COPY_FROM("crowdstrike.ContextImageFileName").
		IGNORE_EMPTY(true)
	SET("file.hash.sha256").
		IF(`ctx.event?.action != null && ctx.event.action.endsWith('Written') && ctx.host?.os?.type == 'linux'`).
		COPY_FROM("crowdstrike.SHA256HashData").
		IGNORE_EMPTY(true)
}

func deviceFields() {
	BLANK().COMMENT("Device Fields.")

	for i, src := range []string{
		"crowdstrike.SensorId",
		"crowdstrike.DeviceId",
		"observer.serial_number",
	} {
		s := SET("device.id").
			TAG(fmt.Sprintf("set_device_id_from_%s", src)).
			COPY_FROM(src).
			IGNORE_EMPTY(true)
		if i != 0 {
			s.IF(`ctx.device?.id == null`)
		}
	}
}

func cloudAssetFields() {
	awsCloudAssetFields()
	azureCloudAssetFields()
	gcpCloudAssetFields()
}

func awsCloudAssetFields() {
	BLANK().COMMENT("AWS FDR asset inventory → cloud.* (and host/related IPs)")

	SET("_temp.is_aws_event").
		TAG("set_temp_is_aws_event").
		IF(`ctx.event?.action instanceof String && ctx.event.action.startsWith('Aws')`).
		VALUE(true)
	SET("cloud.provider").
		TAG("set_cloud_provider_aws").
		IF(`ctx._temp?.is_aws_event == true`).
		VALUE("aws")
	for _, m := range []struct {
		dst, src, tag string
	}{
		{dst: "cloud.account.id", src: "crowdstrike.AwsOwnerId"},
		{dst: "cloud.region", src: "crowdstrike.AwsRegion"},
		{dst: "cloud.instance.id", src: "crowdstrike.AwsInstanceId"},
		{dst: "cloud.instance.name", src: "crowdstrike.AwsInstanceName"},
	} {
		SET(m.dst).
			TAG(fmt.Sprintf("set_%s_from_%s", m.dst, m.src)).
			IF(`ctx._temp?.is_aws_event == true`).
			COPY_FROM(m.src).
			IGNORE_EMPTY(true)
	}

	for _, ip := range []struct {
		src string
		dst string
		tag string
	}{
		{src: "crowdstrike.AwsPrivateIPAddress", dst: "_temp.aws_private_ip", tag: "AwsPrivateIPAddress"},
		{src: "crowdstrike.AwsPublicIpAddress", dst: "_temp.aws_public_ip", tag: "AwsPublicIpAddress"},
	} {
		CONVERT(ip.dst, ip.src, "ip").
			TAG(fmt.Sprintf("convert_crowdstrike_%s_to_ip", ip.tag)).
			IF(fmt.Sprintf(`ctx._temp?.is_aws_event == true && ctx.crowdstrike?.%s != null && ctx.crowdstrike.%s != ''`, ip.tag, ip.tag)).
			ON_FAILURE(
				REMOVE(ip.src).
					TAG(fmt.Sprintf("remove_crowdstrike_%s", ip.tag)).
					IGNORE_MISSING(true),
				APPEND("error.message", errorMessage),
			)
	}
	appendTempCloudIPs("aws")
}

func azureCloudAssetFields() {
	BLANK()
	BLANK().COMMENT("Azure FDR asset inventory → cloud.* (and host/related IPs)")

	SET("_temp.is_azure_event").
		TAG("set_temp_is_azure_event").
		IF(`ctx.event?.action instanceof String && ctx.event.action.startsWith('Azure')`).
		VALUE(true)
	SET("cloud.provider").
		TAG("set_cloud_provider_azure").
		IF(`ctx._temp?.is_azure_event == true`).
		VALUE("azure")
	for _, m := range []struct {
		dst, src string
	}{
		{dst: "cloud.account.id", src: "crowdstrike.AzureSubscriptionId"},
		{dst: "cloud.region", src: "crowdstrike.AzureLocation"},
		{dst: "cloud.instance.id", src: "crowdstrike.AzureVmId"},
		{dst: "cloud.instance.name", src: "crowdstrike.AzureVMName"},
	} {
		SET(m.dst).
			TAG(fmt.Sprintf("set_%s_from_%s", m.dst, m.src)).
			IF(`ctx._temp?.is_azure_event == true`).
			COPY_FROM(m.src).
			IGNORE_EMPTY(true)
	}

	for _, ip := range []struct {
		src string
		dst string
		tag string
	}{
		{src: "crowdstrike.AzurePrivateIpAddress", dst: "_temp.azure_private_ip", tag: "AzurePrivateIpAddress"},
		{src: "crowdstrike.AzureIpAddress", dst: "_temp.azure_public_ip", tag: "AzureIpAddress"},
	} {
		CONVERT(ip.dst, ip.src, "ip").
			TAG(fmt.Sprintf("convert_crowdstrike_%s_to_ip", ip.tag)).
			IF(fmt.Sprintf(`ctx._temp?.is_azure_event == true && ctx.crowdstrike?.%s != null && ctx.crowdstrike.%s != ''`, ip.tag, ip.tag)).
			ON_FAILURE(
				REMOVE(ip.src).
					TAG(fmt.Sprintf("remove_crowdstrike_%s", ip.tag)).
					IGNORE_MISSING(true),
				APPEND("error.message", errorMessage),
			)
	}
	appendTempCloudIPs("azure")
}

func gcpCloudAssetFields() {
	BLANK()
	BLANK().COMMENT("GCP FDR asset inventory → cloud.* (and host/related IPs)")

	SET("_temp.is_gcp_event").
		TAG("set_temp_is_gcp_event").
		IF(`ctx.event?.action instanceof String && ctx.event.action.startsWith('Gcp')`).
		VALUE(true)
	SET("cloud.provider").
		TAG("set_cloud_provider_gcp").
		IF(`ctx._temp?.is_gcp_event == true`).
		VALUE("gcp")
	for _, m := range []struct {
		dst, src string
	}{
		{dst: "cloud.account.id", src: "crowdstrike.GcpProjectId"},
		{dst: "cloud.project.id", src: "crowdstrike.GcpProjectId"},
		{dst: "cloud.region", src: "crowdstrike.GcpRegion"},
		{dst: "cloud.availability_zone", src: "crowdstrike.GcpZone"},
	} {
		SET(m.dst).
			TAG(fmt.Sprintf("set_%s_from_%s", m.dst, m.src)).
			IF(`ctx._temp?.is_gcp_event == true`).
			COPY_FROM(m.src).
			IGNORE_EMPTY(true)
	}
	SET("cloud.instance.id").
		TAG("set_cloud_instance_id_from_crowdstrike_GcpId").
		IF(`ctx._temp?.is_gcp_event == true && ctx.event?.action instanceof String && ctx.event.action.startsWith('GcpComputeInstance')`).
		COPY_FROM("crowdstrike.GcpId").
		IGNORE_EMPTY(true)
	SET("cloud.instance.id").
		TAG("set_cloud_instance_id_from_crowdstrike_GcpAttachedInstanceId").
		IF(`ctx._temp?.is_gcp_event == true && ctx.cloud?.instance?.id == null`).
		COPY_FROM("crowdstrike.GcpAttachedInstanceId").
		IGNORE_EMPTY(true)
	SET("cloud.instance.name").
		TAG("set_cloud_instance_name_from_crowdstrike_GcpName").
		IF(`ctx._temp?.is_gcp_event == true && ctx.event?.action instanceof String && ctx.event.action.startsWith('GcpComputeInstance')`).
		COPY_FROM("crowdstrike.GcpName").
		IGNORE_EMPTY(true)

	for _, ip := range []struct {
		src string
		dst string
		tag string
	}{
		{src: "crowdstrike.GcpNetworkIp", dst: "_temp.gcp_private_ip", tag: "GcpNetworkIp"},
		{src: "crowdstrike.GcpAccessConfigNatIp", dst: "_temp.gcp_public_ip", tag: "GcpAccessConfigNatIp"},
	} {
		CONVERT(ip.dst, ip.src, "ip").
			TAG(fmt.Sprintf("convert_crowdstrike_%s_to_ip", ip.tag)).
			IF(fmt.Sprintf(`ctx._temp?.is_gcp_event == true && ctx.crowdstrike?.%s != null && ctx.crowdstrike.%s != ''`, ip.tag, ip.tag)).
			ON_FAILURE(
				REMOVE(ip.src).
					TAG(fmt.Sprintf("remove_crowdstrike_%s", ip.tag)).
					IGNORE_MISSING(true),
				APPEND("error.message", errorMessage),
			)
	}
	appendTempCloudIPs("gcp")
}

func appendTempCloudIPs(cloud string) {
	for _, kind := range []string{"private", "public"} {
		temp := fmt.Sprintf("_temp.%s_%s_ip", cloud, kind)
		APPEND("host.ip", fmt.Sprintf(`{{{%s}}}`, temp)).
			TAG(fmt.Sprintf("append_host_ip_from_%s_%s_ip", cloud, kind)).
			IF(fmt.Sprintf(`ctx._temp?.%s_%s_ip != null`, cloud, kind)).
			ALLOW_DUPLICATES(false)
		APPEND("related.ip", fmt.Sprintf(`{{{%s}}}`, temp)).
			TAG(fmt.Sprintf("append_related_ip_from_%s_%s_ip", cloud, kind)).
			IF(fmt.Sprintf(`ctx._temp?.%s_%s_ip != null`, cloud, kind)).
			ALLOW_DUPLICATES(false)
	}
}

func threatFields() {
	BLANK().COMMENT("Threat Fields.")

	for _, field := range []struct {
		child string
		dst   string
	}{
		{child: "Technique", dst: "threat.technique.name"},
		{child: "Tactic", dst: "threat.tactic.name"},
	} {
		FOREACH("crowdstrike.Attacks",
			APPEND(field.dst, fmt.Sprintf(`{{{_ingest._value.%s}}}`, field.child)).
				ALLOW_DUPLICATES(false),
		).
			TAG(fmt.Sprintf("foreach_of_crowdstrike_Attacks_with_%s", field.child)). // Avoid hash collision warning.
			IF(`ctx.crowdstrike?.Attacks instanceof List`)
	}

	BLANK()

	FOREACH("crowdstrike.MitreAttack",
		APPEND("threat.tactic.name", `{{{_ingest._value.Tactic}}}`).
			ALLOW_DUPLICATES(false),
	).
		TAG("foreach_of_crowdstrike_MitreAttack_for_Tactic").
		IF(`ctx.crowdstrike?.MitreAttack instanceof List`)
	FOREACH("crowdstrike.MitreAttack",
		APPEND("threat.tactic.id", `{{{_ingest._value.TacticID}}}`).
			ALLOW_DUPLICATES(false),
	).
		TAG("foreach_of_crowdstrike_MitreAttack_for_TacticID").
		IF(`ctx.crowdstrike?.MitreAttack instanceof List`)
	FOREACH("crowdstrike.MitreAttack",
		APPEND("threat.technique.name", `{{{_ingest._value.Technique}}}`).
			ALLOW_DUPLICATES(false),
	).
		TAG("foreach_of_crowdstrike_MitreAttack_for_Technique").
		IF(`ctx.crowdstrike?.MitreAttack instanceof List`)
	FOREACH("crowdstrike.MitreAttack",
		APPEND("threat.technique.id", `{{{_ingest._value.TechniqueID}}}`).
			ALLOW_DUPLICATES(false),
	).
		TAG("foreach_of_crowdstrike_MitreAttack_for_TechniqueID").
		IF(`ctx.crowdstrike?.MitreAttack instanceof List`)
}

func packageFields() {
	BLANK().COMMENT("Package fields.")

	SCRIPT().
		TAG("set_browser_extension_architecture_value").
		IF(`ctx.crowdstrike?.BrowserExtensionArchitecture != null`).
		PARAMS(map[string]any{
			"0": "UNKNOWN",
			"1": "MANIFEST_V2",
			"2": "MANIFEST_V3",
			"3": "SAFARI_APP",
		}).
		SOURCE(`
		  ctx.package = ctx.package ?: [:];
		  ctx.package.architecture = params[ctx.crowdstrike.BrowserExtensionArchitecture];
		`)

	for _, change := range []struct {
		from string
		to   string
	}{
		{from: "crowdstrike.BrowserExtensionInstalledTimestamp", to: "package.installed"},
		{from: "crowdstrike.BrowserExtensionName", to: "package.name"},
		{from: "crowdstrike.BrowserExtensionPath", to: "package.path"},
		{from: "crowdstrike.BrowserExtensionVersion", to: "package.version"},
	} {
		RENAME(change.from, change.to).
			IGNORE_MISSING(true)
	}
}

func crowdstrikeFields() {
	BLANK().COMMENT("Crowdstrike fields.")

	for _, src := range []string{
		"crowdstrike.ContextProcessTagsAsString",
		"crowdstrike.PatternIdList",
		"crowdstrike.ParentProcessPatternIdList",
		"crowdstrike.GrandparentProcessPatternIdList",
		"crowdstrike.SessionPatternIdList",
	} {
		SPLIT("", src, ",").
			IGNORE_MISSING(true)
	}
	SCRIPT().
		TAG("set_browser_extension_install_method_value").
		IF(`ctx.crowdstrike?.BrowserExtensionInstallMethod != null`).
		PARAMS(map[string]any{
			"0": "UNIDENTIFIED",
			"1": "BROWSER",
			"2": "WEBSTORE",
			"3": "GPO",
			"4": "SIDELOADED",
			"5": "WEBSTORE_3RD_PARTY",
		}).
		SOURCE(`
		  ctx.crowdstrike.BrowserExtensionInstallMethod = params[ctx.crowdstrike.BrowserExtensionInstallMethod];
		`)

	for _, src := range []string{
		"crowdstrike.FalconGroupingTags",
		"crowdstrike.SensorGroupingTags",
	} {
		SPLIT("", src, `,\s?`).
			IGNORE_MISSING(true).
			IGNORE_FAILURE(true)
	}
	SCRIPT().
		TAG("convert_tags").
		DESCRIPTION("Convert tags for indexing as keyword.").
		IF(`ctx.crowdstrike?.Tags != null`).
		SOURCE(`
          def result = [];

          if (ctx.crowdstrike.Tags instanceof String) {
            def parts = ctx.crowdstrike.Tags.splitOnToken(",");
            for (def part : parts) {
              def trimmed = part.trim();
              if (trimmed != "") {
                result.add(trimmed);
              }
            }
          } else if (ctx.crowdstrike.Tags instanceof Map) {
            for (def entry : ctx.crowdstrike.Tags.entrySet()) {
              result.add(entry.getKey() + ":" + entry.getValue());
            }
          } else if (ctx.crowdstrike.Tags instanceof List) {
            for (def tag : ctx.crowdstrike.Tags) {
              if (tag instanceof Map) {
                // this format is seen in the falcon data stream
                result.add(tag["Key"] + ":" + tag["ValueString"]);
              } else if (tag instanceof String) {
                // this isn't expected but avoid throwing away indexable data
                result.add(tag);
              }
            }
          }

          ctx.crowdstrike.Tags = result;
		`)
	SPLIT("", "crowdstrike.CallStackModuleNames", `\|`).
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	for _, src := range []string{
		"crowdstrike.UserTime",
		"crowdstrike.KernelTime",
		"crowdstrike.CycleTime",
	} {
		CONVERT("", src, "long").
			IGNORE_MISSING(true)
	}
	APPEND("related.hash", `{{{crowdstrike.ConfigStateHash}}}`).
		IF(`ctx.crowdstrike?.ConfigStateHash != null && ctx.crowdstrike.ConfigStateHash != ""`).
		ALLOW_DUPLICATES(false).
		IGNORE_FAILURE(true)
	TRIM("", "crowdstrike.BootArgs").
		IGNORE_MISSING(true)
	SPLIT("", "crowdstrike.BootArgs", `\s+`).
		IGNORE_MISSING(true)
	for _, src := range []struct {
		field   string
		formats []string
		cond    string
	}{
		{field: "crowdstrike.LogonTime", formats: []string{"UNIX"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.LogonTime")},
		{field: "crowdstrike.LogoffTime", formats: []string{"UNIX"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.LogoffTime")},
		{field: "crowdstrike.ConnectTime", formats: []string{"UNIX"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.ConnectTime")},
		{field: "crowdstrike.PreviousConnectTime", formats: []string{"UNIX"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.PreviousConnectTime")},
		{field: "crowdstrike.AgentLocalTime", formats: []string{"UNIX"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.AgentLocalTime")},
		{field: "crowdstrike.FirstSeen", formats: []string{"UNIX"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.FirstSeen")},
		{field: "crowdstrike.BiosReleaseDate", formats: []string{"MM/dd/yyyy", "strict_date_optional_time"}, cond: notNullEmpytOrNone("ctx.crowdstrike?.BiosReleaseDate")},
	} {

		DATE(src.field, src.field, src.formats...).
			IF(src.cond).
			IGNORE_FAILURE(true)
	}
	for _, conv := range []struct {
		src string
		typ string
	}{
		{src: "crowdstrike.AgentTimeOffset", typ: "float"},
		{src: "crowdstrike.Timeout", typ: "long"},
		{src: "crowdstrike.PhysicalAddressLength", typ: "long"},
		{src: "crowdstrike.InterfaceIndex", typ: "long"},
		{src: "crowdstrike.NetLuidIndex", typ: "long"},
		{src: "crowdstrike.AttemptNumber", typ: "long"},
		{src: "crowdstrike.SystemTableIndex", typ: "long"},
	} {
		CONVERT("", conv.src, conv.typ).
			IGNORE_MISSING(true)
	}
	for _, src := range []string{
		"crowdstrike.NeighborList",
		"crowdstrike.ConfigStateData",
	} {
		SPLIT("", src, `\|`).
			IGNORE_MISSING(true)
	}
	for _, src := range []struct {
		value string
		cond  string
	}{
		{value: `{{{crowdstrike.LogonServer}}}`, cond: `ctx.crowdstrike?.LogonServer != null`},
		{value: `{{{crowdstrike.ClientComputerName}}}`, cond: `ctx.crowdstrike?.ClientComputerName != null`},
		{value: `{{{crowdstrike.info.user.LastLoggedOnHost}}}`, cond: `ctx.crowdstrike?.info?.user?.LastLoggedOnHost != null`},
	} {
		APPEND("related.hosts", src.value).
			IF(src.cond).
			ALLOW_DUPLICATES(false)
	}

	BLANK()
	var longFields []string
	err := json.Unmarshal(longFieldsData, &longFields)
	if err != nil {
		log.Fatal(err)
	}
	SCRIPT().
		DESCRIPTION("Remove long fields based on user input stored in _conf.long_fields*.").
		TAG("script_remove_long_fields").
		IF("ctx._conf?.long_fields == 'delete_long_fields' && ctx._conf?.long_fields_max_length != null").
		PARAMS(map[string]any{
			"potential_long_fields": longFields,
		}).
		SOURCE(`
          for (String field: params.potential_long_fields) {
            if (ctx.crowdstrike.get(field) != null && ctx.crowdstrike[field].length() > ctx._conf.long_fields_max_length) {
              ctx.crowdstrike.remove(field);
            }
          }
		`)
}

func cleanup() {
	BLANK().COMMENT("Cleanup.")

	REMOVE("crowdstrike.event_platform").
		IF(`ctx.host?.os?.type != null`).
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	REMOVE(
		"log.file.path",
		"log.offset",
	).
		IF(`ctx.aws?.s3?.bucket != null && ctx.aws.s3.object != null`).
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	REMOVE(
		"agent.ephemeral_id",
		"event.timezone",
		"log.offset",
	).
		IF(`ctx._conf?.prune_fields == true`).
		IGNORE_MISSING(true).
		IGNORE_FAILURE(true)
	REMOVE(
		"_temp",
		"crowdstrike.timestamp",
		"crowdstrike._time",
		"crowdstrike.Time",
		"crowdstrike.CreationTimeStamp",
		"crowdstrike.DomainName",
		"crowdstrike.ConnectionDirection",
		"crowdstrike.UserIsAdmin",
		"crowdstrike.UTCTimestamp",
		"crowdstrike.TargetDirectoryName",
		"crowdstrike.BrowserExtensionArchitecture",
		"crowdstrike.MitreAttack",
		"_conf",
	).IGNORE_MISSING(true)
	SCRIPT().
		TAG("remove_nulls").
		DESCRIPTION("This script processor iterates over the whole document to remove fields with null values.").
		SOURCE(`
          void handleMap(Map map) {
            map.values().removeIf(v -> {
              if (v instanceof Map) {
                  handleMap(v);
              } else if (v instanceof List) {
                  handleList(v);
              }
              return v == null || v == '' || v == '-' || v == 'none' || (v instanceof Map && v.size() == 0) || (v instanceof List && v.size() == 0)
            });
          }
          void handleList(List list) {
            list.removeIf(v -> {
              if (v instanceof Map) {
                  handleMap(v);
              } else if (v instanceof List) {
                  handleList(v);
              }
              return v == null || v == '' || v == '-' || v == 'none' || (v instanceof Map && v.size() == 0) || (v instanceof List && v.size() == 0)
            });
          }
          handleMap(ctx);
		`)

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

func notNullEmpytOrNone(f string) string {
	return fmt.Sprintf("%[1]s != null && %[2]s != '' && %[2]s != 'none'", f, strings.ReplaceAll(f, "?", ""))
}

const errorMessage = `Processor {{{_ingest.on_failure_processor_type}}} with tag {{{_ingest.on_failure_processor_tag}}} in pipeline {{{_ingest.on_failure_pipeline}}} failed with message: {{{_ingest.on_failure_message}}}`
