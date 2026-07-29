package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	. "github.com/efd6/dispear"
)

func main() {
	dir := flag.String("dir", "", "direction (required: inbound or outbound)")
	flag.Parse()
	if *dir != "inbound" && *dir != "outbound" {
		flag.Usage()
		os.Exit(1)
	}

	local := "source"
	remote := "destination"
	if *dir == "inbound" {
		local = "destination"
		remote = "source"
	}

	DESCRIPTION(fmt.Sprintf("Pipeline for processing %s network details", *dir))

	for _, src := range []string{
		"CurrentLocalIP",
		"LocalIP",
	} {
		SET(fmt.Sprintf("%s.ip", local)).
			TAG(strings.ToLower(fmt.Sprintf("%[1]s_ip_from_%[2]s", local, src))).
			IF(fmt.Sprintf(`ctx.%[1]s?.ip == null && ctx.crowdstrike?.%[2]s != null`, local, src)).
			VALUE(fmt.Sprintf(`{{{crowdstrike.%s}}}`, src))
	}
	for _, src := range []string{
		"LocalAddressIP4",
		"LocalAddressIP6",
	} {
		SET(fmt.Sprintf("%s.ip", local)).
			TAG(strings.ToLower(fmt.Sprintf("%[1]s_ip_from_%[2]s", local, src))).
			IF(fmt.Sprintf(`ctx.%[1]s?.ip == null && ctx.crowdstrike?.%[2]s instanceof List && ctx.crowdstrike.%[2]s.length > 0`, local, src)).
			VALUE(fmt.Sprintf(`{{{crowdstrike.%s.0}}}`, src))
	}

	CONVERT("", fmt.Sprintf("%s.ip", local), "ip").
		IGNORE_MISSING(true).
		ON_FAILURE(
			REMOVE(fmt.Sprintf("%s.ip", local)).
				IGNORE_MISSING(true),
			APPEND("error.message", errorMessage),
		)
	SET(fmt.Sprintf("%s.address", local)).
		COPY_FROM(fmt.Sprintf("%s.ip", local)).
		IGNORE_EMPTY(true)

	RENAME("crowdstrike.LocalPort", fmt.Sprintf("%s.port", local)).
		IGNORE_MISSING(true)
	RENAME("crowdstrike.MAC", fmt.Sprintf("%s.mac", local)).
		IGNORE_MISSING(true)
	RENAME("crowdstrike.PhysicalAddress", fmt.Sprintf("%s.mac", local)).
		IF(fmt.Sprintf(`ctx.%s?.mac == null`, local)).
		IGNORE_MISSING(true)

	for _, src := range []string{
		"RemoteAddressIP4",
		"RemoteAddressIP6",
	} {
		src = fmt.Sprintf("crowdstrike.%s", src)
		CONVERT("", src, "ip").
			IGNORE_MISSING(true).
			ON_FAILURE(
				REMOVE(src).
					IGNORE_MISSING(true),
				APPEND("error.message", errorMessage),
			)
		RENAME(src, fmt.Sprintf("%s.ip", remote)).
			IGNORE_MISSING(true)
	}
	SET(fmt.Sprintf("%s.address", remote)).
		COPY_FROM(fmt.Sprintf("%s.ip", remote)).
		IGNORE_EMPTY(true)
	RENAME("crowdstrike.RemotePort", fmt.Sprintf("%s.port", remote)).
		IGNORE_MISSING(true)

	ON_FAILURE(
		SET("event.kind").
			VALUE("pipeline_error"),
		APPEND("tags", "preserve_original_event").
			ALLOW_DUPLICATES(false),
		APPEND("error.message", errorMessage),
	)

	Generate()
}

const errorMessage = `Processor {{{_ingest.on_failure_processor_type}}} with tag {{{_ingest.on_failure_processor_tag}}} in pipeline {{{_ingest.on_failure_pipeline}}} failed with message: {{{_ingest.on_failure_message}}}`
