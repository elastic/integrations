package main

import (
	"encoding/json"
	"log"

	// For categorize.json.
	_ "embed"

	. "github.com/efd6/dispear"
)

//go:embed categorize.json
var data []byte

func main() {
	var cats map[string]any
	err := json.Unmarshal(data, &cats)
	if err != nil {
		log.Fatal(err)
	}

	DESCRIPTION("Pipeline for categorizing Crowdstrike events")

	SET("event.category").
		IF(`ctx.crowdstrike?.event_simpleName != null && ctx.crowdstrike.event_simpleName.endsWith('Written')`).
		VALUE([]string{"file"})

	SCRIPT().
		DESCRIPTION("Categorize events.").
		TAG("categorize_events").
		PARAMS(cats).
		SOURCE(`
          def m = params.get(ctx.crowdstrike?.event_simpleName);
          if (m != null) {
            m.forEach((k, v) -> {
              if (v instanceof List) {
                ctx.event[k] = new ArrayList(v);
              } else {
                ctx.event[k] = v;
              }
            });
          }
		`)

	Generate()
}
