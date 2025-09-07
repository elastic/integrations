# CEL integration guide

## Execution Model & State Lifecycle

CEL integrations in Elastic run on a **tick-based model** controlled by the `interval` setting in your package. Each invocation of the `program:` field is a full, stateless evaluation from the top of your CEL logic to its return value.

* **Each tick starts with `state`**: a map containing everything persisted from previous runs.
* The **output replaces state**, unless you use `.with(...)` to explicitly preserve fields.
* Returning `want_more: true` triggers an immediate re-run (pagination cycle).
* If `want_more` is false, Elastic Agent waits until the next `interval`.
* Only `state.cursor` is persisted across **agent restarts**. Everything else is **ephemeral** and lost on restart.
* Top-level keys like `events`, `want_more`, `metrics`, etc. are **reserved** and removed after the run. Use `state` to persist values across invocations.

---

## Runtime Objects & Helper Functions

CEL programs operate on a set of core primitives and helpers:

| Category           | Examples & Usage                                                                   |
| ------------------ | ---------------------------------------------------------------------------------- |
| **State**          | `state`, `state.with({...})`, `state.jobs[0]`                                      |
| **Binding**        | `expr.as(name, expr2)` binds `name` **only in `expr2`**, returns result of `expr2` |
| **Requests**       | `request("GET", url).with({Header: {...}}).do_request()`                           |
| **Responses**      | `resp.StatusCode`, `bytes(resp.Body).decode_json()`                                |
| **JSON decode**    | **Always decode once**, e.g. `bytes(resp.Body).decode_json().as(body, ...)`        |
| **Null-safe ops**  | Use `?`, `optional.of(...)`, `has(...)`, and `.orValue(...)`                       |
| **Mapping**        | `array.map(e, expr)`, use `.flatten()` for nested arrays                           |
| **Duration/time**  | `duration("24h")`, `now`, `timestamp(...)`, `format(...)`                          |
| **Dynamic access** | `dyn(obj).someField` for untyped access                                            |

---

## A Minimal Hello World Example

This basic pattern demonstrates a single request, simple decoding, and event output:

```yaml
program: |
  request("GET", state.url + "/objects").with({
    "Header": {"Authorization": ["Bearer " + state.token]}
  }).do_request().as(resp,
    resp.StatusCode == 200 ?
      bytes(resp.Body).decode_json().as(body, {
        "events": body.results.map(r, {"message": r}),
        "want_more": false
      })
    :
      {
        "events": {
          "error": {
            "code": string(resp.StatusCode),
            "message": "GET failed: " + (size(resp.Body)!=0 ? string(resp.Body) : string(resp.Status))
          }
        },
        "want_more": false
      }
  )
```

Notes:

* `events` can be an object or array of messages.
* Always check status codes.
* Use `state.with(...)` if anything must be carried forward.

---

## String Construction & Format Query

CEL doesn't support string interpolation. Instead, use classic concatenation or `.format_query()` for query strings.

### Concatenation:

```cel
"Authorization": "Bearer " + state.token
"url": state.url.trim_right("/") + "/items/" + id
```

### Query building:

```cel
{
  "limit": ["100"],
  "sort": ["desc"],
  "start": [state.cursor.last_seen_id]
}.format_query()
```

✅ All values must be arrays of strings
✅ Used to safely produce query strings like `?limit=100&sort=desc`

---

## State Preservation with `.with(...)`

By default, returning a plain map like this:

```cel
{
  "events": [...],
  "want_more": true
}
```

... will discard everything else in the previous `state`.

To preserve additional keys (e.g. `state.url`, `state.batch_size`, etc.), always wrap outputs like this:

```cel
state.with({
  "events": [...],
  "want_more": true
})
```

✅ Only `.with(...)` guarantees state merging.
✅ Use `.as(name, expr)` for scoped logic, but remember to `.with(...)` when returning.

---

## Error Handling & Logging

You must never crash the program. CEL integrations treat failure as a **non-event** — nothing is stored or retried. Always return structured error messages.

### Good pattern:

```cel
{
  "events": {
    "error": {
      "code": string(resp.StatusCode),
      "id": string(resp.Status),
      "message": "GET /endpoint: " + (
        size(resp.Body) != 0 ? string(resp.Body) : string(resp.Status)
      )
    }
  },
  "want_more": false
}
```

Notes:

* Prefer single object (not array) for `events.error`.
* Avoid failing silently — log **what** failed and **why**.
* Be careful not to emit secrets. Use `redact.fields` for tokens/passwords.

---

## Pagination Strategies

Pagination in CEL follows two styles:

### Token-based (`links.next`, `after`, `cursor`, etc.)

```cel
"next": body.links.next,
"want_more": has(body.links) && body.links.next != ""
```

### Count-based (`limit`/`offset`, `page`, `hasNextPage`, etc.)

```cel
"cursor": { "offset": int(state.cursor.offset or 0) + 100 },
"want_more": size(body.results) == 100
```

### Stateful queue pattern (multi-stage pagination):

Create a list of job dicts like:

```cel
state.jobs = [
  {"type": "threats_page", "url": "..."},
  {"type": "companies_page", "url": "...", "threat": {...}}
]
```

Each run pops `jobs[0]`, processes it, and updates the list using `tail(state.jobs)`.

Benefits:

* CEL doesn’t support loops/recursion, but queues simulate it.
* Can combine multiple APIs in a clean DAG-like flow.
* Allows memory-safe streaming: one job per run.


## Job Queues & Multi-Stage Traversal

When APIs require multi-step traversal (e.g., get threats → companies → evidence), CEL’s lack of loops means you must simulate the control flow using a **flat job queue** in `state.jobs`.

### Pattern

Each job is a map like:

```json
{ "type": "companies_page", "threat": {...}, "url": "..." }
```

You:

* Process `state.jobs[0]`
* Replace the queue with `tail(state.jobs)` + new jobs

### Benefits

* Works across nested levels
* Enables depth-first (`new_jobs + tail(...)`) or breadth-first (`tail(...) + new_jobs`)
* Each job is **atomic**, so the agent can resume cleanly on restart

### Common job types:

* `threats_page`
* `companies_page`
* `evidence_page`

Initialize queue on first run:

```cel
has(state.jobs) && size(state.jobs) > 0 ? state : state.with({ jobs: [{...}] })
```

---

## Nested Enrichment Calls

You can enrich records by doing **secondary requests per item** using `.map(...) → .do_request()`.

### Pattern:

```cel
body.results.map(it,
  request("GET", state.url + "/details/" + it.id)
  .do_request().as(resp,
    resp.StatusCode == 200 ?
      bytes(resp.Body).decode_json().as(detail, {"message": detail})
    :
      {"error": "detail fetch failed"}
  )
).flatten()
```

### Key Points

* Always decode `resp.Body` before access
* Always use `.flatten()` after `map(..., request(...))` to ensure the result is a flat array
* These can be expensive — consider limiting nesting depth or caching in state

---

## Cursors & Deduplication

Cursors track your **last-seen position**, so the agent doesn’t re-fetch data across runs.

### Best practices:

* Always store under `state.cursor`: only this is persisted across agent restarts
* Use:

  * Timestamps (`first_seen_date`, `last_updated`)
  * Numeric IDs
  * Composite keys if needed

### Pattern:

```cel
"cursor": {
  "last_seen": body.results.map(e, e.timestamp).max()
}
```

### Deduping

Use `fingerprint` in ingest pipeline to avoid duplicates. Example:

```yaml
- fingerprint:
    fields: [bitsight]
    target_field: _id
```

---

## Authentication Recipes

Most APIs require authentication, usually one of the following:

### Bearer token

```cel
"Authorization": ["Bearer " + state.token]
```

### Basic auth

```cel
"Authorization": ["Basic " + (state.token + ":").base64()]
```

### Cookie dance

1. Login request returns cookie in `Set-Cookie`
2. Store cookie in `state.cursor.cookie`
3. Use it in all headers

### OAuth2

1. Request token
2. Store token and expiry in `cursor.auth_data`
3. Refresh if `expires` is near

---

## Rate-Limit & Retry Controls

Elastic Agent doesn’t retry on failure unless you return `want_more: true`. CEL lets you be smart about API throttling.

### Strategy:

```cel
"want_more": !(resp.StatusCode == 429 || resp.StatusCode >= 500)
```

This avoids retrying on rate-limit or server errors.

---

## Emitting Events Correctly

For real event output:

### Required format:

```cel
"events": [
  {
    "message": your_structured_json_map,
    ?"event.original": state.?preserve_original_event.orValue(false) ? optional.of(msg.encode_json()) : optional.none()
  }
]
```

### Don’t:

* Return raw strings or partial maps
* Emit events without a `message` key
* Forget to wrap things in `as(msg, …)` if you want to reuse it

### Errors:

Emit as structured object (not in array!):

```cel
"events": {
  "error": {
    "code": string(resp.StatusCode),
    "message": "GET failed: " + string(resp.Body)
  }
}
```

### Use polling placeholders

```cel
"events": [{"message": {"event": {"reason": "polling"}}}]
```

Drop them in pipeline.

If at any point an empty event is emitted, the integration will stop and only continue with next interval!!!
So be careful with this and make sure to always return a valid event if you want to continue.

---

## Handling Empty Responses Gracefully

Many APIs return a valid HTTP 200 with an empty list. You should handle this explicitly:

### Example:

```cel
has(body.results) && size(body.results) > 0 ?
  // handle items
:
  {
    // emit some event or handle it otherwise

    // And then remove useless job e.g. depends on your logic
    "jobs": tail(state.jobs),
    "want_more": true
  }
```

---

## Dual Execution Loops Explained

There are **two levels** of looping in Elastic CEL integrations:

### 1. Pagination loop (`want_more`)

* If `want_more` is `true`, Agent immediately re-runs the program
* Happens up to `max_executions` times per tick
* Best for consuming paginated API data quickly

### 2. Poll interval (`interval`)

* Scheduled re-invocation of the input
* Occurs when `want_more` is `false`
* State between ticks is carried forward

### Summary

| Loop        | Trigger     | State persists? | Used for                   |
| ----------- | ----------- | --------------- | -------------------------- |
| `want_more` | True return | Yes             | Page-through within a tick |
| `interval`  | Timer tick  | Yes             | Full integration cycle     |

---

## Ingest-Pipeline Integration

Once events are emitted, your ingest pipeline transforms and enriches them.

### Typical flow:

```yaml
- rename:
    field: message
    target_field: bitsight

- drop:
    if: ctx.bitsight?.event?.reason == 'polling'
```

### Preserving structure:

Use `preserve_original_event` to copy the full emitted `message` into `event.original`.

### Tips:

* Normalize timestamps to `@timestamp`
* Apply `fingerprint` to dedupe
* Use `script` to drop empty fields
* Use `grok` for string parsing

---

## Testing & Debugging Tips

CEL doesn’t support printing or logging — but you can emulate it.

### Emit debugging events

Emit structured trace messages:

```cel
"events": [{
  "message": {
    "debug": "reached stage X",
    "job": job
  }
}]
```

### Trace headers

Set:

```yaml
resource.tracer.filename: "../../logs/cel/http-request-trace-*.ndjson"
```

This logs each HTTP call made by the input.

---


## End-to-end examples


These three annotated programs round out Chapter 11 with concrete, production-tested blueprints for:

* **Work-list, time-window paging (Abnormal)**
* **OAuth2 + Link headers (Auth0)**
* **Cookie session + multi-queue offsets (BeyondInsight)**

They illustrate how far you can push CEL’s functional style while keeping state machine logic declarative and transparent.


## A Abnormal Security – *AI Security Mailbox*

*A two-level “work-list” pattern (parent list → child detail)*

```yaml
config_version: 2
interval: {{interval}}
{{#if enable_request_tracer}}
resource.tracer.filename: "../../logs/cel/http-request-trace-*.ndjson"
resource.tracer.maxbackups: 5
{{/if}}
{{#if proxy_url}}
resource.proxy_url: {{proxy_url}}
{{/if}}
{{#if ssl}}
resource.ssl: {{ssl}}
{{/if}}
{{#if http_client_timeout}}
resource.timeout: {{http_client_timeout}}
{{/if}}
resource.url: {{url}}
state:
  initial_interval: {{initial_interval}}
  page_size: {{page_size}}
  access_token: {{access_token}}
  next_page: 1
redact:
  fields:
    - access_token
program: |
  (
    has(state.worklist) && size(state.worklist) > 0 ?     // ① still processing IDs?
      state                                               //     → skip top call, jump to child
    :
      (
        state.?want_more.orValue(false) ?                 // ② second run of same time-window?
          state                                           //     → keep previous start/end
        :
          state.with({                                    //     first run → compute window
            "start_time":
              state.?cursor.last_timestamp.orValue(       //       ▸ resume from last timestamp
                 (now - duration(state.initial_interval))
                 .format(time_layout.RFC3339)),
            "end_time": now.format(time_layout.RFC3339),
          })
      )
      .as(state,                                           // ③ scoped re-binding
        state.with(
          request("GET",
            state.url.trim_right("/") +
            "/v1/abusecampaigns?" + {                     // ④ top-level LIST call
              "pageSize": [string(state.page_size)],
              "pageNumber": [string(state.next_page)],
              "filter": [
                "lastReportedTime gte " + state.start_time +
                " lte " + state.end_time
              ]
            }.format_query()
          ).with({
            "Header": {
              "Authorization": ["Bearer " + string(state.access_token)]  // ▸ auth header
            }
          }).do_request().as(resp, resp.StatusCode == 200 ?
            bytes(resp.Body).decode_json().as(body, {     // ⑤ success → create work-list
              "worklist": body.campaigns.map(e, e.campaignId),
              "next":     0                                //     index of first child to pull
            })
          :
            {                                              // ⑥ error → synthetic event
              "events": {
                "error": {
                  "code": string(resp.StatusCode),
                  "id": string(resp.Status),
                  "message": "GET:"+(
                    size(resp.Body) != 0 ?
                      string(resp.Body)
                    :
                      string(resp.Status) + ' (' + string(resp.StatusCode) + ')'
                  ),
                },
              },
              "want_more": false,
            }
          )
        )
      )
  )
  .as(state,                                              // ⑦ CHILD request loop
    state.with(
      !has(state.worklist) ? state                         //     abort if top call failed
      : state.next < size(state.worklist) ?
          request("GET",
            state.url.trim_right("/") +
            "/v1/abusecampaigns/" + state.worklist[state.next]  //    /v1/abusecampaigns/{id}
          ).with({
            "Header": {
              "Authorization": ["Bearer " + string(state.access_token)]
            }
          }).do_request().as(resp, resp.StatusCode == 200 ?
            bytes(resp.Body).decode_json().as(body,{
              "events": [{
                "message": body.encode_json()              // one event
              }],
              "cursor": {
                "last_timestamp": state.end_time           // update cursor
              },
              "worklist": int(state.next) + 1 < size(state.worklist) ?
                 state.worklist : [],                      // still items?
              "next": int(state.next) + 1 < size(state.worklist) ?
                 state.next + 1 : 0,
              "next_page": int(state.next) + 1 < size(state.worklist) ?
                 state.next_page : int(state.next_page) + 1,  // same page or next
              "want_more": true
            })
          :
            {
              "events": {
                "error": {
                  "code": string(resp.StatusCode),
                  "id": string(resp.Status),
                  "message": "GET:"+(
                    size(resp.Body) != 0 ?
                      string(resp.Body)
                    :
                      string(resp.Status) + ' (' + string(resp.StatusCode) + ')'
                  ),
                },
              },
              "want_more": false,
            }
          )
      :
        {
          "events": [],
          "want_more": false,
          "next_page": 1                                   // list exhausted
        }
    )
  )
tags:
{{#if preserve_original_event}}
  - preserve_original_event
{{/if}}
{{#if preserve_duplicate_custom_fields}}
  - preserve_duplicate_custom_fields
{{/if}}
{{#each tags as |tag|}}
  - {{tag}}
{{/each}}
{{#contains "forwarded" tags}}
publisher_pipeline.disable_host: true
{{/contains}}
{{#if processors}}
processors:
{{processors}}
{{/if}}

```

**Key take-aways**

| Idea                               | Where      | Why it matters                                                                            |
| ---------------------------------- | ---------- | ----------------------------------------------------------------------------------------- |
| Work-list array (`state.worklist`) | line 1     | Holds *only IDs* of campaigns. Keeps memory small and avoids multi-page child pagination. |
| Two-phase window logic             | lines 7-18 | First run => define `start_time`/`end_time`; subsequent `want_more` cycles reuse them.    |
| Per-item cursor update             | line 45    | Once *all* items of a window are processed the next outer call moves `next_page` forward. |
| Flat events                        | line 40    | Each campaign detail is emitted as one event, wrapped in `{message: …}`.                  |

---

## B Auth0 – *Logs API*

*OAuth2 “pre-flight”, Link-header pagination & dynamic start ID*

```yaml
config_version: 2
interval: {{interval}}
{{#if enable_request_tracer}}
resource.tracer.filename: "../../logs/cel/http-request-trace-*.ndjson"
request.tracer.maxbackups: 5
{{/if}}
{{#if proxy_url}}
resource.proxy_url: {{proxy_url}}
{{/if}}
{{#if ssl}}
resource.ssl: {{ssl}}
{{/if}}
{{#if http_client_timeout}}
resource.timeout: {{http_client_timeout}}
{{/if}}
resource.url: {{url}}
state:
  client_id: {{client_id}}
  client_secret: {{client_secret}}
  look_back: {{initial_interval}}
  want_more: false
  take: {{batch_size}}
redact:
  fields:
    - client_secret
program: |
  state.with(                                           // ① always create a new scope
    post(state.url.trim_right("/") + "/oauth/token",    // ② fetch access-token
      "application/json",
      {
        "client_id":     state.client_id,
        "client_secret": state.client_secret,
        "audience":      state.url.trim_right("/") + "/api/v2/",
        "grant_type":    "client_credentials"
      }.encode_json()
    )
    .as(auth_resp, auth_resp.StatusCode != 200 ?
      { "events": {                                     // ③ auth error
          "error": {
            "code": string(auth_resp.StatusCode),
            "id": string(auth_resp.Status),
            "message": "POST:"+(
              size(auth_resp.Body) != 0 ?
                string(auth_resp.Body)
              :
                string(auth_resp.Status) + ' (' + string(auth_resp.StatusCode) + ')'
            ),
          }
        },
        "want_more": false
      }
    :
      { "Body": bytes(auth_resp.Body).decode_json() }   // ④ token ok
    )
    .as(token,
      has(token.events) ? token                         // if auth failed
      :
      get_request(                                      // ⑤ data call
        state.?next.orValue(                            // bulk: either
          has(state.?cursor.next) ?                     //   ▸ follow rel=next
            state.cursor.next.parse_url().with({
              "RawQuery":
                state.cursor.next.parse_url().RawQuery
                .parse_query().with({ ?"take": has(state.take) ?
                  optional.of([string(state.take)])     //     (keep user take)
                : optional.none()
              }).format_query()
            }).format_url()
          :
            state.url.trim_right("/") + "/api/v2/logs?" + {
              ?"take": has(state.take) ?
                optional.of([string(state.take)])       //   OR ▸ first run
              : optional.none(),
              ?"from": optional.of([                    //     look back X hrs
                "900" +
                (now-duration(state.look_back)).format("20060102150405") +
                "000000000000000000000000000000000000000"  //   “Log ID” prefix
              ])
            }.format_query()
        )
      )
      .with({
        "Header": {
          "Authorization": [token.?Body.token_type.orValue("Bearer") + " " + token.?Body.access_token.orValue("MISSING")],
          "Accept": ["application/json"]
        }
      })
      .do_request().as(resp, resp.StatusCode != 200 ?
        { "events": {                                   // ⑥ data call error
            "error": {
              "code": string(resp.StatusCode),
              "id": string(resp.Status),
              "message": "GET:"+(
                size(resp.Body) != 0 ?
                  string(resp.Body)
                :
                  string(resp.Status) + ' (' + string(resp.StatusCode) + ')'
              ),
            }
          },
          "want_more": false
        }
      :
        { "Body": bytes(resp.Body).decode_json(),
          ?"next": resp.Header.?Link[0].orValue("").as(next,
            next.split(";").as(attrs,
              attrs.exists(attr, attr.contains('rel="next"')) ?
                attrs.map(attr,
                  attr.matches("^<https?://"),
                  attr.trim_prefix('<').trim_suffix('>')
                )[?0]
              : optional.none()
            )
          )
        }
        .as(result, result.with({                        // ⑦ build output state
          "events": result.Body.map(e, {
            "json": {
              "log_id": e.log_id,
              "data": e
            }
          }),
          "cursor": { ?"next": result.?next },
          "want_more": has(result.next) && size(result.Body) != 0
        }).drop("Body"))
      )
    )
  )
tags:
{{#if preserve_original_event}}
  - preserve_original_event
{{/if}}
{{#each tags as |tag|}}
  - {{tag}}
{{/each}}
{{#contains "forwarded" tags}}
publisher_pipeline.disable_host: true
{{/contains}}
{{#if processors}}
processors:
{{processors}}
{{/if}}

```

**Highlights**

| Feature                                          | Why it’s interesting                                                                                              |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| **Token fetch every cycle** – no `state` caching | Simpler; the Auth0 token endpoint is cheap and rate-limit tolerant.                                               |
| **Link-header parsing**                          | Standard HTTP `Link: <..>; rel="next"` converted into `cursor.next`.                                              |
| **Dynamic back-fill**                            | First run constructs *synthetic* log-ID (“900yyyymmddhhMM…”) so old data can be pulled without knowing a real ID. |
| **`get_request()` helper**                       | Uses a pre-built URL that already contains query params; easier than `request("GET", …)`.                         |

---

## C BeyondInsight Password Safe – *Asset stream*

*Cookie-based auth **plus** multi-workgroup queue with offset pagination*

```yaml
config_version: 2
interval: {{interval}}
resource.tracer:
  enabled: {{enable_request_tracer}}
  filename: "../../logs/cel/http-request-trace-*.ndjson"
  maxbackups: 5
{{#if proxy_url}}
resource.proxy_url: {{proxy_url}}
{{/if}}
{{#if http_client_timeout}}
resource.timeout: {{http_client_timeout}}
{{/if}}
resource.ssl.renegotiation: freely
resource.url: {{url}}
{{#if ssl}}
resource.ssl: {{ssl}}
{{/if}}
state:
  limit: {{limit}}
  apikey: {{apikey}}
  password: {{password}}
  username: {{username}}
redact:
  fields:
    - apikey
    - password
program: |-
  state.?cursor.cookies.orValue(                      // ① we have cookie cached?
  	// Authenticating using API to retrieve Cookie
  	request("POST", state.url.trim_suffix("/") + "/Auth/SignAppin").with(
  		{
  			"Header": {
  				"Authorization": [
  					"PS-Auth key=" + state.apikey +     //      API key
  					";runas=" + state.username +        //      run-as user
  					((state.?password.orValue("") != "") ? (";pwd=[" + state.password + "];") : ""),  // (opt) password
  				],
  				"Content-Type": ["application/json"],
  			},
  		}
  	).do_request().as(resp,
  		resp.Header["Set-Cookie"]                      // returns Set-Cookie header
  	)
  ).as(cookies,
  	state.?cursor.asset_reqs.orValue(                 // ② queue of (workgroup,offset)
  		request("GET", state.url.trim_suffix("/") + "/Workgroups").with(
  			{
  				"Header": {
  					"Content-Type": ["application/json"],
  					"Cookie": cookies,
  				},
  			}
  		).do_request().as(resp,
  			(resp.StatusCode == 200) ?
  				bytes(resp.Body).decode_json().as(workgroups,
  					workgroups.map(wg, [string(wg.ID), 0])   // start offset=0 per group
  				)
  			:
  				[]                                          // login failed
  		)
  	).as(asset_reqs,
  		(asset_reqs == []) ?                            // ③ nothing to do
  			state.with(
  				{
  					"events": [],
  					"want_more": false,
  					"cursor": {
  						"cookies": cookies,
  					},
  				}
  			)
  		:
  			{
  				"workgroup_id": asset_reqs[0][0],           // ④ pop first tuple
  				"offset": asset_reqs[0][1],
  				"rest_workgroups": tail(asset_reqs),
  			}.as(r,
  				request(
  					"GET",
  					state.url.trim_suffix("/") + "/Workgroups/" + r.workgroup_id + "/Assets?" + {
  						"limit": [string(state.limit)],
  						"offset": [string(r.offset)],
  					}.format_query()
  				).with(
  					{
  						"Header": {
  							"Content-Type": ["application/json"],
  							"Cookie": cookies,
  						},
  					}
  				).do_request().as(assetResp,
  					(assetResp.StatusCode != 200) ?
  						state.with(
  							{
  								"events": {"error": {"message": "Authentication expired or incorrect. Clearing and retrying...", "statuscode": string(assetResp.StatusCode)}},  // bad cookie → clear & retry
  								"want_more": false,
  							}
  						)
  					:
  						bytes(assetResp.Body).decode_json().as(assetBody,
  							(
  								(size(assetBody.Data) + int(r.offset) < int(assetBody.TotalCount)) ?
  									([[r.workgroup_id, int(r.offset) + size(assetBody.Data)]] + r.rest_workgroups)  // ⑤ queue next page / next wg
  								:
  									r.rest_workgroups
  							).as(asset_reqs,
  								state.with(
  									{
  										"events": assetBody.Data.map(e,
  											{
  												"message": e,
  												?"event.original": state.?preserve_original_event.orValue(false) ? optional.of(e.encode_json()) : optional.none(),
  											}
  										),
  										"want_more": true,
  										"cursor": {
  											"cookies": cookies,              // persist cookie
  											"asset_reqs": asset_reqs         // persist queue
  										},
  									}
  								)
  							)
  						)
  				)
  			)
  	)
  )
tags:
{{#if preserve_original_event}}
  - preserve_original_event
{{/if}}
{{#each tags as |tag|}}
  - {{tag}}
{{/each}}
{{#contains "forwarded" tags}}
publisher_pipeline.disable_host: true
{{/contains}}
{{#if processors}}
processors:
{{processors}}
{{/if}}

```

**What makes it stand out**

| Point                       | Detail                                                                                                         |
| --------------------------- | -------------------------------------------------------------------------------------------------------------- |
| **Cookie cached in cursor** | Login is expensive; cookie persists until 401, then cleared to force re-auth.                                  |
| **Double queue**            | Outer queue = list of workgroups; while a group has > `limit` assets, it re-queues itself with updated offset. |
| **Offset math**             | `offset + size(Data) < TotalCount` decides if more pages are needed inside same group.                         |
| **Tail helper**             | `tail(array)` removes first element; CEL built-in.                                                             |
| **Flexible password**       | If `password` config omitted, the `pwd=[…]` segment is dropped.                                                |

*End result:* the stream walks every workgroup, paginates each fully, **and** survives cookie expiry without manual intervention.


## Full Bitsight Example with CEL and Ingest Pipeline with multi stage nested API calls

```yaml
# Bitsight Vulnerability → Evidence three-stage integration
# This cel.yml.hbs implements a depth-first (LIFO) work-queue that walks the
# Bitsight Threats API in three nested levels:
#   1) Threat list   (/ratings/v2/threats)                           - A-level
#   2) Companies per threat (/ratings/v2/threats/{t}/companies)      - B-level
#   3) Evidence  per company (/ratings/v2/threats/{t}/companies/{c}/evidence) - C-level
# The queue lives in `state.jobs` and each run processes **exactly one** job -
# this keeps memory stable and lets the Agent resume cleanly after restarts.
# New child jobs are *prepended* to the list (LIFO) so we always finish a
# branch before moving on to the next threat.
#
# Cursor logic:
#  • `cursor.last_first_seen_date` remembers the date we last started from.
#  • On the very first run we look back `initial_interval` (e.g. "720h").
#  • At the end of a full cycle (queue empty) we persist the **same** start
#    date - this way the next schedule begins where the previous left off.
#
# Authentication:
#  • Bitsight uses *Basic* auth with the API token as the **username** and an
#    empty password.  We build the header once per request.
#
# Error handling:
#  • All HTTP are logged as error events with the status code and message.
#  • The failed job is *dropped* so we don't loop forever.
#
# Pagination:
#  • Every endpoint supports `limit` + `links.next` full URL.  We enqueue the
#    `links.next` URL (same job type) whenever it is present and non-empty.
#
# Output events:
#  • Each evidence row becomes **one** JSON document:
#    {
#      "threat": { full threat JSON },
#      "company": { full company JSON },
#      "evidence": { evidence row JSON }
#    }
config_version: 2
interval: {{interval}}
{{#if enable_request_tracer}}
resource.tracer.filename: "../../logs/cel/http-request-trace-*.ndjson"
resource.tracer.maxbackups: 5
{{/if}}
{{#if proxy_url}}
resource.proxy_url: {{proxy_url}}
{{/if}}
{{#if ssl}}
resource.ssl: {{ssl}}
{{/if}}
{{#if http_client_timeout}}
resource.timeout: {{http_client_timeout}}
{{/if}}
resource.url: {{url}}
{{#if resource_rate_limit_limit}}
resource.rate_limit.limit: {{resource_rate_limit_limit}}
{{/if}}
{{#if resource_rate_limit_burst}}
resource.rate_limit.burst: {{resource_rate_limit_burst}}
{{/if}}

{{#if resource_retry_max_attempts}}
resource.retry.max_attempts: {{resource_retry_max_attempts}}
{{/if}}

{{#if resource_retry_wait_min}}
resource.retry.wait_min: {{resource_retry_wait_min}}
{{/if}}

{{#if resource_retry_wait_max}}
resource.retry.wait_max: {{resource_retry_wait_max}}
{{/if}}

state:
  url: {{url}} 
  token: {{token}}
  batch_size: {{batch_size}}
  initial_interval: {{initial_interval}}  # e.g. "720h" (=30 days)
  preserve_original_event: {{preserve_original_event}}

redact:
  fields:
    - token

program: |-
  (
    //    Build the job queue
    //    First, ensure start_date exists
    //    Use previous state if we are in a pagination want_more cycle
    //    Otherwise its a new run and we use the stored cursor or the initial interval
    state.with({
      "start_date": state.?start_date.orValue(
        state.?cursor.last_first_seen_date.orValue(
          (now - duration(state.initial_interval)).format("2006-01-02")
        )
      )
    })
    .as(state, state.with(
      // If we are in a pagination cycle, the jobs are already set
      has(state.jobs) && size(state.jobs) > 0 ?
        state
      :
        // If we have a new run, we need to build the job queue
        // We use the start_date to build the first job
        {
          "jobs": [{
            "type": "threats_page",
            "url": state.url.trim_right("/") + "/ratings/v2/threats/?" + {
              "category_slug": ["vulnerability"],
              "first_seen_date_gte": [state.start_date],
              "limit": [string(state.batch_size)],
              "sort" : ["first_seen_date"]
            }.format_query()
          }]
        }
    ))
  )
  .as(state, state.with(
    //    Pop the first job (LIFO) and dispatch on its `type`.
    //    We *always* build a new output map that contains at minimum
    //    `jobs`, `events`.
    //    We have the state.with in scope here so we preserve all other
    //    state variables which we dont explicitly change.
    state.jobs[0].as(job,
      job.?url.orValue(null) != null ? (
        // A:  Threats page  →  enqueue companies jobs + maybe next page
        job.type == "threats_page" ?
          request("GET", job.url).with({
            "Header": {"Authorization": ["Basic " + (state.token + ":").base64()]}
          }).do_request().as(resp,
            resp.StatusCode == 200 ?
              bytes(resp.Body).decode_json().as(body,
                has(body.results) && size(body.results) > 0 ?
                  // We need to build a new company job for each threat
                  // and add it to the job queue
                  body.results.map(t, {
                    "type": "companies_page",
                    "threat": t,
                    "url": state.url.trim_right("/") + "/ratings/v2/threats/" + t.guid + "/companies?" + {
                      "limit": [string(state.batch_size)]
                    }.format_query()
                  }).as(company_jobs,
                    // We also need to check if there is a next page
                    // and add it as a threats_page job
                    {
                      "events": [{"message": {"event": {"reason": "polling"}}}],
                      "jobs": company_jobs +
                        (has(body.links) && has(body.links.next) && body.links.next != null && body.links.next != "" ?
                          [{"type": "threats_page", "url": body.links.next}] : []) +
                        tail(state.jobs),
                      "want_more": true
                    }
                  )
                :
                  {
                    "events": {
                      "error": {
                        "code": string(resp.StatusCode),
                        "id": string(resp.Status),
                        "message": "GET /threats returned no resulsts: " + (
                          size(resp.Body) != 0 ?
                            string(resp.Body)
                          :
                            string(resp.Status) + " (" + string(resp.StatusCode) + ")"
                        )
                      }
                    },
                    // We need to drop the faulty job and continue with the next one
                    "jobs": tail(state.jobs),
                    "want_more": true
                  }
              )
            :
              {
                "events": {
                  "error": {
                    "code": string(resp.StatusCode),
                    "id": string(resp.Status),
                    "message": "GET /threats: " + (
                      size(resp.Body) != 0 ?
                        string(resp.Body)
                      :
                        string(resp.Status) + " (" + string(resp.StatusCode) + ")"
                    )
                  }
                },
                // We need to drop the faulty job and continue with the next one
                "jobs": tail(state.jobs),
                // Do not continue if we get a 429 or 500 error since this might be a temporary issue
                // and we dont want to spam the API with requests
                // Neither do we want to loose the job queue and overwrite the cursor at the end
                "want_more": !(resp.StatusCode == 429 || resp.StatusCode >= 500)
              }
          )
        :
        // B:  Companies page  →  enqueue evidence jobs + maybe next page
        job.type == "companies_page" ?
          request("GET", job.url).with({
            "Header": {"Authorization": ["Basic " + (state.token + ":").base64()]}
          }).do_request().as(resp,
            resp.StatusCode == 200 ?
              bytes(resp.Body).decode_json().as(body,
                has(body.results) && size(body.results) > 0 ?
                  body.results.map(c, {
                    "type": "evidence_page",
                    "threat": job.threat,
                    "company": c,
                    "url": state.url.trim_right("/") + "/ratings/v2/threats/" + job.threat.guid + "/companies/" + c.company_guid + "/evidence?" + {
                      "limit": [string(state.batch_size)]
                    }.format_query()
                  }).as(ev_jobs,
                    {
                      "events": [{"message": {"event": {"reason": "polling"}}}],
                      "jobs": ev_jobs +
                        (has(body.links) && has(body.links.next) && body.links.next != null && body.links.next != "" ?
                          [{"type": "companies_page", "threat": job.threat, "url": body.links.next}] : []) +
                        tail(state.jobs),
                      "want_more": true
                    }
                  )
                :
                  // There are no companie records for this threat
                  // We simply emit the threat and continue with the next one
                  (
                    {
                      "threat":  job.threat
                    }.as(msg,
                      {
                        "message": msg,
                        ?"event.original": state.?preserve_original_event.orValue(false) ? optional.of(msg.encode_json()) : optional.none()
                      }
                    )
                  ).as(evts,
                    {
                      "events": evts,
                      // No need to enqueue a new job, we just continue with the next one
                      "jobs": tail(state.jobs),
                      // We can still set the last_first_seen_date here
                      "cursor": { "last_first_seen_date":  job.threat.first_seen_date},
                      "want_more": true
                    }
                  )
              )
            :
              {
                "events": {
                  "error": {
                    "code": string(resp.StatusCode),
                    "id": string(resp.Status),
                    "message": "GET companies: " + (
                      size(resp.Body) != 0 ?
                        string(resp.Body)
                      :
                        string(resp.Status) + " (" + string(resp.StatusCode) + ")"
                    )
                  }
                },
                // We need to drop the faulty job and continue with the next one
                "jobs": tail(state.jobs),
                "want_more": !(resp.StatusCode == 429 || resp.StatusCode >= 500)
              }
          )
        :
        // C: Evidence page  →  emit events + maybe next page
        job.type == "evidence_page" ?
          request("GET", job.url).with({
            "Header": {"Authorization": ["Basic " + (state.token + ":").base64()]}
          }).do_request().as(resp,
            resp.StatusCode == 200 ?
              bytes(resp.Body).decode_json().as(body,
                has(body.results) && size(body.results) > 0 ?
                  body.results.map(e,
                    {
                      "threat":  job.threat,
                      "company": job.company,
                      "evidence": e
                    }.as(msg,
                      {
                        "message": msg,
                        ?"event.original": state.?preserve_original_event.orValue(false) ? optional.of(msg.encode_json()) : optional.none()
                      }
                    )
                  ).as(evts,
                    {
                      "events": evts,
                      "jobs":
                        (has(body.links) && has(body.links.next) && body.links.next != null && body.links.next != "" ?
                          [{"type": "evidence_page", "threat": job.threat, "company": job.company, "url": body.links.next}] : []) +
                        tail(state.jobs),
                        // We can just set the last_first_seen_date here
                        // because we sort the jobs by first_seen_date acscending
                        // every further job will always be later than this one and replace it
                      "cursor": { "last_first_seen_date":  job.threat.first_seen_date},
                      "want_more": true
                    }
                  )
                :
                  // There are no evidence records for this company
                  // We simply emit the threat and company and continue with the next one
                  (
                    {
                      "threat":  job.threat,
                      "company": job.company
                    }.as(msg,
                      {
                        "message": msg,
                        ?"event.original": state.?preserve_original_event.orValue(false) ? optional.of(msg.encode_json()) : optional.none()
                      }
                    )
                  ).as(evts,
                    {
                      "events": evts,
                      // No need to enqueue a new job, we just continue with the next one
                      "jobs": tail(state.jobs),
                      // We can still set the last_first_seen_date here
                      "cursor": { "last_first_seen_date":  job.threat.first_seen_date},
                      "want_more": true
                    }
                  )
              )
            :
              {
                "events": {
                  "error": {
                    "code": string(resp.StatusCode),
                    "id": string(resp.Status),
                    "message": "GET evidence: " + (
                      size(resp.Body) != 0 ?
                        string(resp.Body)
                      :
                        string(resp.Status) + " (" + string(resp.StatusCode) + ")"
                    )
                  }
                },
                // We need to drop the faulty job and continue with the next one
                "jobs": tail(state.jobs),
                "want_more": !(resp.StatusCode == 429 || resp.StatusCode >= 500)
              }
          )
        :
          // D:  Unknown job type - should never happen, drop & continue
          {
            "events": {
              "error": {
                "message": "Unknown job type: " + string(job)
              }
            },
            "jobs": tail(state.jobs),
            "want_more": true
          }
        )
      :
        // The job url is null, we need to drop the job and continue with the next one
        {
          "events": {
            "error": {
              "message": "Job url is null: " + string(job)
            }
          },
          "jobs": tail(state.jobs),
          "want_more": true
        }
    )
  ))
  .as(state, state.with(
    //    When the queue is completely empty we finish the cycle
    size(state.jobs) == 0 ?
      {
        "want_more": false
      }
    :
      // We just emit the already created output and dont add anything else
      {}
  ))

tags:
{{#if preserve_original_event}}
  - preserve_original_event
{{/if}}
{{#each tags as |tag|}}
  - {{tag}}
{{/each}}
{{#contains "forwarded" tags}}
publisher_pipeline.disable_host: true
{{/contains}}
{{#if processors}}
processors:
{{processors}}
{{/if}}
```

And the pipeline configuration:

```yaml
---
description: Pipeline for processing Bitsight Vulnerability output
processors:
  - rename:
      field: message
      target_field: bitsight

  - drop:
      if: ctx.bitsight?.event?.reason == 'polling'

  - fingerprint:
      fields:
        - bitsight
      tag: fingerprinting
      target_field: "_id"
      on_failure:
        - append:
            field: error.message
            value: 'Processor {{{_ingest.on_failure_processor_type}}} with tag {{{_ingest.on_failure_processor_tag}}} in pipeline {{{_ingest.on_failure_pipeline}}} failed with message: {{{_ingest.on_failure_message}}}'

  ##################### Scripts for processing input #####################

  - script:
      description: Drops null/empty values recursively.
      lang: painless
      source: |
        boolean dropEmptyFields(Object object) {
          if (object == null || object == "") {
            return true;
          } else if (object instanceof Map) {
            ((Map) object).values().removeIf(value -> dropEmptyFields(value));
            return (((Map) object).size() == 0);
          } else if (object instanceof List) {
            ((List) object).removeIf(value -> dropEmptyFields(value));
            return (((List) object).size() == 0);
          }
          return false;
        }
        dropEmptyFields(ctx);

  - date:
      field: bitsight.threat.last_seen_date
      formats: ["yyyy-MM-dd"]
      target_field: '@timestamp'
      ignore_failure: true

  - set:
      field: vulnerability.id
      copy_from: bitsight.threat.name
      ignore_failure: true

  - set:
      field: vulnerability.scanner.vendor
      value: "Bitsight"
      ignore_failure: true

  # Map Bitsight severity.level → ECS severity
  - script:
      lang: painless
      source: |
        if (ctx.bitsight?.threat?.severity?.level != null) {
          String lvl = ctx.bitsight.threat.severity.level;
          if (lvl.equalsIgnoreCase('minor')) {
            ctx.vulnerability.severity = 'Low';
          } else if (lvl.equalsIgnoreCase('moderate')) {
            ctx.vulnerability.severity = 'Medium';
          } else if (lvl.equalsIgnoreCase('material')) {
            ctx.vulnerability.severity = 'High';
          } else if (lvl.equalsIgnoreCase('severe')) {
            ctx.vulnerability.severity = 'Critical';
          } else {
            ctx.vulnerability.severity = lvl;
          }
        }
      ignore_failure: true

  # Extract score from severity.details field
  - grok:
      field: bitsight.threat.severity.details
      patterns: ["CVSS %{NUMBER:vulnerability.score.base:float}"]
      ignore_failure: true

  # Extract IP from evidence identifier field (e.g., 1.2.3.4:443)
  - remove:
      field: host
      ignore_failure: true
  - grok:
      field: bitsight.evidence.identifier
      patterns: ["%{IP:extracted_ip}:%{NUMBER}"]
      ignore_failure: true
  - append:
      field: host.ip
      value: "{{extracted_ip}}"
      if: ctx?.extracted_ip != null
      ignore_failure: true
      allow_duplicates: false
  - remove:
      field: extracted_ip
      ignore_failure: true

  # Append company name to category
  - append:
      field: vulnerability.category
      value: "{{bitsight.company.company_name}}"
      allow_duplicates: false
      ignore_failure: true

#################### Error Log fields ####################

on_failure:
  - append:
      field: error.message
      value: '{{{_ingest.on_failure_message}}}'

  - set:
      field: event.kind
      value: pipeline_error
```

And the fields:

```yaml
---
- name: bitsight
  type: group
  description: Bitsight data
  fields:
    - name: threat
      type: group
      description: Bitsight threat metadata
      fields:
        - name: guid
          type: keyword
          description: Unique threat GUID
        - name: name
          type: keyword
          description: Threat name (e.g. CVE-ID)
        - name: first_seen_date
          type: date
          description: Date when this threat was first seen
        - name: last_seen_date
          type: date
          description: Date when threat data was last available
        - name: support_started_date
          type: date
          description: Date when this threat was first supported in Bitsight
        - name: exposed_count
          type: integer
          description: Number of companies observed to have evidence of exposure
        - name: mitigated_count
          type: integer
          description: Number of companies with evidence of mitigation
        - name: exposure_trend
          type: integer
          description: Change in exposure count over the last 14 days
        - name: questionnaires_sent
          type: integer
          description: Number of questionnaires sent (when expanded)
        - name: evidence_certainty
          type: keyword
          description: Overall certainty for this threat's evidence
        - name: severity
          type: group
          description: Severity information
          fields:
            - name: level
              type: keyword
              description: Bitsight severity level
            - name: details
              type: keyword
              description: CVSS score details like type and base score (e.g. “CVSS 7.1”)
        - name: category
          type: group
          description: Threat category
          fields:
            - name: name
              type: keyword
              description: Category name
            - name: slug
              type: keyword
              description: Category slug
        - name: epss
          type: group
          description: Exploit Prediction Scoring System data
          fields:
            - name: score
              type: float
              description: EPSS score
            - name: percentile
              type: float
              description: EPSS percentile
        - name: dve
          type: group
          description: Dynamic Vulnerability Exploit data
          fields:
            - name: score
              type: float
              description: DVE score
            - name: highest_score
              type: float
              description: Highest recorded DVE score
            - name: highest_score_date
              type: date
              description: Date of highest DVE score
            - name: cti_attributes
              type: group
              description: CTI attributes
              fields:
                - name: name
                  type: keyword
                  description: CTI attribute name
                - name: slug
                  type: keyword
                  description: CTI attribute slug

    - name: company
      type: group
      description: Bitsight company exposure data
      fields:
        - name: company_name
          type: keyword
          description: Company name
        - name: company_guid
          type: keyword
          description: Company GUID
        - name: first_seen_date
          type: date
          description: Date when this threat first affected the company
        - name: last_seen_date
          type: date
          description: Date when this threat was last seen for the company
        - name: evidence_certainty
          type: keyword
          description: Certainty level of the company's evidence
        - name: exposure_detection
          type: keyword
          description: Company's exposure detection status
        - name: tier
          type: keyword
          description: Tier the company belongs to (Identifier)
        - name: tier_name
          type: keyword
          description: Tier name (Human readable)
        - name: logo
          type: keyword
          description: URL of the company logo
        - name: detection_types
          type: keyword
          description: How the data was collected
        - name: evidence_tags
          type: group
          description: Evidence tags for the company
          fields:
            - name: name
              type: keyword
              description: Evidence tag name
            - name: slug
              type: keyword
              description: Evidence tag slug

    - name: evidence
      type: group
      description: Bitsight evidence record details
      fields:
        - name: identifier
          type: keyword
          description: Asset identifier (e.g. “IP:port”)
        - name: detection_type
          type: keyword
          description: How the evidence was collected
        - name: certainty
          type: keyword
          description: Certainty level of this evidence
        - name: exposure_detection
          type: keyword
          description: Exposure detection status for this evidence
        - name: first_seen_date
          type: date
          description: Date when this evidence was first seen
        - name: last_seen_date
          type: date
          description: Date when this evidence was last seen
        - name: evidence_tag
          type: group
          description: Evidence tag details
          fields:
            - name: name
              type: keyword
              description: Evidence tag name
            - name: slug
              type: keyword
              description: Evidence tag slug
```