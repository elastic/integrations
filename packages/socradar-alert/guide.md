# Elastic Alerting — SOCRadar Status Sync (Optional)

> **This step is optional.** Follow this guide if you want status changes made on the **Security → Alerts** table to be reflected back in SOCRadar automatically.

---

## How It Works

1. The integration ships a **Detection Rule** (`SOCRadar - Alarm Detection`) that creates a Security Alert for every incoming alarm. Once installed and enabled, it scans all alarms already in your index — including historical data up to 90 days back.
2. An Elasticsearch **Watcher** (installed in Step 2 below) runs every minute. When it detects a status change on any SOCRadar alert within the last 2 minutes, it calls the SOCRadar API to sync the new status.

---

## Prerequisites

- Elasticsearch **Watcher** must be enabled on your cluster
  - Included in **Basic license and above** on self-hosted deployments
  - Included in all **Elastic Cloud** tiers
- You need your **SOCRadar API Key**

To confirm Watcher is available, run this in **Kibana → Dev Tools**:

```json
GET _watcher/stats
```

If you get a response with `"watcher_state"`, you're good to go.

---

## Step 1 — Enable the Detection Rule

1. Go to **Kibana → Security → Rules → Detection rules (SIEM)**
2. Search for `SOCRadar - Alarm Detection`
3. If the rule appears but is disabled, click the toggle to **Enable** it
4. If the rule does not appear, click **Add Elastic rules**, search for `SOCRadar - Alarm Detection`, click **Install rule**, then enable it

> Once enabled, the rule scans your entire alarm history (up to 90 days) and creates Security Alerts for all existing alarms. New alarms are detected every 5 minutes going forward.

---

## Step 2 — Install the Watcher

Open **Kibana → Dev Tools** and run the following, replacing `<your-api-key>` with your SOCRadar API key:

```json
PUT _watcher/watch/socradar_alarm_status_sync
{
  "trigger": { "schedule": { "interval": "1m" } },
  "input": {
    "search": {
      "request": {
        "indices": [".alerts-security.alerts-*"],
        "body": {
          "size": 1,
          "_source": ["kibana.alert.workflow_status", "alarm.alarm_id", "alarm.company_id"],
          "query": {
            "bool": {
              "must": [{ "term": { "kibana.alert.rule.rule_id": "socradar-alarm-detection-rule" } }],
              "filter": [{ "range": { "kibana.alert.workflow_status_updated_at": { "gte": "now-2m" } } }]
            }
          },
          "sort": [{ "kibana.alert.workflow_status_updated_at": { "order": "desc" } }]
        }
      }
    }
  },
  "condition": {
    "script": {
      "lang": "painless",
      "source": "return ctx.payload.hits.total > 0;"
    }
  },
  "transform": {
    "script": {
      "lang": "painless",
      "source": "Map statusMap = new HashMap(); statusMap.put('acknowledged', 'INVESTIGATING'); statusMap.put('in-progress', 'INVESTIGATING'); statusMap.put('investigating', 'INVESTIGATING'); statusMap.put('pending_info', 'PENDING_INFO'); statusMap.put('legal_review', 'LEGAL_REVIEW'); statusMap.put('vendor_assessment', 'VENDOR_ASSESSMENT'); statusMap.put('closed', 'RESOLVED'); statusMap.put('resolved', 'RESOLVED'); statusMap.put('false-positive', 'FALSE_POSITIVE'); statusMap.put('duplicate', 'DUPLICATE'); statusMap.put('processed_internally', 'PROCESSED_INTERNALLY'); statusMap.put('mitigated', 'MITIGATED'); statusMap.put('not_applicable', 'NOT_APPLICABLE'); def hit = ctx.payload.hits.hits[0]; def src = hit._source; def elasticStatus = src.get('kibana.alert.workflow_status'); def alarmObj = src.get('alarm'); def alarmId = alarmObj.get('alarm_id').toString(); def companyId = alarmObj.get('company_id').toString(); def mappedStatus = statusMap.containsKey(elasticStatus) ? statusMap.get(elasticStatus) : 'OPEN'; return ['alarm_id': alarmId, 'company_id': companyId, 'status': mappedStatus];"
    }
  },
  "actions": {
    "notify_socradar": {
      "webhook": {
        "method": "POST",
        "url": "https://platform.socradar.com/api/company/alarms/status/change",
        "headers": {
          "Content-Type": "application/json",
          "Api-Key": "<your-api-key>"
        },
        "body": "{\"alarm_ids\": [\"{{ctx.payload.alarm_id}}\"], \"company_id\": {{ctx.payload.company_id}}, \"status\": \"{{ctx.payload.status}}\"}"
      }
    }
  }
}
```

---

## Step 3 — Verify the Watcher is Active

```json
GET _watcher/watch/socradar_alarm_status_sync
```

Confirm `"state": "active"` appears under `"watch_status"`.

To manually trigger a test run:

```json
POST _watcher/watch/socradar_alarm_status_sync/_execute
{ "record_execution": true }
```

---

## Changing Alert Status

1. Go to **Kibana → Security → Alerts**
2. Select one or more alerts using the checkbox on the left
3. Click **Change status** in the toolbar that appears and select the new status
4. SOCRadar will be notified within 1 minute

---

## Supported Status Mappings

| Elastic status | SOCRadar status |
|----------------|-----------------|
| `acknowledged` / `investigating` | `INVESTIGATING` |
| `closed` / `resolved` | `RESOLVED` |
| `false-positive` | `FALSE_POSITIVE` |
| `duplicate` | `DUPLICATE` |
| `processed_internally` | `PROCESSED_INTERNALLY` |
| `mitigated` | `MITIGATED` |
| `not_applicable` | `NOT_APPLICABLE` |
| `pending_info` | `PENDING_INFO` |
| `legal_review` | `LEGAL_REVIEW` |
| `vendor_assessment` | `VENDOR_ASSESSMENT` |

---

## Removing the Watcher

```json
DELETE _watcher/watch/socradar_alarm_status_sync
```

---

## Troubleshooting

**No alerts in Security → Alerts after enabling the rule**
- Check rule execution logs under **Security → Rules → SOCRadar - Alarm Detection → Execution results**
- Confirm data exists: open **Discover** and filter by `logs-socradar.incidents-*`
- The rule runs every 5 minutes — wait at least one full cycle after enabling

**`_watcher/stats` returns an error**
- Watcher is not available on your license. Contact your Elastic administrator.

**Watcher is active but SOCRadar is not updating**
- Change an alert status in **Security → Alerts**, wait 1 minute, then check:
  ```json
  GET .watcher-history-*/_search
  {
    "sort": [{ "result.execution_time": { "order": "desc" } }],
    "size": 1
  }
  ```
- Confirm your API key is correct — re-run the `PUT _watcher/watch/...` command with the correct key if needed

