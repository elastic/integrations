# ForgeRock Identity Platform

ForgeRock is a modern identity platform which helps organizations radically simplify identity and access management (IAM) and identity governance and administration (IGA). The ForgeRock integration collects audit logs from the [API](https://backstage.forgerock.com/knowledge/kb/article/a37739488).

### Configuration

Authorization parameters for the ForgeRock Identity Cloud API (`API Key ID`, and `API Key Secret`) can be created [in the Identity Cloud admin UI](https://backstage.forgerock.com/docs/idcloud/latest/developer-docs/authenticate-to-rest-api-with-api-key-and-secret.html#get_an_api_key_and_secret). 

### Example event

An example event for ForgeRock looks as following:

```json
{
	"tags": [
		"forwarded",
		"forgerock-audit",
		"forgerock-am-access"
	],
	"input": {
		"type": "httpjson"
	},
	"observer": {
		"vendor": "ForgeRock Identity Platform"
	},
	"@timestamp": "2022-12-13T21:21:44.228Z",
	"ecs": {
		"version": "8.5.2"
	},
	"data_stream": {
		"namespace": "default",
		"type": "logs",
		"dataset": "forgerock.am_access"
	},
	"service": {
		"name": "OAuth"
	},
	"forgerock": {
		"level": "INFO",
		"response": {
			"elapsedTimeUnits": "MILLISECONDS",
			"detail": {
				"scope": "fr:idm:*",
				"active": true,
				"token_type": "Bearer",
				"client_id": "autoid-resource-server",
				"username": "autoid-resource-server"
			},
			"elapsedTime": 17,
			"status": "SUCCESSFUL"
		},
		"eventName": "AM-ACCESS-OUTCOME",
		"http": {
			"request": {
				"headers": {
					"host": [
						"am.fr-platform"
					],
					"content-type": [
						"application/x-www-form-urlencoded"
					],
					"accept": [
						"application/json"
					],
					"user-agent": [
						"Apache-HttpAsyncClient/4.1.4 (Java/11.0.17)"
					]
				},
				"secure": true
			}
		},
		"topic": "access",
		"realm": "/",
		"source": "audit",
		"trackingIds": [
			"acdb66cd-d964-4c92-ade5-8c1a9bfc4f8c-394538"
		]
	},
	"client": {
		"port": 43048,
		"ip": "10.68.11.13"
	},
	"http": {
		"request": {
			"Path": "https://am.fr-platform/am/oauth2/introspect",
			"method": "POST"
		},
		"response": {
			"status_code": 200
		}
	},
	"event": {
		"duration": 17000000,
		"agent_id_status": "verified",
		"ingested": "2022-12-13T21:37:06Z",
		"created": "2022-12-13T21:37:05.672Z",
		"action": "AM-ACCESS-OUTCOME",
		"id": "acdb66cd-d964-4c92-ade5-8c1a9bfc4f8c-394544",
		"type": "access",
		"dataset": "forgerock.am_access",
		"outcome": "success"
	},
	"user": {
		"id": "id=openidm-resource-server,ou=agent,ou=am-config"
	},
	"transaction": {
		"id": "1670966504205-c228c1d5b34eae0061b9-38630/0/0/0"
	}
}
```

**Exported fields**

{{fields "audit"}}