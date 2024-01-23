# Keycloak Integration

The Keycloak integration collects events from the [Keycloak](https://www.keycloak.org/server/logging) log files.

To enable logging of all Keycloak events like logins, user creation/updates/deletions.... add the below 
```
    <logger category="org.keycloak.events">
        <level name="DEBUG"/>
    </logger>
```
to your configuration XML file (ie standalone.xml) under the path below
```
<server>
    <profile>
        <subsystem xmlns="urn:jboss:domain:logging:8.0">
            ....
        </subsystem>
    </profile>
</server>
```

Note:
- Keycloak log files could contain multiline logs. In order to process them, the [multiline configuration](https://www.elastic.co/guide/en/beats/filebeat/current/multiline-examples.html) should be added to the parsers section when deploying the integration.

## Logs

### log

{{fields "log"}}

{{event "log"}}
