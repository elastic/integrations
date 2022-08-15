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
## Logs

### log

{{fields "log"}}

{{event "log"}}