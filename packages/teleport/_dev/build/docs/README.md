# Teleport Audit Events Integration


## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

For step-by-step instructions on how to set up an integration,
see the {{ url "getting-started-observability" "Getting started" }} guide.

## Data streams

The Teleport Audit data stream `audit` provides events from Teleport audit logs.
Event fields are grouped into logical categories.

{ { event "audit"}}

{{fields "audit"}}

## Contributing

### Sources

- [Teleport icon](https://goteleport.com/static/favicon.svg)
- Teleport source:
  - [Events message structure](https://github.com/gravitational/teleport/blob/master/api/proto/teleport/legacy/types/events/events.proto)
  - [Description of event types](https://github.com/gravitational/teleport/blob/master/web/packages/teleport/src/services/audit/makeEvent.ts)
  - [List of example events](https://github.com/gravitational/teleport/blob/master/web/packages/teleport/src/Audit/fixtures/index.ts)

IP replacement:

```shell
sed -e "s/1\.1.1./67.43.156.1/g;s/2\.2.2./67.43.156./g;s/198.51.100./175.16.199./g;s/172.10.1./67.43.156./g;s/100.104.52.89/81.2.69.192/g;s/190.58.129.4/89.160.20.112/g;s/192.000.0.000/89.160.20.128/g;s/50.34.48.113/81.2.69.193/g;s/54-162-177-255/175-16-199-255/g;s/\[::1\]/2a02:cf40::/g;s/198.51.100./1.128.0./g" -i bak data_stream/audit/_dev/test/pipeline/test-teleport-all-events.log
```

### How the ingest pipeline was generated

With OpenAI and the generated text list of events, we
[generated a pipeline to assign each event to a category](../data_stream/audit/elasticsearch/ingest_pipeline/event-categories.yml).

With Integration Assistant and the Go source of event message structure, we
[generated field list and a pipeline to assign each field](../data_stream/audit/elasticsearch/ingest_pipeline/event-groups.yml).


### How the text list of events was built

```just
#!/usr/bin/env just --justfile

# Run the whole conversion pipeline.
convert: download
    cat makeEvent.ts | rg "type:" -A1 | sed "s/--//g" | sed s/\',//g | sed "s/    ....: '//g" | sed 's/"//g' | just convert-script | sort > events.txt

# Script to convert a list of pairs of strings into a an 'A:B' format.
convert-script:
    #!/usr/bin/env python3
    import fileinput

    key = value = None

    for line in fileinput.input():
        line = line.strip()
        if not line:
            assert not key and not value
        elif key:
            value = line
            print(f"{key}: {value}")
            key = value = None
        else:
            key = line

# Download the original file.
download:
    curl -o makeEvent.ts https://raw.githubusercontent.com/gravitational/teleport/0aa5285477d422e98bb72ccf42a4381e6fdce527/web/packages/teleport/src/services/audit/makeEvent.ts
```
