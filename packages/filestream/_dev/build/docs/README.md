# Custom Filestream Log integration

The `filestream` custom input is used to read lines from active log files. It is the
new, improved alternative to the `log` input. It comes with various improvements
to the existing input:

1. Checking of `close_*` options happens out of band. Thus, if an output is blocked,
Elastic Agent can close the reader and avoid keeping too many files open.

2. Detailed metrics are available for all files that match the `paths` configuration
regardless of the `harvester_limit`. This way, you can keep track of all files,
even ones that are not actively read.

3. The order of `parsers` is configurable. So it is possible to parse JSON lines and then
aggregate the contents into a multiline event.

4. Some position updates and metadata changes no longer depend on the publishing pipeline.
If the pipeline is blocked some changes are still applied to the registry.

5. Only the most recent updates are serialized to the registry. In contrast, the `log` input
has to serialize the complete registry on each ACK from the outputs. This makes the registry updates
much quicker with this input.

6. The input ensures that only offsets updates are written to the registry append only log.
The `log` writes the complete file state.

7. Stale entries can be removed from the registry, even if there is no active input.

More information can be found on the [Filestream documentation page](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-filestream.html)