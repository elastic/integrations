# Custom Filestream Log integration

The `filestream` custom input is used to read lines from active log files. It is the
new, improved alternative to the `log` input. It comes with various improvements
to the existing input:

1. Checking of `close_*` options happens out of band. Thus, if an output is blocked,
Elastic Agent can close the reader and avoid keeping too many files open.

2. The order of `parsers` is configurable. So it is possible to parse JSON lines and then
aggregate the contents into a multiline event.

3. Some position updates and metadata changes no longer depend on the publishing pipeline.
If the pipeline is blocked some changes are still applied to the registry.

4. Only the most recent updates are serialized to the registry. In contrast, the `log` input
has to serialize the complete registry on each ACK from the outputs. This makes the registry updates
much quicker with this input.

5. The input ensures that only offsets updates are written to the registry append only log.
The `log` writes the complete file state.

6. Stale entries can be removed from the registry, even if there is no active input.

7. The fingerprint file identity is used by default.

More information can be found on the {{ url "filebeat-input-filestream" "Filestream documentation page" }}

As Filestream configures a new input, configuring it to collect data
from a file that was previously collected by Custom Logs integration
will result in duplicate data. You may wish to configure
`ignore_older` or temporarily set `ignore_inactive: since_first_start`
to limit the amount of duplicate data collected.

If the Custom Logs integration is removed and the Custom Filestream
Logs is added in the same policy change, there risk of data being
missed between the last entry ingested by the Custom Logs and the
first one ingested by the Custom Filestream Logs.
