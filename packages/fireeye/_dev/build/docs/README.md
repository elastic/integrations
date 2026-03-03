# FireEye Integration

This integration periodically fetches logs from [FireEye Network Security](https://www.fireeye.com/products/network-security.html) devices. 

## Compatibility

The FireEye `nx` integration has been developed against FireEye Network Security 9.0.0.916432 but is expected to work with other versions.

## Logs

### NX

The `nx` integration ingests network security logs from FireEye NX through TCP/UDP and file.

{{fields "nx"}}

{{event "nx"}}