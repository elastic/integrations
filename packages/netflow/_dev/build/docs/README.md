# Netflow Integration

This integration is for receiving NetFlow and IPFIX flow records over UDP. 
It supports NetFlow versions 1, 5, 6, 7, 8 and 9, as well as IPFIX. For NetFlow versions older than 9, fields are mapped automatically to NetFlow v9.

For more information on Netflow and IPFIX, see:

- [Cisco Systems NetFlow Services Export Version 9](https://www.ietf.org/rfc/rfc3954.txt)
- [Specification of the IP Flow Information Export (IPFIX) Protocol for the Exchange of Flow Information](https://www.ietf.org/rfc/rfc7011.txt)

It includes the following dataset:

- `log` dataset

## Compatibility

## Logs

### log

The `log` dataset collects netflow logs.

{{fields "log"}}
