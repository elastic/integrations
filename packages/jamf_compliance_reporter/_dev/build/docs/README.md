# JAMF Compliance Reporter

The [JAMF Compliance Reporter](https://docs.jamf.com/compliance-reporter/documentation/Compliance_Reporter_Overview.html) Integration collects and parses data received from JAMF Compliance Reporter using TLS or HTTP Endpoint.  
Reference link for setting up JAMF Compliance Reporter: [Here](https://docs.jamf.com/compliance-reporter/documentation/Setting_Up_Compliance_Reporter.html)
## Requirements
- Enable the Integration with the TLS or HTTP Endpoint input.
- Configure JAMF Compliance Reporter to send logs to the Elastic Agent.

## Steps for generating remote endpoint logging certificates for Compliance Reporter
##### This process is only for initial configuration. After validating settings, you can use a configuration profile in Jamf Pro to deploy certificates to endpoints in production.
1. In Terminal, execute the following to get the full output to the certificate file.

   ```
   echo -n | openssl s_client -showcerts -connect HOSTNAME:PORT
   ```

2. Copy the certificate text, including the BEGIN CERTIFICATE and END CERTIFICATE lines to separate .txt files.

3. Rename the .txt file to a .pem file and double-click to import the file into the system keychain.
The output should be similar to the following.
   ```
   $ ls -la certs.d
   server-leaf-cert.pem
   intermediate-ca.pem
   root-ca.pem
   $ cat server-leaf-cert.pem
   -----BEGIN CERTIFICATE-----
   MIIFazCCBFOgAwIBAgISBIuX8OD2k1mBKORs6oCdBeaFMA0GCSqGSIb3DQEBCwUA
   MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
   ... (truncated for readability)
   -----END CERTIFICATE-----
   ```

## Steps for setting up Compliance Reporter
1. In Jamf Pro, click **Computers** at the top of the sidebar.

2. Click **Configuration Profiles** in the sidebar.

3. Click **New**.

4. Use the General payload to configure basic settings, including the level at which to apply the profile and the distribution method.

5. Use the Application & Custom Settings payload to configure Jamf Applications.

6. Click **Add**.

7. Select **com.jamf.compliancereporter** from the **Jamf Application Domain** pop-up menu.

8. Select a version of the preference domain you want to configure.

9. Select **ComplianceReporter.json** from the **Variant** pop-up menu.

10. Configure the **Compliance Reporter** settings.
    - To enable remote logging, you must configure the following general preference keys.
    
      ```
      <key>LogRemoteEndpointEnabled</key>
      <true/>
      ```

      ```
      <key>LogRemoteEndpointURL</key>
      <string>https://server.address.com:9093</string>
      ```

      ```
      <key>LogRemoteEndpointType</key>
      <string>Server Name</string>
      ```

      Use one of the following based on the aggregation server you are using.
        - TLS: "TLS"
        - REST Endpoint: "REST"

    - Configure the following preference keys for REST endpoint remote logging in Compliance Reporter.
      ```
      <key>LogRemoteEndpointREST</key>
      <dict></dict>
      ```

      ```
      <key>PublicKeyHash</key>
      <string>e838SOLK9Yu+brDTxM4s0HatE2UdoSBtNDU=</string>
      ```

    - Configure the following preference keys for TLS remote logging in Compliance Reporter.
      ```
      <key>LogRemoteEndpointTLS</key>
      <dict></dict>
      ```

      ```
      <key>TLSServerCertificate</key>
      <array>
         <string>server_name.company.com</string>
         <string>Let's Encrypt Authority X3</string>
         <string>DST Root CA X3</string>
      </array>
      ```

11. Click the **Scope tab** and configure the scope of the profile.
12. Click **Save**.

## Compatibility
This package has been tested for Compliance Reporter against JAMF pro version 10.18.0

## Logs

### App Metrics Logs

- Default port for HTTP Endpoint: _9550_  
- Default port for TLS: _9553_

### Audit Logs

- Default port for HTTP Endpoint: _9551_  
- Default port for TLS: _9554_

### Event Logs

- Default port for HTTP Endpoint: _9552_  
- Default port for TLS: _9555_

## Fields and Sample Event

### App Metrics Logs

This is the `app_metrics` dataset.

{{event "app_metrics"}}

{{fields "app_metrics"}}

### Audit Logs

This is the `audit` dataset.

{{event "audit"}}

{{fields "audit"}}

### Event Logs

This is the `event` dataset.

{{event "event"}}

{{fields "event"}}
