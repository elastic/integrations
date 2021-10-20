# Development process for Fleet UI

## Development workflow

See the Kibana docs for [how to set up your dev environment](https://github.com/elastic/kibana/blob/master/CONTRIBUTING.md#setting-up-your-development-environment), [run Elasticsearch](https://github.com/elastic/kibana/blob/master/CONTRIBUTING.md#running-elasticsearch), and [start Kibana](https://github.com/elastic/kibana/blob/master/CONTRIBUTING.md#running-kibana)

One common development workflow is:

- Clone Kibana repo
  ```
  git clone https://github.com/[YOUR_USERNAME]/kibana.git kibana
  cd kibana
  ```
- Install Dependencies
  ```
  nvm use
  npm install -g yarn
  ```

- Bootstrap Kibana
  ```
  yarn kbn bootstrap
  ```
- Start Elasticsearch in one shell
  ```
  yarn es snapshot -E xpack.security.authc.api_key.enabled=true
  ```
- Start Kibana in another shell
  ```
  yarn start --xpack.fleet.enabled=true --no-base-path
  ```
- Download fleet-server package from https://www.elastic.co/downloads/past-releases/#elastic-agent
- Untar fleet server tarball and `cd` to the directory
- Install fleet-server (See also the alternative solution)
  ```
  sudo ./elastic-agent install  -f \
  --fleet-server-es=http://elastic:changeme@localhost:9200 \
  --fleet-server-policy=<default policy id>
  ```
    The `default policy id` can be retrieved by fleet ui instructions in Kibana before any fleet server is installed.
    Fleet Server will start in `https://users_machine_ip:8220`
- Update Fleet settings on the top right corner of Fleet UI to set the correct Fleet Server hosts (ip from previous step).
- After that user can enrol as many agents as they want
- Any code update in Kibana fleet plugin should be picked up automatically and either cause the server to restart, or be served to the browser on the next page refresh.

### Alternative solution for fleet server
Instead of download fleet server package and running it as a local process you can run Fleet Server Locally in a Container.

It can be useful to run Fleet Server in a container on your local machine in order to free up your actual "bare metal" machine to run Elastic Agent for testing purposes. Otherwise, you'll only be able to a single instance of Elastic Agent dedicated to Fleet Server on your local machine, and this can make testing integrations and policies difficult.

_The following is adapted from the Fleet Server [README](https://github.com/elastic/fleet-server#running-elastic-agent-with-fleet-server-in-container)_

1. Add the following configuration to your `config/kibana.yml`

```yml
server.host: 0.0.0.0
```

2. Append the following option to the command you use to start Elasticsearch

```
-E http.host=0.0.0.0
```

This command should look something like this:

```
yarn es snapshot --license trial -E xpack.security.authc.api_key.enabled=true -E path.data=/tmp/es-data -E http.host=0.0.0.0
```

3. Run the Fleet Server Docker container. Make sure you include a `BASE-PATH` value if your local Kibana instance is using one. `YOUR-IP` should correspond to the IP address used by your Docker network to represent the host. For Windows and Mac machines, this should be `192.168.65.2`. If you're not sure what this IP should be, run the following to look it up:

```
docker run -it --rm alpine nslookup host.docker.internal
```

To run the Fleet Server Docker container:

```
docker run -e KIBANA_HOST=http://{YOUR-IP}:5601/{BASE-PATH} -e KIBANA_USERNAME=elastic -e KIBANA_PASSWORD=changeme -e ELASTICSEARCH_HOST=http://{YOUR-IP}:9200 -e ELASTICSEARCH_USERNAME=elastic -e ELASTICSEARCH_PASSWORD=changeme -e KIBANA_FLEET_SETUP=1 -e FLEET_SERVER_ENABLE=1 -e FLEET_SERVER_INSECURE_HTTP=1 -p 8220:8220 docker.elastic.co/beats/elastic-agent:{VERSION}
```

Ensure you provide the `-p 8220:8220` port mapping to map the Fleet Server container's port `8220` to your local machine's port `8220` in order for Fleet to communicate with Fleet Server.

For the latest version, use `8.0.0-SNAPSHOT`. Otherwise, you can explore the available versions at https://www.docker.elastic.co/r/beats/elastic-agent.

Once the Fleet Server container is running, you should be able to treat it as if it were a local process running on `http://localhost:8220` when configuring Fleet via the UI. You can then run `elastic-agent` on your local machine directly for testing purposes.