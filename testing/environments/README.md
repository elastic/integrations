Firstly, refresh docker images:

```bash
$ docker-compose -f snapshot.yml pull
```

Run docker containers (Elasticsearch, Kibana, Package Registry):

```bash
$ docker-compose -f snapshot.yml -f local.yml up --force-recreate
```

... or with Elastic Agent:

```bash
$ docker-compose -f snapshot.yml -f local.yml -f agent.yml up --force-recreate
```

Use this command to spawn more agents:

```bash
$ docker-compose -f snapshot.yml -f local.yml -f agent.yml up --scale elastic-agent=10 --no-recreate -d
```