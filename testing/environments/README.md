Firstly, refresh docker images:

```bash
$ docker-compose -f snapshot.yml pull
```

Run docker containers:

```bash
$ docker-compose -f snapshot.yml -f local.yml up --force-recreate
```
