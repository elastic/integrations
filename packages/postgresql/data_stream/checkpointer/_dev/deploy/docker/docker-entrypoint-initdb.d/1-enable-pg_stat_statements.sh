#!/usr/bin/env bash
cat <<-EOF >> $PGDATA/postgresql.conf
shared_preload_libraries = 'pg_stat_statements'
pg_stat_statements.max = 10000
pg_stat_statements.track = all
EOF
