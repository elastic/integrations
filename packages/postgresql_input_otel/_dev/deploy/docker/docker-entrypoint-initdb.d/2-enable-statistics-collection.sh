#!/usr/bin/env bash
cat <<-EOF >> $PGDATA/postgresql.conf
track_activities = on
track_cost_delay_timing = on
track_counts = on
track_functions = all
track_io_timing = on
track_wal_io_timing = on
EOF
