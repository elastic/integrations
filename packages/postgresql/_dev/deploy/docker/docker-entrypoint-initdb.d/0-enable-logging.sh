#!/usr/bin/env bash
chmod a+wx /var/log/postgresql

cat <<-EOF >> $PGDATA/postgresql.conf
# Enable some log facilities.
log_duration = 'on'
log_connections = 'on'
log_disconnections = 'on'

# Ensure that statements are logged, with their durations.
log_statement = 'none'
log_min_duration_statement = 0

# Give agent read permissions. In NO case for production usage.
log_file_mode = '0666'

# Try to imitate logging behaviour in Debian/Ubuntu, but there the logging collector
# is not used.
logging_collector = 'on'
log_directory = '/var/log/postgresql'
log_line_prefix = '%m [%p] %q%u@%d '
EOF
