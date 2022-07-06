#!/bin/sh

# Create Rabbitmq user
( rabbitmqctl wait --timeout 60 $RABBITMQ_PID_FILE ; \
# rabbitmqctl add_user guest guest ; \
# rabbitmqctl set_user_tags guest administrator ; \
# rabbitmqctl set_permissions -p / guest  ".*" ".*" ".*" ; \
rabbitmqadmin declare queue name=my-queue
rabbitmqadmin declare queue name=target-queue
rabbitmqctl set_parameter shovel my-shovel \
'{"src-protocol": "amqp091", "src-uri": "amqp://", "src-queue": "my-queue", "dest-protocol": "amqp091", "dest-uri": "amqp://localhost", "dest-queue": "target-queue"}'
echo "*** Log in the WebUI at port 15672 (example: http:/localhost:15672) ***") &

# $@ is used to pass arguments to the rabbitmq-server command.
# For example if you use it like this: docker run -d rabbitmq arg1 arg2,
# it will be as you run in the container rabbitmq-server arg1 arg2
rabbitmq-server $@
