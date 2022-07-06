ARG RABBITMQ_VERSION=${RABBITMQ_VERSION:-3}
FROM rabbitmq:${RABBITMQ_VERSION}-management

USER root
RUN apt-get update && apt-get install -y netcat && apt-get install -y curl && apt-get install -y rabbitmq-server && apt-get clean
ENV RABBITMQ_DEFAULT_USER guest
ENV RABBITMQ_DEFAULT_PASS guest
ENV RABBITMQ_PID_FILE /var/lib/rabbitmq/mnesia/rabbitmq
RUN rabbitmq-plugins enable --offline rabbitmq_shovel && rabbitmq-plugins enable --offline rabbitmq_shovel_management

ADD init.sh /init.sh
RUN ["chmod", "+x", "/init.sh"]

EXPOSE 5672 15672 

HEALTHCHECK --interval=1s --retries=90 CMD nc -w 1 -v 127.0.0.1 15672 </dev/null

CMD ["/init.sh"]


