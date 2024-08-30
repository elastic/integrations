ARG IMAGE=${IMAGE:-tomcat:10.1.5-jre17}
FROM ${IMAGE}

ARG user=tests
ARG group=tests
ARG uid=1000
ARG gid=1000


RUN groupadd -g ${gid} ${group} \
    && useradd -d "${CATALINA_HOME}" -u ${uid} -g ${gid} -s /bin/bash ${user}

USER ${user}

