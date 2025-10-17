FROM apache/kafka:4.0.0

USER root

# Copy jolokia agent jar from host into container
COPY jolokia/jolokia-jvm-agent.jar /opt/jolokia/jolokia-jvm.jar

# Copy startup script
COPY startup.sh /opt/startup.sh
COPY healthcheck.sh /opt/healthcheck.sh
RUN chmod +x /opt/startup.sh /opt/healthcheck.sh && chown -R 1001:0 /opt

USER 1001

ENTRYPOINT ["/opt/startup.sh"]