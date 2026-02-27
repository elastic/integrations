FROM confluentinc/cp-kafka-connect:7.5.0

USER root

# Copy jolokia agent jar from host into container
RUN mkdir -p /opt/jolokia
ADD jolokia/jolokia-jvm-2.3.0.jar /opt/jolokia/jolokia-jvm.jar

# Fix permissions
RUN chown -R appuser:appuser /opt/jolokia

USER appuser

# Default command
CMD ["/etc/confluent/docker/run"]
