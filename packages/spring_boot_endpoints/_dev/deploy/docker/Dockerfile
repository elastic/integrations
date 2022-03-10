FROM openjdk:8-jdk-alpine
RUN addgroup -S spring && adduser -S spring -G spring
RUN apk add curl
USER spring:spring
COPY actuator-demo-0.0.1-Release.jar app.jar
HEALTHCHECK --interval=1s --retries=90 CMD curl -f http://actuator:actuator@springbootendpoints:8090/actuator/info
ENTRYPOINT ["java","-jar","/app.jar"]
