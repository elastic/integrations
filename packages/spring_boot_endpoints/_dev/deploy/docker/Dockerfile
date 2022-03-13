FROM maven:3.8.4-eclipse-temurin-11-alpine
RUN apk add curl
RUN mkdir -p /build
WORKDIR /build
COPY ./spring_boot/ /build/spring_boot/
WORKDIR /build/spring_boot
RUN mvn -B dependency:resolve dependency:resolve-plugins \
    && mvn package
HEALTHCHECK --interval=1s --retries=90 CMD curl -f http://actuator:actuator@springbootendpoints:8090/actuator/info
ENTRYPOINT ["java","-jar","/build/spring_boot/target/actuator-0.0.1-Release.jar"]
