FROM maven:3.8.4-openjdk-8
RUN mkdir -p /build && chmod -R 777 /build
WORKDIR /build
COPY ./spring_boot/ /build/spring_boot/
WORKDIR /build/spring_boot
RUN mvn package -q -DskipTests
HEALTHCHECK --interval=5s --retries=5 CMD curl -f http://springboot:8090/actuator/health || exit 1
ENTRYPOINT ["java","-jar","/build/spring_boot/target/actuator-0.0.1-Release.jar"]
