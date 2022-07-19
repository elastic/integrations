FROM maven:3.8.4-openjdk-8
RUN mkdir -p /build
RUN chmod -R 777 /build
WORKDIR /build
COPY ./spring_boot/ /build/spring_boot/
WORKDIR /build/spring_boot
RUN mvn package -q
HEALTHCHECK --interval=1s --retries=90 CMD curl -f http://actuator:actuator@springboot:8090/actuator/info
ENTRYPOINT ["java","-jar","/build/spring_boot/target/actuator-0.0.1-Release.jar"]
