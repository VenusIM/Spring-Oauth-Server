FROM openjdk:17.0.1-jdk-slim AS builder

COPY . /tmp
WORKDIR /tmp

RUN sed -i 's/\r$//' ./gradlew

RUN chmod +x ./gradlew
RUN ./gradlew --no-daemon --refresh-dependencies clean bootjar

FROM openjdk:17.0.1-jdk-slim
COPY --from=builder /tmp/build/libs/auth-1.0.0.jar ./

CMD ["java", "-jar", "auth-1.0.0.jar"]