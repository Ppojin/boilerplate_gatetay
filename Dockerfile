### BUILD
FROM gradle:8.2-jdk17 as builder
WORKDIR /build

# 그래들 파일이 변경되었을 때만 새롭게 의존패키지 다운로드 받게함.
COPY build.gradle.kts settings.gradle.kts /build/
RUN gradle build -x test

COPY . /build/
RUN gradle build -x test

### APP
FROM openjdk:17-ea-slim
WORKDIR /app

# 빌더 이미지에서 jar 파일만 복사
COPY --from=builder /build/build/libs/gateway-0.0.1-SNAPSHOT.jar .

ENV SERVER_PORT=8080
ENV HOSTNAME=http://app.ppojin.localhost:30080
ENV KEYCLOAK_URI=http://keycloak.default.svc:8080
ENV HTTPBIN_URI=http://httpbin.default.svc:8080
ENV DEBUG_PORT=30050

# root 대신 nobody 권한으로 실행
USER nobody
ENTRYPOINT "java" \
    "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=0.0.0.0:${DEBUG_PORT}" \
    "-jar" \
    "-Dserver.port=${SERVER_PORT}" \
    "-Dppojin_gw.hostname=${HOSTNAME}" \
    "-Dppojin_gw.keycloak.uri=${KEYCLOAK_URI}" \
    "-Dppojin_gw.httpbin.uri=${HTTPBIN_URI}" \
    "gateway-0.0.1-SNAPSHOT.jar"
