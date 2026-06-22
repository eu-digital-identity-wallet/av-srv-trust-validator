# Copyright (c) 2025-2026 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# --- Build stage ---
FROM eclipse-temurin:17-jdk-jammy AS builder
WORKDIR /app

# Copy the Gradle wrapper and build configuration first, so dependency
# resolution is cached as a separate layer when only sources change.
COPY gradlew settings.gradle.kts build.gradle.kts gradle.properties ./
COPY gradle ./gradle
RUN chmod +x gradlew && ./gradlew --no-daemon dependencies > /dev/null 2>&1 || true

# Build the executable (boot) jar.
COPY src ./src
RUN ./gradlew --no-daemon -x test bootJar

# Spring Boot produces both the executable jar and a "-plain" jar; keep only the executable one.
RUN cp "$(ls build/libs/*.jar | grep -v -- '-plain')" app.jar

# Explode the boot jar so the application runs from an extracted layout (like the buildpack image).
# This is required because classpath resources such as 'tl.jks' must resolve to real files on disk
# (BOOT-INF/classes/...), which is not the case when running the fat jar with `java -jar`.
RUN mkdir exploded && (cd exploded && jar -xf ../app.jar)

# --- Runtime stage ---
FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

# Run as a non-root user.
RUN groupadd --system app && useradd --system --gid app app

# Copy the exploded application (BOOT-INF/classes is a real directory → classpath resources are files).
COPY --from=builder /app/exploded/ ./

# Point the DSS / LoTE caches to a writable location (the working directory is not writable
# for the non-root user). Override at runtime if you mount a persistent volume.
ENV TRUST_VALIDATOR_DSS_CACHE_LOCATION=/tmp/dss-cache \
    TRUST_VALIDATOR_LOTE_CACHE_LOCATION=/tmp/lote-cache \
    SERVER_PORT=8080

USER app
EXPOSE 8080
ENTRYPOINT ["java", "-cp", "/app", "org.springframework.boot.loader.launch.JarLauncher"]
