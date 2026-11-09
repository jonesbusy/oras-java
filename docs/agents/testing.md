# Testing

## Kinds of tests

- Unit tests (`*Test.java`) run with `mvn test`. They use WireMock for HTTP mocking and Testcontainers for real registries: `ZotContainer` (HTTP + htpasswd), `ZotTlsContainer` (HTTPS only), `ZotUnsecureContainer`, all in `src/test/java/land/oras/utils/`. They need Docker or Podman.
- Integration tests (`*ITCase.java`) run with `mvn verify` against public or vendor registries (Docker Hub, GHCR, Quay, ECR, Harbor, Artifactory...). Many need credentials, so expect some to be skipped locally.
- OCI layout fixtures are in `src/test/resources/oci/`.
- New code needs at least 80% coverage. The JaCoCo report is at `target/site/jacoco/index.html`.

## Parallel execution

Test classes run concurrently (`src/test/resources/junit-platform.properties`, fixed parallelism 2, `max-pool-size=2`). Don't raise the pool size: resource locks make JUnit spawn extra threads, and the resulting burst of container starts breaks the Podman socket.

## Tests that change environment variables

Changing `HOME` or other env vars (system-stubs `EnvironmentVariables`) affects the whole JVM. Every `Registry.builder()` reads `HOME` to find `registries.conf`, so an unguarded env change makes other test classes flaky (for example `NoSuchFileException` on `/tmp/junit-*/.config/containers/registries.conf`).

- A method that writes the environment gets `@ResourceLock(EnvironmentLock.SYSTEM_ENVIRONMENT)`.
- A class that reads it gets `@ResourceLock(providers = EnvironmentLock.class)` on the class. This gives non-writer methods a READ lock. Don't put a class-level READ lock directly, because JUnit then escalates the whole class to READ_WRITE.
- To run code with a temporary `HOME`, use `TestUtils.withHome(path, () -> ...)`.

If a test that touches `registries.conf`, `HOME` or auth fails randomly in CI, check for this race before blaming a dependency bump.
