# ORAS Java

Java 17 SDK for [ORAS](https://oras.land/), built as one Maven module. Sources are in `src/main/java/land/oras/`.

## Commands

- `mvn clean install` — full build, formatting, license, Javadoc, and tests
- `mvn clean install -Pquick-build` — skip tests and checks
- `mvn test -Dtest=RegistryTest` — run one test class
- `mvn verify` — integration tests (`*ITCase`); Docker or Podman required
- `mvn javadoc:javadoc` — Javadoc; warnings fail the build

## Universal rules

- Before finishing: `mvn spotless:apply` and `mvn license:update-file-header`.
- Public API requires warning-free Javadoc.
- Use JSpecify `@Nullable` / `@NonNull`; do not introduce APIs newer than Java 17.
- Keep model classes immutable, add `with*()` copies, and retain `@JsonPropertyOrder` for stable serialized bytes.
- Security checks use the resolved reference after rewrites and mirror selection.

## Detailed guidelines

- [Architecture](docs/agents/architecture.md) — packages, core types, models, authentication
- [Security model](docs/agents/security.md) — resolution order, mirrors, policy, credentials
- [Testing](docs/agents/testing.md) — test types, containers, parallelism, environment locks
