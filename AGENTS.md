# AGENTS.md

oras-java is a Java 17 SDK for [ORAS](https://oras.land/): push and pull OCI artifacts to OCI registries and local OCI layouts. Single Maven module, sources under `src/main/java/land/oras/`.

## Commands

```bash
mvn clean install                  # full build: format, license, javadoc checks + tests
mvn clean install -Pquick-build    # skip tests and all checks
mvn test -Dtest=RegistryTest       # one test class
mvn verify                         # integration tests (*ITCase), need Docker/Podman
mvn spotless:apply                 # Palantir Java Format
mvn license:update-file-header     # add missing Apache 2.0 headers
mvn javadoc:javadoc                # fails on any warning
```

## Rules that apply to every change

- Run `mvn spotless:apply` and `mvn license:update-file-header` before finishing. The build fails on unformatted code or missing headers.
- Public API needs Javadoc that compiles without warnings (`failOnWarnings=true`).
- Use JSpecify `@Nullable` / `@NonNull` for nullability.
- Model classes are immutable. Derive copies with `with*()` methods. Keep `@JsonPropertyOrder` on them: serialized JSON must be byte-stable or digests change.
- Blocked/insecure/policy checks run on the resolved reference, after rewriting and mirror selection. Don't move them earlier. See [security.md](docs/agents/security.md).
- CI runs on Java 17, 21 and 25. Don't use APIs newer than 17.

## More detail

- [Architecture](docs/agents/architecture.md): packages, `OCI` / `Registry` / `OCILayout`, data models, auth
- [Security model](docs/agents/security.md): reference resolution order, mirrors, trust policy limits
- [Testing](docs/agents/testing.md): unit vs integration tests, Zot containers, parallel execution and env locks
