# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Commands

```bash
# Build (all checks + tests)
mvn clean install

# Quick build (skip tests, formatting, license checks, spotless, javadoc)
mvn clean install -Pquick-build

# Unit tests only
mvn test

# Run a specific test class
mvn test -Dtest=RegistryTest

# Integration tests (requires Docker/Podman for Testcontainers)
mvn verify

# Check and apply code formatting (Palantir Java Format via Spotless)
mvn spotless:check
mvn spotless:apply

# Check and fix Apache 2.0 license headers
mvn license:check-file-header
mvn license:format

# Generate JavaDoc (failOnWarnings=true — keep Javadoc clean)
mvn javadoc:javadoc
```

## Architecture

**oras-java** is a Java SDK for [ORAS](https://oras.land/) (OCI Registry as Storage), enabling applications to push and pull OCI artifacts to/from OCI-conformant registries.

### Module Layout

Single-module Maven project. Main packages under `src/main/java/land/oras/`:

| Package               | Purpose                                                       |
|-----------------------|---------------------------------------------------------------|
| `land.oras`           | Core API — `Registry`, `OCILayout`, `OCI`, data models        |
| `land.oras.auth`      | Authentication providers and HTTP client                      |
| `land.oras.policy`    | Container policy classes                                      |
| `land.oras.utils`     | Constants, JSON/TOML/YAML utils, digest, compression, archive |
| `land.oras.exception` | `OrasException` and OCI error model                           |

### Core Abstraction

`OCI<T>` is a sealed abstract class that defines operations shared between remote registries and local layouts:

- **`Registry extends OCI<ContainerRef>`** — remote registry operations (push/pull blobs and manifests, list tags/repos/referrers). This is the main entry point for most users. Built via `Registry.Builder`.
- **`OCILayout extends OCI<LayoutRef>`** — local OCI layout on disk. Built via `OCILayout.Builder`.

### Data Models

All OCI data models live in the root `land.oras` package and are serialized/deserialized with Jackson. They are annotated with `@OrasModel` and use `@JsonPropertyOrder` to ensure deterministic JSON output (required for digest stability).

#### Class hierarchy

`Descriptor` is a sealed class with four permitted subtypes:

```
Descriptor (sealed)
├── Config      — the manifest's config object (often the empty config: {})
├── Layer       — a single content layer within a manifest
├── Manifest    — an OCI image manifest (schemaVersion, config, layers, subject, annotations)
└── Index       — an OCI image index / multi-arch manifest list (schemaVersion, manifests[])
```

Common fields on `Descriptor`: `mediaType`, `digest`, `size`, `artifactType`, `annotations`.
Additional fields:
- `Manifest` adds: `schemaVersion`, `config` (Config), `layers` (List\<Layer\>), `subject` (Subject)
- `Index` adds: `schemaVersion`, `manifests` (List\<ManifestDescriptor\>)
- `Layer` / `Config` add: `data` (optional base64 inline content)

Supporting classes (not subtypes of Descriptor):
- `ManifestDescriptor` — an entry inside an `Index.manifests[]` list; carries `mediaType`, `digest`, `size`, `annotations`, `artifactType`, `platform`
- `Subject` — the referrer target inside a `Manifest`; same shape as a descriptor
- `ContainerRef` — parses `[registry/]namespace/repository[:tag][@digest]` with regex validation
- `LayoutRef` — reference inside a local OCI layout (path + tag/digest)
- `LocalPath` — wraps a local file or directory for push operations
- `Annotations`, `Platform`, `ArtifactType` — thin value-objects

All models are immutable-style; use `with*()` methods to derive modified copies.

#### OCI JSON shapes

**OCI Image Index** (`index.json` at the root of an OCI layout):

```json
{
  "schemaVersion": 2,
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:cb1d49ba...",
      "size": 556,
      "annotations": {
        "org.opencontainers.image.created": "2025-03-08T08:20:56Z",
        "org.opencontainers.image.ref.name": "latest"
      },
      "artifactType": "foo/bar"
    }
  ]
}
```

**OCI Image Manifest** (stored as a blob, referenced by the index):

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "foo/bar",
  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "sha256:44136fa3...",
    "size": 2,
    "data": "e30="
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar",
      "digest": "sha256:98ea6e4f...",
      "size": 3,
      "annotations": { "org.opencontainers.image.title": "hi.txt" }
    }
  ],
  "annotations": { "org.opencontainers.image.created": "2025-03-08T08:20:56Z" }
}
```

**Manifest with `subject`** (referrer — attached to another manifest via the Referrers API):

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.text.file.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "sha256:44136fa3...",
    "size": 2,
    "data": "e30="
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar",
      "digest": "sha256:e094bc80...",
      "size": 4,
      "annotations": { "org.opencontainers.image.title": "hi2.txt" }
    }
  ],
  "subject": {
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "digest": "sha256:bb329f10...",
    "size": 554
  },
  "annotations": { "org.opencontainers.image.created": "2025-04-07T14:54:25Z" }
}
```

The empty config blob (`{}`, base64 `e30=`, digest `sha256:44136fa3...`) is used as the standard no-op config for non-image ORAS artifacts.

### Reference resolution and security evaluation order

Security decisions are always evaluated against the **effective (resolved)**
reference, never the raw reference passed by the caller. The order is fixed:

1. **Resolve** — short-name / unqualified-search expansion (`nginx` →
   `docker.io/library/nginx`), `registries.conf` `prefix` → `location` rewrites, and
   mirror selection. See `RegistriesConf.rewrite` / `rewriteForMirror` and
   `ContainerRef.getEffectiveRegistry`.
2. **Evaluate** — `ContainerRef.isBlocked` / `isInsecure` and the containers trust
   policy, all computed on the resolved reference (`ContainerRef.checkBlocked`,
   `Registry.verifyContainersPolicy`).
3. **Connect** — HTTP request.

Do **not** move blocked/insecure/policy checks before rewriting. Binding them to the
resolved host is deliberate: it prevents a mirror or alias from redirecting traffic
to a blocked or plaintext host that was only cleared under its original name.
`transportLocked` (`ContainerRef.isInsecure:511`) further prevents a registry-level
`insecure` entry from downgrading an explicitly-secure mirror connection.

Known, intentional limitations (do not "fix" without a design discussion):
- **Repo-level policy scope.** `ContainerRef.java` strips `:tag`/`@digest` before
  policy matching (the `policy.json` format is repository-scoped). Policy cannot
  target an individual tag or digest.
- **Policy is a pull-time gate.** `getManifest` runs `verifyContainersPolicy`;
  `deleteManifest` only runs `checkBlocked`. Deletes are not content-verified.
- **Config is trusted.** `registries.conf` / `policy.json` are operator-controlled;
  an attacker able to edit them is outside the threat model.

### Authentication

`AuthProvider` interface with implementations:
- `AuthStoreAuthenticationProvider` — reads `~/.docker/config.json` or `$XDG_RUNTIME_DIR/containers/auth.json`
- `UsernamePasswordProvider`, `BearerTokenProvider`, `NoAuthProvider`

`HttpClient` integrates `AuthProvider` and handles token caching (Caffeine) with automatic refresh.

### Testing

- **Unit tests** (`*Test.java`): Use WireMock for HTTP mocking and Testcontainers (`ZotContainer`) for in-process OCI registry. Parallel execution via `@Execution(ExecutionMode.CONCURRENT)`.
- **Integration tests** (`*ITCase.java`): Run against real external registries. Require credentials and Docker/Podman.

Test resources with OCI layout fixtures live in `src/test/resources/oci/`.

### Key Dependencies

- Jackson 3.x (JSON/TOML/YAML)
- Micrometer (metrics)
- Caffeine (token caching)
- Commons Compress + Zstd-JNI (archive/compression)
- BouncyCastle (cryptography)
- JSpecify (null-safety annotations — use `@Nullable`/`@NonNull` where appropriate)
- JUnit Jupiter + Testcontainers + WireMock + Mockito (tests)

### Code Style

- Java 17, formatted with **Palantir Java Format** (enforced via `mvn spotless:apply`)
- All source files require an Apache 2.0 license header (enforced via `mvn license:format`)
- JavaDoc must compile without warnings (`failOnWarnings=true`)
- CI tests against Java 17, 21, and 25
