# Architecture

## Packages

| Package               | Contents                                                          |
|-----------------------|-------------------------------------------------------------------|
| `land.oras`           | Public API: `Registry`, `OCILayout`, `OCI`, `CopyUtils`, models   |
| `land.oras.auth`      | Auth providers, `HttpClient`, token cache, `RegistriesConf`       |
| `land.oras.policy`    | `policy.json` support and Sigstore verification                   |
| `land.oras.utils`     | Constants (`Const`), JSON/TOML/YAML, digests, compression, archives |
| `land.oras.exception` | `OrasException` and the OCI error model                           |

## Core types

`OCI<T>` is a sealed abstract class holding the operations shared by remote and local storage:

- `Registry extends OCI<ContainerRef>`: a remote registry. Main entry point, built with `Registry.builder()`.
- `OCILayout extends OCI<LayoutRef>`: an OCI image layout on disk, as a directory or a `.tar`. Built with `OCILayout.Builder`.

`CopyUtils` copies between any two `OCI` implementations.

## Data models

Models live in `land.oras`, are annotated with `@OrasModel`, and are (de)serialized with Jackson 3 (`tools.jackson.*` packages, not `com.fasterxml.jackson.*`). `@JsonPropertyOrder` keeps output deterministic so digests are stable.

`Descriptor` is sealed:

```
Descriptor
├── Config    manifest config, usually the empty config {}
├── Layer     one content layer
├── Manifest  schemaVersion, config, layers, subject
└── Index     schemaVersion, manifests (List<ManifestDescriptor>)
```

Shared fields: `mediaType`, `digest`, `size`, `artifactType`, `annotations`. `Layer` and `Config` also have `data` (inline base64 content).

Other models, not `Descriptor` subtypes:

- `ManifestDescriptor`: one entry of `Index.manifests`, includes `platform`
- `Subject`: the referrer target in `Manifest.subject`
- `ContainerRef`: parses `[registry/]namespace/repository[:tag][@digest]`
- `LayoutRef`: path plus tag or digest inside a local layout
- `LocalPath`: a file or directory to push, with an optional media type
- `Annotations`, `Platform`, `ArtifactType`: small value objects

The empty config blob is `{}` (base64 `e30=`, `application/vnd.oci.empty.v1+json`) and is the default config for non-image artifacts. Sample `index.json` and manifest files are in `src/test/resources/oci/`.

## Authentication

`AuthProvider` implementations:

- `AuthStoreAuthenticationProvider`: reads `~/.docker/config.json` or `$XDG_RUNTIME_DIR/containers/auth.json`, scoped per host
- `UsernamePasswordProvider`, `BearerTokenProvider`: static credentials that ignore the target host
- `NoAuthProvider`

`HttpClient` uses the provider and caches tokens in Caffeine (`TokenCache`), refreshing them when they expire.
