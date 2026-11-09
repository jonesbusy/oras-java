<div align="center">

<a href="https://oras.land/"><img src="https://oras.land/img/oras.svg" alt="ORAS logo" width="160px"></a>

# ORAS Java SDK

[![Build](https://github.com/oras-project/oras-java/actions/workflows/build.yml/badge.svg)](https://github.com/oras-project/oras-java/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/oras-project/oras-java/branch/main/graph/badge.svg)](https://codecov.io/gh/oras-project/oras-java)
![GitHub Release](https://img.shields.io/github/v/release/oras-project/oras-java?logo=github&color=green)
[![GitHub license](https://img.shields.io/github/license/oras-project/oras-java)](https://github.com/oras-project/oras-java/blob/main/LICENSE)
[![Javadoc](https://img.shields.io/badge/javadoc-latest-blue)](https://oras-project.github.io/oras-java/)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/oras-project/oras-java/badge)](https://scorecard.dev/viewer/?uri=github.com/oras-project/oras-java)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/10047/badge)](https://www.bestpractices.dev/projects/10047)
[![Reproducible Central Artifact](https://img.shields.io/reproducible-central/artifact/land.oras/oras-java-sdk/0.2.15)](https://github.com/jvm-repo-rebuild/reproducible-central/blob/master/content/land/oras/oras-java-sdk/README.md)

Push and pull OCI artifacts from Java.

[Install](#install) · [Examples](#examples) · [Registries configuration](#registries-configuration) · [Trust policy](#trust-policy) · [Javadoc](https://oras-project.github.io/oras-java/)

</div>

[ORAS](https://oras.land/) (OCI Registry as Storage) lets you store any file in an [OCI-conformant](https://github.com/opencontainers/oci-conformance) registry, not just container images. This SDK brings that to Java applications. It can:

- push and pull files and directories as OCI artifacts
- attach signatures, SBOMs or other artifacts to an existing one through the Referrers API
- copy artifacts between registries and to or from a local [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md) (directory or tar)
- reuse your Docker or Podman credentials, `registries.conf` and `policy.json`, including Sigstore signature verification

> [!WARNING]
> The SDK is in **preview**. Configuration and APIs may still change between releases.

## Install

Releases are published to Maven Central. Requires Java 17 or later.

```xml
<dependency>
    <groupId>land.oras</groupId>
    <artifactId>oras-java-sdk</artifactId>
    <version>VERSION_HERE</version>
</dependency>
```

Using Quarkus? The [`quarkus-oras`](https://docs.quarkiverse.io/quarkus-oras/dev/index.html) extension wraps this SDK.

<details>
<summary>Using SNAPSHOT builds</summary>

Every commit on `main` publishes a SNAPSHOT to the Maven Central snapshots repository. Use them for testing only.

```xml
<repositories>
    <repository>
        <id>central-snapshots</id>
        <name>ORAS Maven Central SNAPSHOTS</name>
        <url>https://central.sonatype.com/repository/maven-snapshots/</url>
        <snapshots>
            <enabled>true</enabled>
        </snapshots>
        <releases>
            <enabled>false</enabled>
        </releases>
    </repository>
</repositories>
```

</details>

## Examples

### Authentication

Reuse the credentials from `~/.docker/config.json` or `$XDG_RUNTIME_DIR/containers/auth.json`:

```java
Registry registry = Registry.builder().defaults().build();
```

Or pass a username and password:

```java
Registry registry = Registry.builder().defaults("username", "password").build();
```

The examples below use `insecure()` because they target a local registry over plain HTTP. Drop it for real registries.

### Push a file

```java
Registry registry = Registry.builder().insecure().build();
LocalPath artifact = LocalPath.of(Path.of("my-file.txt"));
Manifest manifest = registry.pushArtifact(ContainerRef.parse("localhost:5000/hello:v1"), artifact);
```

### Push several files with a custom artifact type

Each file becomes one layer, named after the file through the `org.opencontainers.image.title` annotation. You can set a media type per file and add annotations to the manifest or to individual files:

```java
Registry registry = Registry.builder().insecure().build();

Annotations annotations = Annotations.ofManifest(Map.of("build-tool", "maven"))
        .withFileAnnotations("pom.xml", Map.of("format", "xml"));

Manifest manifest = registry.pushArtifact(
        ContainerRef.parse("localhost:5000/my-app:v1"),
        ArtifactType.from("application/vnd.maven+type"),
        annotations,
        LocalPath.of(Path.of("pom.xml"), "application/xml"),
        LocalPath.of(Path.of("target/app.jar"), "application/java-archive"));
```

### Push a directory

A directory is packed into a `tar+gzip` layer titled with the directory name. The SDK also sets `io.deis.oras.content.unpack=true`, so pulling the artifact extracts it again.

```java
Registry registry = Registry.builder().insecure().build();
Manifest manifest = registry.pushArtifact(
        ContainerRef.parse("localhost:5000/my-configs:v1"),
        LocalPath.of(Path.of("config-dir")));
```

To push it as a zip instead, give the media type:

```java
Manifest manifest = registry.pushArtifact(
        ContainerRef.parse("localhost:5000/my-configs:v1"),
        LocalPath.of(Path.of("config-dir"), "application/zip"));
```

### Pull an artifact

Files are written using their `org.opencontainers.image.title` annotation as the file name. The last argument says whether to overwrite existing files.

```java
Registry registry = Registry.builder().insecure().build();
registry.pullArtifact(ContainerRef.parse("localhost:5000/hello:v1"), Path.of("output-dir"), true);
```

### Attach an artifact (referrers)

Attached artifacts, like a signature or an attestation, point at the original manifest through their `subject` field. Clients find them with the [Referrers API](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers).

```java
Registry registry = Registry.builder().insecure().build();
ContainerRef ref = ContainerRef.parse("localhost:5000/my-app:v1");

Manifest manifest = registry.pushArtifact(ref,
        ArtifactType.from("application/vnd.maven+type"),
        LocalPath.of(Path.of("pom.xml"), "application/xml"));

Manifest signatureManifest = registry.attachArtifact(
        ref,
        ArtifactType.from("application/vnd.example.signature"),
        LocalPath.of(Path.of("pom.xml.asc")));

Referrers referrers = registry.getReferrers(
        ref.withDigest(manifest.getDescriptor().getDigest()), null);
```

### Build a manifest from individual blobs

When `pushArtifact` is too high-level, push the blobs and config yourself and assemble the manifest:

```java
Registry registry = Registry.builder().insecure().build();
ContainerRef ref = ContainerRef.parse("localhost:5000/my-app:v1");

Layer layer1 = registry.pushBlob(ref, Files.readAllBytes(Path.of("schema.json")))
        .withAnnotations(Map.of(Const.ANNOTATION_TITLE, "schema.json"));
Layer layer2 = registry.pushBlob(ref, Files.readAllBytes(Path.of("data.csv")))
        .withAnnotations(Map.of(Const.ANNOTATION_TITLE, "data.csv"));

Config config = registry.pushConfig(ref, Config.empty().withMediaType("application/vnd.example.config+json"));

Manifest manifest = Manifest.empty()
        .withConfig(config)
        .withLayers(List.of(layer1, layer2));
registry.pushManifest(ref, manifest);
```

### Copy between registries

Copies the manifest and all its blobs:

```java
Registry source = Registry.builder().defaults("user", "pass").insecure().build();
Registry target = Registry.builder().defaults("user", "pass").build();

ContainerRef from = ContainerRef.parse("localhost:5000/my-app:v1");
ContainerRef to = ContainerRef.parse("registry.example.com/my-app:v1");

CopyUtils.copy(source, from, target, to, CopyUtils.CopyOptions.shallow());
```

### OCI image layout

`OCILayout` has the same push and pull API as `Registry`, but reads and writes an [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md) on disk.

```java
LayoutRef ref = LayoutRef.parse("/tmp/my-layout:latest");
OCILayout ociLayout = OCILayout.Builder.builder().defaults(Path.of("/tmp/my-layout")).build();

// Push
ociLayout.pushArtifact(
        ref,
        ArtifactType.from("application/vnd.example.type"),
        Annotations.empty(),
        LocalPath.of(Path.of("my-file.txt"), "text/plain"));

// Pull
ociLayout.pullArtifact(ref, Path.of("output-dir"), false);
```

Point it at a `.tar` path to get a single portable archive instead of a directory. The API doesn't change:

```java
LayoutRef ref = LayoutRef.parse("/tmp/my-layout.tar:latest");
OCILayout ociLayout = OCILayout.Builder.builder().defaults(Path.of("/tmp/my-layout.tar")).build();
```

`CopyUtils` also works between a layout and a registry:

```java
LayoutRef layoutRef = LayoutRef.parse("/tmp/my-layout:latest");
OCILayout ociLayout = OCILayout.Builder.builder().defaults(Path.of("/tmp/my-layout")).build();

Registry registry = Registry.builder().defaults("user", "pass").build();
ContainerRef target = ContainerRef.parse("registry.example.com/my-app:v1");

CopyUtils.copy(ociLayout, layoutRef, registry, target, CopyUtils.CopyOptions.shallow());
```

## Registries configuration

Since `0.7.0` the SDK reads [`registries.conf`](https://github.com/containers/image/blob/main/docs/containers-registries.conf.5.md), the same file Podman, Skopeo and Buildah use. Files are loaded in this order, and later ones override earlier ones:

1. `/etc/containers/registries.conf`
2. `/etc/containers/registries.conf.d/*.conf` (alphabetical)
3. `$HOME/.config/containers/registries.conf`
4. `$HOME/.config/containers/registries.conf.d/*.conf` (alphabetical)

Supported settings:

```toml
# Short-name resolution (enforcing is the default)
short-name-mode = "enforcing"
unqualified-search-registries = ["docker.io"]

# Rewrite a prefix to another location
[[registry]]
prefix = "docker.io/bitnami"
location = "docker.io/bitnamilegacy"

# Block a registry
[[registry]]
prefix = "gcr.io"
blocked = true

# Use plain HTTP
[[registry]]
location = "localhost:5000"
insecure = true

# Mirrors, tried in order before falling back to the upstream registry
[[registry]]
prefix = "registry.example.com"
location = "registry.example.com"
mirror-by-digest-only = false   # true restricts every mirror to digest pulls

  [[registry.mirror]]
  location = "mirror1.example.com"
  insecure = false
  pull-from-mirror = "all"       # "all" (default) | "tag-only" | "digest-only"

  [[registry.mirror]]
  location = "mirror2.example.com"
  insecure = true
  pull-from-mirror = "digest-only"
```

### How references are resolved

For every operation the SDK first resolves the reference, then applies security checks, then connects:

1. Resolve: expand short names (`nginx` becomes `docker.io/library/nginx`), apply `prefix` → `location` rewrites and pick a mirror.
2. Check: apply `blocked`, `insecure` and the trust policy to the resolved reference.
3. Connect.

The checks run on the host the request will actually reach, not on the name you passed in. Otherwise a mirror or alias could send traffic to a blocked or plain-HTTP host while the check passed on the original name. `registries.conf` and `policy.json` are treated as trusted operator configuration. If an attacker can edit them, the host is already compromised.

This has two consequences:

- Policies are scoped to repositories. `policy.json` matches `registry[/namespace/repository]` and ignores tags and digests, so you can't write a rule for a single tag or digest.
- The trust policy is only checked on pulls. Deletes are checked against `blocked` and `insecure` but not verified. To protect a digest from deletion, use registry-side RBAC or tag immutability.

## Trust policy

The SDK can verify pulls against a [`policy.json`](https://man.archlinux.org/man/containers-policy.json.5.en) trust policy, the format Podman, Skopeo and Buildah use. The first file found wins:

1. `$HOME/.config/containers/policy.json`
2. `/etc/containers/policy.json`

Without a policy file, everything is accepted. You can also set the policy in code:

```java
// From a file
Registry registry = Registry.builder()
        .defaults()
        .withPolicy(Path.of("/etc/containers/policy.json"))
        .build();

// Or programmatically
Registry registry = Registry.builder()
        .defaults()
        .withPolicy(ContainersPolicy.rejectAll())
        .build();
```

Every manifest or index pull is checked against the policy. A pull that fails throws an `OrasException`.

| Requirement type         | Supported | Behavior                                                    |
|--------------------------|-----------|-------------------------------------------------------------|
| `insecureAcceptAnything` | Yes       | Accept without verification.                                |
| `reject`                 | Yes       | Always reject.                                              |
| `sigstoreSigned`         | Yes       | Accept only images signed with the given Sigstore (cosign) key. |
| `signedBy` (GPG)         | No        | Legacy, not implemented.                                    |

### `sigstoreSigned`

Only keyed verification is supported. Give a single Sigstore public key (the `cosign.pub` from `cosign generate-key-pair`) with either:

- `keyPath`: path to the PEM public key
- `keyData`: the same key, base64-encoded

Multiple keys (`keyPaths`, `keyDatas`) and keyless Fulcio/Rekor verification aren't supported yet.

The SDK finds signatures through the [Referrers API](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers), looking for a Sigstore bundle (`application/vnd.dev.sigstore.bundle.v0.3+json`) attached to the image. It doesn't read a local signature store. The signature is bound to the pulled image by digest. `signedIdentity` is ignored: the cosign bundle only carries the image digest, so there is no Docker reference to compare against.

```json
{
    "default": [{"type": "insecureAcceptAnything"}],
    "transports": {
        "docker": {
            "example.com/my-image": [
                {"type": "sigstoreSigned", "keyPath": "/home/me/my-key.pub"}
            ]
        }
    }
}
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). This project follows the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/master/code-of-conduct.md).
