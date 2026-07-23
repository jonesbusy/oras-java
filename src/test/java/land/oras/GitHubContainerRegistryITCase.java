/*-
 * =LICENSE=
 * ORAS Java SDK
 * ===
 * Copyright (C) 2024 - 2026 ORAS
 * ===
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =LICENSEEND=
 */

package land.oras;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import land.oras.policy.ContainersPolicy;
import land.oras.utils.ArchiveUtils;
import land.oras.utils.Const;
import land.oras.utils.ZotUnsecureContainer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@Execution(ExecutionMode.CONCURRENT)
class GitHubContainerRegistryITCase {

    @Container
    private final ZotUnsecureContainer unsecureRegistry = new ZotUnsecureContainer().withStartupAttempts(3);

    @TempDir
    Path tempDir;

    @Test
    void shouldGetTags() {
        Registry registry = Registry.builder().build();
        ContainerRef containerRef = ContainerRef.parse("ghcr.io/jenkinsci/helm-charts/jenkins");
        Tags tags = registry.getTags(containerRef);
        assertTrue(tags.tags().contains("5.9.40"), "Tag 5.9.40 must exists");
        assertTrue(tags.tags().size() > 50, "More that 50 must be returned");
    }

    @Test
    void shouldPullIndex() {
        Registry registry = Registry.builder().build();
        ContainerRef containerRef1 = ContainerRef.parse("ghcr.io/oras-project/oras:main");
        Index index = registry.getIndex(containerRef1);
        assertNotNull(index);
    }

    @Test
    void shouldGetReferrersUsingLegacyTagFallback() {
        Registry registry = Registry.builder().build();
        ContainerRef containerRef = ContainerRef.parse(
                "ghcr.io/jonesbusy/alpine-signed@sha256:9e56ed4cb843f61658fcdb17d4205a87d5e217515f23831314b2173a776174d6");
        Referrers referrers = registry.getReferrers(containerRef, null);
        assertFalse(referrers.getManifests().isEmpty(), "Referrers must be found through the legacy tag fallback");
        assertTrue(
                referrers.getManifests().stream().anyMatch(manifest -> "application/vnd.dev.sigstore.bundle.v0.3+json"
                        .equals(manifest.getArtifactType())),
                "Sigstore bundle referrer must be found");
    }

    @Test
    @Execution(ExecutionMode.SAME_THREAD)
    void shouldPullSignedImage(@TempDir Path homeDir) throws Exception {

        Path path = homeDir.resolve("policy.json");
        Path publicKeyPath = Path.of("src/test/resources/keys/sigstore/alpine-signed.pub");

        // language=toml
        String config =
                """
            [[registry]]
            location = "ghcr.io"
            insecure = false
            """;

        // language=json
        Files.writeString(
                path,
                """
                {
                  "default": [{"type": "reject"}],
                  "transports": {
                    "docker": {
                      "ghcr.io/jonesbusy/alpine-signed": [{"type": "sigstoreSigned", "keyPath": "%s"}]
                    }
                  }
                }
                """
                        .formatted(publicKeyPath.toAbsolutePath().toString()));
        ContainersPolicy policy = ContainersPolicy.newPolicy(path);
        TestUtils.createRegistriesConfFile(homeDir, config);
        TestUtils.withHome(homeDir, () -> {
            Registry registry = Registry.builder().defaults().withPolicy(policy).build();
            ContainerRef containerRef1 = ContainerRef.parse("ghcr.io/jonesbusy/alpine-signed:latest");
            Manifest manifest = registry.getManifest(containerRef1);
            assertNotNull(manifest);
        });
    }

    @Test
    @Execution(ExecutionMode.SAME_THREAD)
    void shouldPullIndexWithAlias(@TempDir Path homeDir) throws Exception {
        // language=toml
        String config =
                """
                [aliases]
                "oras"="ghcr.io/oras-project/oras"
                """;

        // Setup
        TestUtils.createRegistriesConfFile(homeDir, config);

        TestUtils.withHome(homeDir, () -> {
            Registry registry = Registry.builder().defaults().build();
            ContainerRef containerRef1 = ContainerRef.parse("oras:main");
            Index index = registry.getIndex(containerRef1);
            assertNotNull(index);
        });
    }

    @Test
    void shouldPUllManifest() {
        Registry registry = Registry.builder().build();
        ContainerRef containerRef1 = ContainerRef.parse(
                "ghcr.io/oras-project/oras@sha256:fd4c818e80ea594cbd39ca47dc05067c8c5690c4eee6c8aee48c508290a5a0c0");
        Manifest manifest = registry.getManifest(containerRef1);
        assertNotNull(manifest);
    }

    @Test
    void shouldPullOneBlob() {
        Registry registry = Registry.builder().build();
        ContainerRef containerRef1 = ContainerRef.parse("ghcr.io/oras-project/oras:main");
        Index index = registry.getIndex(containerRef1);
        Manifest manifest = registry.getManifest(
                containerRef1.withDigest(index.getManifests().get(1).getDigest())); // Just take first manifest
        Layer oneLayer = manifest.getLayers().get(0);
        registry.fetchBlob(containerRef1.withDigest(oneLayer.getDigest()), tempDir.resolve("my-blob"));
        assertNotNull(tempDir.resolve("my-blob"));
    }

    @Test
    void shouldPullArtifact() {
        Registry registry = Registry.builder().build();
        ContainerRef artifact = ContainerRef.parse("ghcr.io/aquasecurity/trivy-db:2");
        registry.pullArtifact(artifact, tempDir, false);
        assertNotNull(tempDir.resolve("db.tar.gz"));
        ArchiveUtils.uncompressuntar(
                tempDir.resolve("db.tar.gz"), tempDir.resolve("db"), Const.DEFAULT_BLOB_DIR_MEDIA_TYPE);
    }

    @Test
    void shouldCopyTagToInternalRegistry() {

        // Source registry
        Registry sourceRegistry = Registry.Builder.builder().defaults().build();

        // Copy to this internal registry
        Registry targetRegistry = Registry.Builder.builder()
                .defaults("myuser", "mypass")
                .withInsecure(true)
                .build();

        ContainerRef containerSource = ContainerRef.parse("ghcr.io/oras-project/oras:main");
        ContainerRef containerTarget =
                ContainerRef.parse("%s/docker/library/oras:main".formatted(unsecureRegistry.getRegistry()));

        CopyUtils.copy(sourceRegistry, containerSource, targetRegistry, containerTarget, CopyUtils.CopyOptions.deep());
        assertTrue(targetRegistry.exists(containerTarget));
    }
}
