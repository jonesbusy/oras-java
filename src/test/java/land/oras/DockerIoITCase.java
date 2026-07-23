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

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import land.oras.utils.ZotUnsecureContainer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@Execution(ExecutionMode.CONCURRENT)
class DockerIoITCase {

    @TempDir
    Path tempDir;

    @Container
    private final ZotUnsecureContainer unsecureRegistry = new ZotUnsecureContainer().withStartupAttempts(3);

    @Test
    void shouldGetTags() {
        Registry registry = Registry.builder().build();
        ContainerRef containerRef = ContainerRef.parse("docker.io/library/alpine");
        Tags tags = registry.getTags(containerRef);
        assertNotNull(tags);
        assertTrue(tags.tags().size() > 100);
        tags = registry.getTags(containerRef, 2, null);
        assertNotNull(tags);
        assertEquals(2, tags.tags().size());
        assertEquals("2.7", tags.last());
        tags = registry.getTags(containerRef, 2, tags.last());
        assertNotNull(tags);
        assertEquals(2, tags.tags().size());
        assertEquals("20190408", tags.last());
    }

    @Test
    void shouldPullAnonymousIndexFQDN() {

        // FQDN
        Registry registry = Registry.builder().build();
        ContainerRef containerRef = ContainerRef.parse("docker.io/library/alpine");
        Index index = registry.getIndex(containerRef);
        assertNotNull(index);
    }

    @Test
    void shouldPullAnonymousIndexDefaultRegistryAndNamespace() {
        // Simple name
        Registry registry = Registry.builder().build();
        ContainerRef containerRef3 = ContainerRef.parse("library/alpine");
        Index index3 = registry.getIndex(containerRef3);
        assertNotNull(index3);
    }

    @Test
    void shouldPullAnonymousIndexUnqualified() {

        // Simple name
        Registry registry = Registry.builder().build();
        ContainerRef containerRef = ContainerRef.parse("alpine");
        Index index3 = registry.getIndex(containerRef);
        assertNotNull(index3);
    }

    @Test
    void shouldPullOneBlob() {
        Registry registry = Registry.builder().build();
        ContainerRef containerRef1 = ContainerRef.parse("jbangdev/jbang-action");
        String effectiveRegistry = containerRef1.getEffectiveRegistry(registry);
        Manifest manifest = registry.getManifest(containerRef1);
        Layer oneLayer = manifest.getLayers().get(0);
        registry.fetchBlob(
                containerRef1.forRegistry(effectiveRegistry).withDigest(oneLayer.getDigest()),
                tempDir.resolve("my-blob"));
        assertNotNull(tempDir.resolve("my-blob"));
    }

    @Test
    void shouldCopyTagToInternalRegistry() {

        // Source registry
        Registry sourceRegistry =
                Registry.Builder.builder().withParallelism(3).defaults().build();

        // Copy to this internal registry
        Registry targetRegistry = Registry.Builder.builder()
                .defaults("myuser", "mypass")
                .withParallelism(3)
                .withInsecure(true)
                .build();

        ContainerRef containerSource = ContainerRef.parse("docker.io/library/alpine:latest");
        ContainerRef containerTarget =
                ContainerRef.parse("%s/docker/library/alpine:latest".formatted(unsecureRegistry.getRegistry()));

        CopyUtils.copy(sourceRegistry, containerSource, targetRegistry, containerTarget, CopyUtils.CopyOptions.deep());
        assertTrue(targetRegistry.exists(containerTarget));
    }

    @Test
    void shouldContainsCommonLinuxPlatform() {

        // Source registry
        Registry sourceRegistry = Registry.Builder.builder().defaults().build();

        ContainerRef containerSource = ContainerRef.parse(
                "docker.io/library/alpine@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659");

        Index index = sourceRegistry.getIndex(containerSource);

        // Ensure standard platform matching
        assertTrue(index.getManifests().stream().anyMatch(m -> m.getPlatform().equals(Platform.linux386())));
        assertTrue(index.getManifests().stream().anyMatch(m -> m.getPlatform().equals(Platform.linuxAmd64())));
        assertTrue(index.getManifests().stream().anyMatch(m -> m.getPlatform().equals(Platform.linuxArmV6())));
        assertTrue(index.getManifests().stream().anyMatch(m -> m.getPlatform().equals(Platform.linuxArmV7())));
        assertTrue(index.getManifests().stream().anyMatch(m -> m.getPlatform().equals(Platform.linuxArm64V8())));
        assertTrue(index.getManifests().stream().anyMatch(m -> m.getPlatform().equals(Platform.linuxPpc64le())));
        assertTrue(index.getManifests().stream().anyMatch(m -> m.getPlatform().equals(Platform.linuxS390x())));
        assertTrue(index.getManifests().stream().anyMatch(m -> m.getPlatform().equals(Platform.linuxRiscv64())));
    }

    @Test
    @Execution(ExecutionMode.SAME_THREAD)
    void shouldCopyTagToInternalRegistryViaAlias(@TempDir Path homeDir) throws Exception {

        // language=toml
        String config =
                """
            [aliases]
            "dockerhub-alpine" = "docker.io/library/alpine"
            """;
        TestUtils.createRegistriesConfFile(homeDir, config);

        TestUtils.withHome(homeDir, () -> {
            // Source registry
            Registry sourceRegistry = Registry.Builder.builder().defaults().build();

            // Copy to this internal registry
            Registry targetRegistry = Registry.Builder.builder()
                    .defaults("myuser", "mypass")
                    .withInsecure(true)
                    .build();

            ContainerRef containerSource = ContainerRef.parse("dockerhub-alpine");
            ContainerRef containerTarget =
                    ContainerRef.parse("%s/docker/library/alpine:latest".formatted(unsecureRegistry.getRegistry()));

            CopyUtils.copy(
                    sourceRegistry, containerSource, targetRegistry, containerTarget, CopyUtils.CopyOptions.deep());
            assertTrue(targetRegistry.exists(containerTarget));
        });
    }
}
