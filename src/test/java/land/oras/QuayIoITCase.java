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

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class QuayIoITCase {

    @TempDir
    private Path tempDir;

    @Test
    void shouldPullIndex() {
        Registry registry = Registry.builder().build();
        ContainerRef containerRef1 = ContainerRef.parse("quay.io/openshift/origin-cli:latest");
        Index index = registry.getIndex(containerRef1);
        assertNotNull(index);
    }

    @Test
    void shouldPullManifest() {
        Registry registry = Registry.builder().build();
        ContainerRef containerRef1 = ContainerRef.parse(
                "quay.io/openshift/origin-cli@sha256:569ebcccdc62d1dc1a2d01c05fbda49850747243d7afa838cf4601cd9e67e0fd");
        Manifest manifest = registry.getManifest(containerRef1);
        assertNotNull(manifest);
    }

    @Test
    void shouldPullOneBlob() {
        Registry registry = Registry.builder().build();
        ContainerRef containerRef1 = ContainerRef.parse(
                "quay.io/openshift/origin-cli@sha256:569ebcccdc62d1dc1a2d01c05fbda49850747243d7afa838cf4601cd9e67e0fd");
        Manifest manifest = registry.getManifest(containerRef1);
        Layer oneLayer = manifest.getLayers().get(0);
        registry.fetchBlob(containerRef1.withDigest(oneLayer.getDigest()), tempDir.resolve("my-blob"));
        assertNotNull(tempDir.resolve("my-blob"));
    }
}
