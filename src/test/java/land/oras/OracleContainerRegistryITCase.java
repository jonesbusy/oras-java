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

class OracleContainerRegistryITCase {

    @TempDir
    private Path tempDir;

    @Test
    void shouldPullIndex() {
        Registry registry = Registry.builder().build();
        ContainerRef containerRef1 = ContainerRef.parse("container-registry.oracle.com/os/oraclelinux:8");
        Index index = registry.getIndex(containerRef1);
        assertNotNull(index);
    }

    @Test
    void shouldPullOneBlob() {
        Registry registry = Registry.builder().build();
        ContainerRef containerRef1 = ContainerRef.parse(
                "container-registry.oracle.com/os/oraclelinux@sha256:50ab38810635947eebaa66f1d3b551fcb5a28cc372dd3022805d83618fb59c02");
        registry.fetchBlob(containerRef1, tempDir.resolve("my-blob"));
        assertNotNull(tempDir.resolve("my-blob"));
    }
}
