/*-
 * =LICENSE=
 * ORAS Java SDK
 * ===
 * Copyright (C) 2024 - 2025 ORAS
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import land.oras.utils.Const;
import land.oras.utils.SupportedAlgorithm;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

@Execution(ExecutionMode.CONCURRENT)
class LayerTest {

    @TempDir
    public static Path tempDir;

    @Test
    void shouldReadLayer() {
        String json = sampleLayer();
        Layer layer = Layer.fromJson(json);
        assertEquals("application/vnd.oci.image.layer.v1.tar+gzip", layer.getMediaType());
        assertEquals("sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", layer.getDigest());
        assertEquals(32654, layer.getSize());
        assertEquals(json, layer.toJson());
    }

    @Test
    void shouldReadLayerFromFile() throws Exception {
        Path file = tempDir.resolve("hi.txt");
        Files.writeString(file, "hi");
        Layer layer = Layer.fromFile(file);
        assertEquals("application/vnd.oci.image.layer.v1.tar", layer.getMediaType());
        assertEquals("sha256:8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4", layer.getDigest());
        assertEquals(2, layer.getSize());
        layer = Layer.fromFile(file, SupportedAlgorithm.SHA384);
        assertEquals("application/vnd.oci.image.layer.v1.tar", layer.getMediaType());
        assertEquals(
                "sha384:0791006df8128477244f53d0fdce210db81f55757510e26acee35c18a6bceaa28dcdbbfd6dc041b9b4dc7b1b54e37f52",
                layer.getDigest());
        assertEquals(2, layer.getSize());
        layer = Layer.fromFile(file, SupportedAlgorithm.SHA512);
        assertEquals("application/vnd.oci.image.layer.v1.tar", layer.getMediaType());
        assertEquals(
                "sha512:150a14ed5bea6cc731cf86c41566ac427a8db48ef1b9fd626664b3bfbb99071fa4c922f33dde38719b8c8354e2b7ab9d77e0e67fc12843920a712e73d558e197",
                layer.getDigest());
        assertEquals(2, layer.getSize());
    }

    @Test
    void shouldCreateLayerForCompressedDir() {
        ContainerRef containerRef = ContainerRef.parse("test/container:latest");
        byte[] data = "test".getBytes(); // We don't really care about the content here
        Layer layer = Layer.fromCompressedDirectory(containerRef, data);
        assertEquals("application/vnd.oci.image.layer.v1.tar+gzip", layer.getMediaType());
        assertEquals("sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", layer.getDigest());

        // Ensure unpack annotations is set
        assertEquals(1, layer.getAnnotations().size());
        assertEquals("true", layer.getAnnotations().get(Const.ANNOTATION_ORAS_UNPACK));
    }

    @Test
    void shouldHaveEmptyLayer() {
        String json = emptyLayer();
        assertEquals(Layer.fromJson(json).toJson(), Layer.empty().toJson());
    }

    @Test
    void shouldReadNullAnnotations() {
        String json =
                """
            {
              "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
              "digest": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
              "size": 32654
            }
        """;
        Layer layer = Layer.fromJson(json);
        assertEquals("application/vnd.oci.image.layer.v1.tar+gzip", layer.getMediaType());
        assertEquals("sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", layer.getDigest());
        assertEquals(32654, layer.getSize());
        assertEquals(0, layer.getAnnotations().size());
    }

    @Test
    void shouldReadBlobData() {
        String json =
                """
            {
              "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
              "digest": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
              "data": "e30="
            }
        """;
        Layer layer = Layer.fromJson(json);
        assertEquals("application/vnd.oci.image.layer.v1.tar+gzip", layer.getMediaType());
        assertEquals("sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", layer.getDigest());
        assertEquals("e30=", layer.getData());
    }

    @Test
    void testEqualsAndHashCode() {
        // Empty
        Layer empty1 = Layer.empty();
        Layer empty2 = Layer.empty();
        assertEquals(empty1, empty2);

        // Layer data
        Layer object1 = Layer.fromJson(sampleLayer());
        Layer object2 = Layer.fromJson(sampleLayer());
        assertEquals(object1, object2);
        assertEquals(object1.hashCode(), object2.hashCode());

        // Not equals
        Layer different = Layer.fromJson(emptyLayer()).withMediaType("fake/bar");
        assertNotEquals(object1, different);
        assertNotEquals(object1.hashCode(), different.hashCode());
        assertNotEquals("foo", object1);
        assertNotEquals(null, object1);
    }

    @Test
    void testToString() {
        Layer layer = Layer.fromJson(sampleLayer());
        String json = layer.toString();
        assertEquals(
                "{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\",\"digest\":\"sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\",\"size\":32654}",
                json);
    }

    private String emptyLayer() {
        return """
            {
              "mediaType": "application/vnd.oci.empty.v1+json",
              "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
              "size": 2,
              "data": "e30=",
              "annotations": {}
            }
        """;
    }

    /**
     * A sample manifest
     * @return The manifest
     */
    private String sampleLayer() {
        return Layer.fromJson(
                        """
                            {
                              "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                              "digest": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                              "size": 32654
                            }
                        """)
                .toJson();
    }
}
