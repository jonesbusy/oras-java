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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import land.oras.utils.Const;
import land.oras.utils.JsonUtils;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.NullUnmarked;
import org.jspecify.annotations.Nullable;

/**
 * Class for manifest
 */
@NullUnmarked
@OrasModel
@JsonPropertyOrder({
    Const.JSON_PROPERTY_SCHEMA_VERSION,
    Const.JSON_PROPERTY_MEDIA_TYPE,
    Const.JSON_PROPERTY_ARTIFACT_TYPE,
    Const.JSON_PROPERTY_DIGEST,
    Const.JSON_PROPERTY_SIZE,
    Const.JSON_PROPERTY_CONFIG,
    Const.JSON_PROPERTY_SUBJECT,
    Const.JSON_PROPERTY_ANNOTATIONS,
    Const.JSON_PROPERTY_DATA,
    Const.JSON_PROPERTY_LAYERS
})
@JsonInclude(JsonInclude.Include.NON_NULL) // We need to serialize empty list of layers
public final class Manifest extends Descriptor implements Describable {

    private final int schemaVersion;
    private final Config config;
    private final Subject subject;
    private final List<Layer> layers;

    /**
     * The manifest descriptor
     */
    private final ManifestDescriptor descriptor;

    @JsonCreator
    @SuppressWarnings("unused")
    private Manifest(
            @JsonProperty(Const.JSON_PROPERTY_SCHEMA_VERSION) int schemaVersion,
            @JsonProperty(Const.JSON_PROPERTY_MEDIA_TYPE) String mediaType,
            @JsonProperty(Const.JSON_PROPERTY_SIZE) Long size,
            @JsonProperty(Const.JSON_PROPERTY_ARTIFACT_TYPE) String artifactType,
            @JsonProperty(Const.JSON_PROPERTY_DIGEST) String digest,
            @JsonProperty(Const.JSON_PROPERTY_CONFIG) Config config,
            @JsonProperty(Const.JSON_PROPERTY_SUBJECT) Subject subject,
            @JsonProperty(Const.JSON_PROPERTY_LAYERS) List<Layer> layers,
            @JsonProperty(Const.JSON_PROPERTY_ANNOTATIONS) Map<String, String> annotations) {
        super(
                digest,
                size,
                mediaType,
                annotations != null && !annotations.isEmpty() ? Map.copyOf(annotations) : null,
                artifactType,
                null,
                null);
        this.schemaVersion = schemaVersion;
        this.descriptor = null;
        this.config = config;
        this.subject = subject;
        this.layers = layers;
    }

    private Manifest(
            int schemaVersion,
            String mediaType,
            ArtifactType artifactType,
            ManifestDescriptor descriptor,
            Config config,
            Subject subject,
            List<Layer> layers,
            Annotations annotations,
            String registry,
            String json) {
        super(
                null,
                null,
                mediaType,
                Map.copyOf(annotations.manifestAnnotations()),
                artifactType != null ? artifactType.getMediaType() : null,
                registry,
                json);
        this.schemaVersion = schemaVersion;
        this.descriptor = descriptor;
        this.config = config;
        this.subject = subject;
        this.layers = layers;
    }

    /**
     * Get the schema version
     * @return The schema version
     */
    public int getSchemaVersion() {
        return schemaVersion;
    }

    @Override
    @JsonIgnore
    public @NonNull ArtifactType getArtifactType() {
        if (artifactType != null) {
            return ArtifactType.from(artifactType);
        }
        if (config != null) {
            return ArtifactType.from(
                    config.getMediaType() != null ? config.getMediaType() : Const.DEFAULT_ARTIFACT_MEDIA_TYPE);
        }
        return ArtifactType.unknown();
    }

    @Override
    protected Manifest withRegistry(String registry) {
        return (Manifest) super.withRegistry(registry);
    }

    /**
     * Get the artifact type as string for JSON serialization
     * @return The artifact type as string
     */
    @JsonProperty(Const.JSON_PROPERTY_ARTIFACT_TYPE)
    @SuppressWarnings("unused")
    public String getArtifactTypeAsString() {
        return artifactType;
    }

    @Override
    @JsonIgnore
    public ManifestDescriptor getDescriptor() {
        return descriptor;
    }

    @Override
    @JsonIgnore
    public String getDigest() {
        if (descriptor == null) {
            return super.getDigest();
        }
        return descriptor.getDigest();
    }

    /**
     * Get the top-level digest (for JSON serialization)
     * @return The top-level digest
     */
    @JsonProperty(Const.JSON_PROPERTY_DIGEST)
    @SuppressWarnings("unused")
    public String getTopLevelDigest() {
        return digest;
    }

    /**
     * Get the config
     * @return The config
     */
    public Config getConfig() {
        return config;
    }

    @Override
    public Subject getSubject() {
        return subject;
    }

    /**
     * Get the layers
     * @return The layers
     */
    public List<Layer> getLayers() {
        return layers != null ? Collections.unmodifiableList(layers) : List.of();
    }

    /**
     * Return a new manifest with the given artifact type
     * @param artifactType The artifact type
     * @return The manifest
     */
    public Manifest withArtifactType(ArtifactType artifactType) {
        return new Manifest(
                schemaVersion,
                mediaType,
                artifactType,
                descriptor,
                config,
                subject,
                layers,
                Annotations.ofManifest(annotations),
                registry,
                json);
    }

    /**
     * Return a new manifest with the given layers
     * @param layers The layers
     * @return The manifest
     */
    public Manifest withLayers(List<Layer> layers) {
        return new Manifest(
                schemaVersion,
                mediaType,
                getTopLevelArtifactType(),
                descriptor,
                config,
                subject,
                layers,
                Annotations.ofManifest(annotations),
                registry,
                json);
    }

    /**
     * Return a new manifest with the given config
     * @param config The config
     * @return The manifest
     */
    public Manifest withConfig(Config config) {
        return new Manifest(
                schemaVersion,
                mediaType,
                getTopLevelArtifactType(),
                descriptor,
                config,
                subject,
                layers,
                Annotations.ofManifest(annotations),
                registry,
                json);
    }

    /**
     * Return a new manifest with the given config
     * @param subject The subject
     * @return The manifest
     */
    public Manifest withSubject(Subject subject) {
        return new Manifest(
                schemaVersion,
                mediaType,
                getTopLevelArtifactType(),
                descriptor,
                config,
                subject,
                layers,
                Annotations.ofManifest(annotations),
                registry,
                json);
    }

    /**
     * Return a new manifest with the given annotations
     * @param annotations The annotations
     * @return The manifest
     */
    public Manifest withAnnotations(Map<String, String> annotations) {
        return new Manifest(
                schemaVersion,
                mediaType,
                getTopLevelArtifactType(),
                descriptor,
                config,
                subject,
                layers,
                Annotations.ofManifest(annotations),
                registry,
                json);
    }

    /**
     * Return a new manifest with the given descriptor
     * @param descriptor The descriptor
     * @return The manifest
     */
    public Manifest withDescriptor(ManifestDescriptor descriptor) {
        return new Manifest(
                schemaVersion,
                mediaType,
                getTopLevelArtifactType(),
                descriptor,
                config,
                subject,
                layers,
                Annotations.ofManifest(annotations),
                registry,
                json);
    }

    /**
     * Return same instance but with original JSON
     * @param json The original JSON
     * @return The index
     */
    @Override
    protected Manifest withJson(String json) {
        this.json = json;
        return this;
    }

    /**
     * Create a manifest from a JSON string
     * @param json The JSON string
     * @return The manifest
     */
    public static Manifest fromJson(String json) {
        return JsonUtils.fromJson(json, Manifest.class).withJson(json);
    }

    /**
     * Create a manifest from a path
     * @param path The path
     * @return The manifest
     */
    public static Manifest fromPath(Path path) {
        return fromJson(JsonUtils.readFile(path));
    }

    private @Nullable ArtifactType getTopLevelArtifactType() {
        if (artifactType != null) {
            return ArtifactType.from(artifactType);
        }
        return null;
    }

    /**
     * Return a copy of an empty manifest
     * @return The empty manifest
     */
    public static Manifest empty() {
        ManifestDescriptor descriptor = ManifestDescriptor.of(
                Const.DEFAULT_EMPTY_MEDIA_TYPE,
                "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
                2);
        return new Manifest(
                2,
                Const.DEFAULT_MANIFEST_MEDIA_TYPE,
                null,
                descriptor,
                Config.empty(),
                null,
                List.of(),
                Annotations.empty(),
                null,
                null);
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Manifest manifest = (Manifest) o;
        return Objects.equals(toJson(), manifest.toJson());
    }

    @Override
    public int hashCode() {
        return Objects.hash(toJson());
    }

    @Override
    public String toString() {
        return toJson();
    }
}
