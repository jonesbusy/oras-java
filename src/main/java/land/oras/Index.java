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
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiPredicate;
import land.oras.exception.OrasException;
import land.oras.utils.Const;
import land.oras.utils.JsonUtils;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Index from an OCI layout
 */
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
    Const.JSON_PROPERTY_MANIFESTS,
})
@JsonInclude(JsonInclude.Include.NON_NULL) // We need to serialize empty list of manifests
public final class Index extends Descriptor implements Describable {

    private final int schemaVersion;
    private final List<ManifestDescriptor> manifests;
    private final Subject subject;

    /**
     * The index descriptor
     */
    private final ManifestDescriptor descriptor;

    @JsonCreator
    @SuppressWarnings("unused")
    private Index(
            @JsonProperty(Const.JSON_PROPERTY_SCHEMA_VERSION) int schemaVersion,
            @JsonProperty(Const.JSON_PROPERTY_MEDIA_TYPE) String mediaType,
            @JsonProperty(Const.JSON_PROPERTY_ARTIFACT_TYPE) String artifactType,
            @JsonProperty(Const.JSON_PROPERTY_MANIFESTS) List<ManifestDescriptor> manifests,
            @JsonProperty(Const.JSON_PROPERTY_ANNOTATIONS) Map<String, String> annotations,
            @JsonProperty(Const.JSON_PROPERTY_SUBJECT) Subject subject) {
        super(
                null,
                null,
                mediaType,
                annotations != null && !annotations.isEmpty() ? Map.copyOf(annotations) : null,
                artifactType,
                null,
                null);
        this.schemaVersion = schemaVersion;
        this.manifests = manifests;
        this.descriptor = null;
        this.subject = subject;
    }

    private Index(
            int schemaVersion,
            String mediaType,
            ArtifactType artifactType,
            List<ManifestDescriptor> manifests,
            Map<String, String> annotations,
            Subject subject,
            ManifestDescriptor descriptor,
            String registry,
            String json) {
        super(
                null,
                null,
                mediaType,
                annotations,
                artifactType != null ? artifactType.getMediaType() : null,
                registry,
                json);
        this.schemaVersion = schemaVersion;
        this.descriptor = descriptor;
        this.subject = subject;
        this.manifests = manifests;
    }

    private Index(
            int schemaVersion,
            String mediaType,
            String artifactType,
            List<ManifestDescriptor> manifests,
            Map<String, String> annotations,
            Subject subject,
            ManifestDescriptor descriptor,
            String registry,
            String json) {
        super(null, null, mediaType, annotations, artifactType, registry, json);
        this.schemaVersion = schemaVersion;
        this.descriptor = descriptor;
        this.subject = subject;
        this.manifests = manifests;
    }

    /**
     * Get the schema version
     * @return The schema version
     */
    public int getSchemaVersion() {
        return schemaVersion;
    }

    /**
     * Get the list of manifests
     * @return The list of manifests
     */
    public List<ManifestDescriptor> getManifests() {
        return manifests;
    }

    /**
     * Filter the manifests by platform
     * @param platform The platform
     * @return The list of manifests that match the platform
     */
    public List<ManifestDescriptor> filter(Platform platform) {
        return filter(platform, Platform::matches);
    }

    /**
     * Filter the manifests by platform with a custom comparator
     * @param platform The platform
     * @param comparator The comparator to compare the platform of the manifest descriptor and the given platform. The first parameter is the platform of the manifest descriptor, and the second parameter is the given platform. The comparator should return true if the manifest descriptor matches the given platform, and false otherwise.
     * @return The list of manifests that match the platform
     */
    public List<ManifestDescriptor> filter(Platform platform, BiPredicate<Platform, Platform> comparator) {
        return getManifests().stream()
                .filter(manifestDescriptor -> comparator.test(manifestDescriptor.getPlatform(), platform))
                .toList();
    }

    /**
     * Get the list of manifests that have unspecified platform
     * @return The list of manifests that have unspecified platform
     */
    public List<ManifestDescriptor> unspecifiedPlatforms() {
        return getManifests().stream()
                .filter(manifestDescriptor -> Platform.unspecified(manifestDescriptor.getPlatform()))
                .toList();
    }

    /**
     * Find a unique manifest by platform. If there are multiple manifests that match the platform, return null
     * @param platform The platform
     * @return The manifest that matches the platform, or null if there are multiple matches or no matches
     */
    public @Nullable ManifestDescriptor findUnique(Platform platform) {
        return filter(platform).stream().findFirst().orElse(null);
    }

    @Override
    @JsonIgnore
    public @NonNull ArtifactType getArtifactType() {
        if (artifactType != null) {
            return ArtifactType.from(artifactType);
        }
        return ArtifactType.unknown();
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

    /**
     * Return a new index with the given manifest descriptor removed from the index
     * @param descriptor The manifest descriptor to remove
     * @return The index with the manifest descriptor removed
     */
    public Index withRemovedDescriptor(ManifestDescriptor descriptor) {
        List<ManifestDescriptor> newManifests = new LinkedList<>(manifests);
        boolean found = false;
        for (ManifestDescriptor d : manifests) {
            if (d.getDigest().equals(descriptor.getDigest())) {
                found = true;
                newManifests.remove(d);
            }
        }
        if (!found) {
            throw new OrasException("Cannot remove manifest descriptor with digest " + descriptor.getDigest()
                    + " because it does not exist in the index");
        }
        return new Index(
                schemaVersion,
                mediaType,
                artifactType,
                newManifests,
                annotations,
                subject,
                this.descriptor,
                registry,
                json);
    }

    /**
     * Return a new index with new manifest added to index
     * @param manifest The manifest
     * @return The index
     */
    public Index withNewManifests(ManifestDescriptor manifest) {
        List<ManifestDescriptor> newManifests = new LinkedList<>();
        for (ManifestDescriptor existingDescriptor : manifests) {

            // Ignore same digest
            if (existingDescriptor.getDigest().equals(manifest.getDigest())) {
                continue;
            }

            // Move previous ref
            if (existingDescriptor.getAnnotations() != null
                    && existingDescriptor.getAnnotations().containsKey(Const.ANNOTATION_REF)
                    && manifest.getAnnotations() != null
                    && manifest.getAnnotations().containsKey(Const.ANNOTATION_REF)
                    && existingDescriptor
                            .getAnnotations()
                            .get(Const.ANNOTATION_REF)
                            .equals(manifest.getAnnotations().get(Const.ANNOTATION_REF))) {
                Map<String, String> newAnnotations = new LinkedHashMap<>(existingDescriptor.getAnnotations());
                newAnnotations.remove(Const.ANNOTATION_REF);
                if (newAnnotations.isEmpty()) {
                    newAnnotations = null;
                }
                newManifests.add(ManifestDescriptor.fromJson(
                        existingDescriptor.withAnnotations(newAnnotations).toJson()));
                continue;
            }
            newManifests.add(ManifestDescriptor.fromJson(existingDescriptor.toJson()));
        }
        newManifests.add(manifest);
        return new Index(
                schemaVersion, mediaType, artifactType, newManifests, annotations, subject, descriptor, registry, json);
    }

    @Override
    @JsonIgnore
    public ManifestDescriptor getDescriptor() {
        return descriptor;
    }

    /**
     * Get the annotations
     * @return The annotations
     */
    @Override
    public @Nullable Map<String, String> getAnnotations() {
        if (annotations != null && !annotations.isEmpty()) {
            return annotations;
        }
        return null;
    }

    /**
     * Return a new index with the given annotations
     * @param annotations The annotations
     * @return The index
     */
    public Index withAnnotations(Map<String, String> annotations) {
        return new Index(
                schemaVersion, mediaType, artifactType, manifests, annotations, subject, descriptor, registry, json);
    }

    /**
     * Return a new index with the given artifact type
     * @param artifactType The artifact type
     * @return The index
     */
    public Index withArtifactType(ArtifactType artifactType) {
        return new Index(
                schemaVersion, mediaType, artifactType, manifests, annotations, subject, descriptor, registry, json);
    }

    /**
     * Return a new index with the given descriptor
     * @param descriptor The descriptor
     * @return The manifest
     */
    public Index withDescriptor(ManifestDescriptor descriptor) {
        return new Index(
                schemaVersion, mediaType, artifactType, manifests, annotations, subject, descriptor, registry, json);
    }

    /**
     * Return same instance but with original JSON
     * @param json The original JSON
     * @return The index
     */
    @Override
    protected Index withJson(String json) {
        this.json = json;
        return this;
    }

    @Override
    public Subject getSubject() {
        return subject;
    }

    /**
     * Return a new index with the given subject
     * @param subject The subject
     * @return The index
     */
    public Index withSubject(Subject subject) {
        return new Index(
                schemaVersion, mediaType, artifactType, manifests, annotations, subject, descriptor, registry, json);
    }

    /**
     * Create an index from a JSON string
     * @param json The JSON string
     * @return The index
     */
    public static Index fromJson(String json) {
        return JsonUtils.fromJson(json, Index.class).withJson(json);
    }

    /**
     * Create an index from a path
     * @param path The path
     * @return The index
     */
    public static Index fromPath(Path path) {
        return JsonUtils.fromJson(path, Index.class);
    }

    /**
     * Create an index from a list of manifests
     * @param descriptors The list of manifests
     * @return The index
     */
    public static Index fromManifests(List<ManifestDescriptor> descriptors) {
        return new Index(
                2, Const.DEFAULT_INDEX_MEDIA_TYPE, (ArtifactType) null, descriptors, null, null, null, null, null);
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Index index = (Index) o;
        return Objects.equals(toJson(), index.toJson());
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
