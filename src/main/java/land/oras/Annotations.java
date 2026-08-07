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
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import land.oras.utils.JsonUtils;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/**
 * Record for annotations
 *
 * @param manifestAnnotations Annotations for the manifest
 * @param configAnnotations   Annotations for the config
 * @param filesAnnotations    Annotations for the layers/files
 */
@NullMarked
@OrasModel
public record Annotations(
        Map<String, String> configAnnotations,
        Map<String, String> manifestAnnotations,
        Map<String, Map<String, String>> filesAnnotations) {

    @JsonCreator
    private Annotations() {
        this(new HashMap<>(), new HashMap<>(), new HashMap<>());
    }

    /**
     * Create a new annotations record with only manifest annotations
     * @param manifestAnnotations The manifest annotations
     * @return The annotations
     */
    public static Annotations ofManifest(@Nullable Map<String, String> manifestAnnotations) {
        if (manifestAnnotations == null) {
            return empty();
        }
        return new Annotations(new HashMap<>(), manifestAnnotations, new HashMap<>());
    }

    /**
     * Create a new annotations record with only config annotations
     * @param configAnnotations The config annotations
     * @return The annotations
     */
    public static Annotations ofConfig(Map<String, String> configAnnotations) {
        return new Annotations(configAnnotations, new HashMap<>(), new HashMap<>());
    }

    /**
     * Empty annotations
     * @return The empty annotations
     */
    public static Annotations empty() {
        return new Annotations(new HashMap<>(), new HashMap<>(), new HashMap<>());
    }

    /**
     * Get the manifest annotations for a file
     * @param key The key
     * @return The annotations
     */
    public Map<String, String> getFileAnnotations(String key) {
        return this.filesAnnotations().getOrDefault(key, new HashMap<>());
    }

    /**
     * Check if there are annotations for a file
     * @param key The key
     * @return True if there are annotations, false otherwise
     */
    public boolean hasFileAnnotations(String key) {
        return this.filesAnnotations().containsKey(key);
    }

    /**
     * Create a new annotations record with the given file annotations
     * @param key The key of the file annotations
     * @param annotations The file annotations
     * @return The new annotations record
     */
    public Annotations withFileAnnotations(String key, Map<String, String> annotations) {
        Map<String, Map<String, String>> newFilesAnnotations = new HashMap<>(this.filesAnnotations());
        newFilesAnnotations.put(key, annotations);
        return new Annotations(this.configAnnotations(), this.manifestAnnotations(), newFilesAnnotations);
    }

    /**
     * Annotations file format
     */
    private static class AnnotationFile extends HashMap<String, Map<String, String>> {
        private static final String MANIFEST_KEY = "$manifest";
        private static final String CONFIG_KEY = "$config";

        /**
         * Get the manifest annotations
         *
         * @return The manifest annotations
         */
        public Map<String, String> getManifestAnnotations() {
            return this.getOrDefault(MANIFEST_KEY, new HashMap<>());
        }

        /**
         * Get the config annotations
         *
         * @return The config annotations
         */
        public Map<String, String> getConfigAnnotations() {
            return this.getOrDefault(CONFIG_KEY, new HashMap<>());
        }

        /**
         * Get the files annotations without the manifest and config annotations
         *
         * @return The files annotations
         */
        public Map<String, Map<String, String>> getFilesAnnotations() {
            return this.entrySet().stream()
                    .filter(entry -> !MANIFEST_KEY.equals(entry.getKey())
                            && !CONFIG_KEY.equals(entry.getKey())) // Filter out $manifest and $config
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        }
    }

    /**
     * Convert the annotations from a JSON string
     *
     * @param json The JSON string
     * @return The annotations
     */
    public static Annotations fromJson(String json) {
        AnnotationFile file = JsonUtils.fromJson(json, AnnotationFile.class);
        return new Annotations(file.getConfigAnnotations(), file.getManifestAnnotations(), file.getFilesAnnotations());
    }

    /**
     * Convert the annotations to a JSON string
     *
     * @return The JSON string
     */
    public String toJson() {
        AnnotationFile file = new AnnotationFile();
        file.put(AnnotationFile.MANIFEST_KEY, manifestAnnotations());
        file.put(AnnotationFile.CONFIG_KEY, configAnnotations());
        file.putAll(filesAnnotations());
        return JsonUtils.toJson(file);
    }

    @Override
    public String toString() {
        return toJson();
    }
}
