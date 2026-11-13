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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import land.oras.exception.OrasException;
import land.oras.utils.ArchiveUtils;
import land.oras.utils.Const;
import land.oras.utils.SupportedAlgorithm;
import land.oras.utils.SupportedCompression;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract class for OCI operation on remote registry or layout
 * Commons methods for OCI operations
 * @param <T> The reference type
 */
public abstract sealed class OCI<T extends Ref<@NonNull T>> permits Registry, OCILayout {

    /**
     * The logger
     */
    protected static final Logger LOG = LoggerFactory.getLogger(OCI.class);

    /**
     * How long an idle transfer worker thread is kept before being released
     */
    static final long TRANSFER_WORKER_KEEP_ALIVE_SECONDS = 30;

    /**
     * Create the default executor for layer transfers. It behaves like a fixed thread pool, but workers are daemon
     * threads released once idle, so an unused instance holds no thread and needs no explicit shutdown.
     * @param parallelism The maximum number of concurrent transfers
     * @param threadName The worker thread name prefix
     * @return The executor service
     */
    static ExecutorService newTransferExecutor(int parallelism, String threadName) {
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
                parallelism,
                parallelism,
                TRANSFER_WORKER_KEEP_ALIVE_SECONDS,
                TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(),
                r -> {
                    Thread t = new Thread(r);
                    t.setName("%s-%d".formatted(threadName, t.getId()));
                    t.setDaemon(true);
                    return t;
                });
        executor.allowCoreThreadTimeOut(true);
        return executor;
    }

    /**
     * Options controlling the behavior of {@link OCI#pushArtifact} operations.
     */
    @OrasModel
    public static final class PushOptions {

        /** Default chunk size: 5 MiB. */
        public static final long DEFAULT_CHUNK_SIZE = 5L * 1024 * 1024;

        private final boolean chunkedEnabled;
        private final long chunkSize;

        private PushOptions(boolean chunkedEnabled, long chunkSize) {
            this.chunkedEnabled = chunkedEnabled;
            this.chunkSize = chunkSize;
        }

        /**
         * Default options: single-request upload, no chunking.
         * @return The default push options
         */
        public static PushOptions defaults() {
            return new PushOptions(false, DEFAULT_CHUNK_SIZE);
        }

        /**
         * Options that enable chunked (PATCH-based) upload with the default chunk size.
         * @return Push options with chunked upload enabled
         */
        public static PushOptions chunked() {
            return new PushOptions(true, DEFAULT_CHUNK_SIZE);
        }

        /**
         * Options that enable chunked (PATCH-based) upload with a custom chunk size.
         * @param chunkSize Maximum number of bytes per chunk. Must be greater than 0.
         * @return Push options with chunked upload enabled
         */
        public static PushOptions chunked(long chunkSize) {
            return new PushOptions(true, chunkSize);
        }

        /**
         * Return whether chunked upload is enabled.
         * @return {@code true} if chunked upload should be used
         */
        public boolean isChunked() {
            return chunkedEnabled;
        }

        /**
         * Return the maximum number of bytes per chunk.
         * @return The chunk size in bytes
         */
        public long chunkSize() {
            return chunkSize;
        }
    }

    /**
     * Options controlling the behavior of {@link OCI#pullArtifact} operations.
     */
    @OrasModel
    public static final class PullOptions {

        private final boolean overwriteEnabled;

        private PullOptions(boolean overwriteEnabled) {
            this.overwriteEnabled = overwriteEnabled;
        }

        /**
         * Default options: do not overwrite existing files.
         * @return The default pull options
         */
        public static PullOptions defaults() {
            return new PullOptions(false);
        }

        /**
         * Options that allow overwriting existing files when pulling.
         * @return Pull options with overwrite enabled
         */
        public static PullOptions overwrite() {
            return new PullOptions(true);
        }

        /**
         * Return whether existing files should be overwritten.
         * @return {@code true} if existing files should be overwritten
         */
        public boolean isOverwrite() {
            return overwriteEnabled;
        }
    }

    /**
     * Default constructor
     */
    protected OCI() {}

    /**
     * Push an artifact
     * @param ref The ref
     * @param paths The paths
     * @return The manifest
     */
    public Manifest pushArtifact(T ref, LocalPath... paths) {
        return pushArtifact(ref, ArtifactType.unknown(), Annotations.empty(), Config.empty(), paths);
    }

    /**
     * Push an artifact
     * @param ref The ref
     * @param artifactType The artifact type
     * @param paths The paths
     * @return The manifest
     */
    public Manifest pushArtifact(T ref, ArtifactType artifactType, LocalPath... paths) {
        return pushArtifact(ref, artifactType, Annotations.empty(), Config.empty(), paths);
    }

    /**
     * Upload an ORAS artifact
     * @param ref The ref
     * @param artifactType The artifact type
     * @param annotations The annotations
     * @param paths The paths
     * @return The manifest
     */
    public Manifest pushArtifact(T ref, ArtifactType artifactType, Annotations annotations, LocalPath... paths) {
        return pushArtifact(ref, artifactType, annotations, Config.empty(), paths);
    }

    /**
     * Push an artifact with explicit push options
     * @param ref The ref
     * @param options The push options
     * @param paths The paths
     * @return The manifest
     */
    public Manifest pushArtifact(T ref, PushOptions options, LocalPath... paths) {
        return pushArtifact(ref, ArtifactType.unknown(), Annotations.empty(), Config.empty(), options, paths);
    }

    /**
     * Push an artifact with explicit push options
     * @param ref The ref
     * @param artifactType The artifact type
     * @param options The push options
     * @param paths The paths
     * @return The manifest
     */
    public Manifest pushArtifact(T ref, ArtifactType artifactType, PushOptions options, LocalPath... paths) {
        return pushArtifact(ref, artifactType, Annotations.empty(), Config.empty(), options, paths);
    }

    /**
     * Push an artifact with explicit push options
     * @param ref The ref
     * @param artifactType The artifact type
     * @param annotations The annotations
     * @param options The push options
     * @param paths The paths
     * @return The manifest
     */
    public Manifest pushArtifact(
            T ref, ArtifactType artifactType, Annotations annotations, PushOptions options, LocalPath... paths) {
        return pushArtifact(ref, artifactType, annotations, Config.empty(), options, paths);
    }

    /**
     * Push a blob from file
     * @param ref The ref
     * @param blob The blob
     * @return The layer
     */
    public Layer pushBlob(T ref, Path blob) {
        return pushBlob(ref, blob, Map.of());
    }

    /**
     * Return whether this OCI instance supports mounting blobs from the given source OCI instance.
     * @param other The source OCI instance to check compatibility with
     * @param sourceRef The source reference
     * @param targetRef The target reference
     * @return {@code true} if mounting from {@code other} is supported
     */
    public abstract boolean canMount(OCI<?> other, T sourceRef, T targetRef);

    /**
     * Mount a blob from another repository in the same OCI target.
     * @param targetRef The target reference containing the digest to mount
     * @param sourceRef The source reference containing the source repository or layout path
     * @return {@code true} if the blob is successfully mounted, {@code false} otherwise (not supported by registry)
     */
    public abstract boolean mountBlob(T sourceRef, T targetRef);

    /**
     * Push a blob stream. Creates a temporary file to store the blob and push the file. The temporary file will be deleted after pushing
     * @param ref The ref
     * @param input The input stream
     * @return The layer
     */
    public Layer pushBlob(T ref, InputStream input) {
        try {
            Path tempFile = Files.createTempFile("oras", "layer");
            Files.copy(input, tempFile, StandardCopyOption.REPLACE_EXISTING);
            return pushBlob(ref, tempFile);
        } catch (IOException e) {
            throw new OrasException("Failed to push blob", e);
        }
    }

    /**
     * Collect layers from the ref
     * @param ref The ref
     * @param contentType The content type
     * @param includeAll Include all layers or only the ones with title annotation
     * @return The layers
     */
    protected List<Layer> collectLayers(T ref, String contentType, boolean includeAll) {
        List<Layer> layers = new LinkedList<>();
        if (isManifestMediaType(contentType)) {
            return getManifest(ref).getLayers();
        }
        Index index = getIndex(ref);
        for (ManifestDescriptor manifestDescriptor : index.getManifests()) {
            String manifestContentType = manifestDescriptor.getMediaType();
            // We just skip unknown media type descriptor
            if (!isManifestMediaType(manifestContentType) && !isIndexMediaType(manifestContentType)) {
                LOG.info(
                        "Unrecognized content type {}, skipping descriptor {}",
                        manifestContentType,
                        manifestDescriptor.getDigest());
                continue;
            }
            // Collect layer for each manifest
            List<Layer> manifestLayers =
                    getManifest(ref.withDigest(manifestDescriptor.getDigest())).getLayers();
            for (Layer manifestLayer : manifestLayers) {
                if (manifestLayer.getAnnotations().isEmpty()
                        || !manifestLayer.getAnnotations().containsKey(Const.ANNOTATION_TITLE)) {
                    if (includeAll) {
                        LOG.debug("Including layer without title annotation: {}", manifestLayer.getDigest());
                        layers.add(manifestLayer);
                    }
                    LOG.debug("Skipping layer without title annotation: {}", manifestLayer.getDigest());
                    continue;
                }
                layers.add(manifestLayer);
            }
        }
        return layers;
    }

    /**
     * Push layers to the target using default push options
     * @param ref The ref
     * @param annotations The annotations for layers (selected by title annotation).
     * @param withDigest Push with digest
     * @param paths The paths to the files
     * @return The layers
     */
    protected final List<Layer> pushLayers(T ref, Annotations annotations, boolean withDigest, LocalPath... paths) {
        return pushLayers(ref, annotations, withDigest, PushOptions.defaults(), paths);
    }

    /**
     * Push layers to the target
     * @param ref The ref
     * @param annotations The annotations for layers (selected by title annotation).
     * @param withDigest Push with digest
     * @param options The push options
     * @param paths The paths to the files
     * @return The layers
     */
    protected final List<Layer> pushLayers(
            T ref, Annotations annotations, boolean withDigest, PushOptions options, LocalPath... paths) {
        try {
            return Arrays.stream(paths)
                    .map(p -> CompletableFuture.supplyAsync(
                            () -> pushLayer(ref, annotations, withDigest, p, options), getExecutorService()))
                    .map(CompletableFuture::join)
                    .toList();
        } catch (CompletionException e) {
            throw new OrasException("Failed to push layers", e.getCause());
        }
    }

    /**
     * Return if a media type is an index media type
     * @param mediaType The media type
     * @return True if it is a index media type
     */
    protected boolean isIndexMediaType(String mediaType) {
        return mediaType.equals(Const.DEFAULT_INDEX_MEDIA_TYPE) || mediaType.equals(Const.DOCKER_INDEX_MEDIA_TYPE);
    }

    /**
     * Return if a media type is a manifest media type
     * @param mediaType The media type
     * @return True if it is a manifest media type
     */
    protected boolean isManifestMediaType(String mediaType) {
        return mediaType.equals(Const.DEFAULT_MANIFEST_MEDIA_TYPE)
                || mediaType.equals(Const.DOCKER_MANIFEST_MEDIA_TYPE)
                || mediaType.equals(Const.LEGACY_MANIFEST_MEDIA_TYPE);
    }

    /**
     * Push config
     * @param ref The ref
     * @param config The config
     * @return The config
     */
    public final Config pushConfig(T ref, Config config) {
        Layer layer = pushBlob(ref, config.getDataBytes());
        LOG.debug("Config pushed: {}", layer.getDigest());
        return config.withRegistry(layer.getRegistry());
    }

    /**
     * Pull config data or just return the data from config if set inline
     * @param ref The ref
     * @param config The config
     * @return The input stream
     */
    public final InputStream pullConfig(T ref, Config config) {
        if (config.getData() != null) {
            return new ByteArrayInputStream(config.getDataBytes());
        }
        String digest = config.getDigest();
        return fetchBlob(ref.withDigest(digest));
    }

    /**
     * Attach an artifact
     * @param ref The ref
     * @param artifactType The artifact type
     * @param paths The paths
     * @return The manifest
     */
    public final Manifest attachArtifact(T ref, ArtifactType artifactType, LocalPath... paths) {
        return attachArtifact(ref, artifactType, Annotations.empty(), paths);
    }

    /**
     * Get the tags for a ref
     * @param ref The ref
     * @return The tags
     */
    public abstract Tags getTags(T ref);

    /**
     * Get the executor service for concurrent operations. This is used for concurrent pushing and pulling of layers.
     * @return The executor service
     */
    public abstract ExecutorService getExecutorService();

    /**
     * Get the tags for a ref
     * @param ref The ref
     * @param n The number of tags to return. If n is less than or equal to 0, return all tags
     * @param last The last tag index, to iterate. If null, start from the beginning
     * @return The tags
     */
    public abstract Tags getTags(T ref, int n, @Nullable String last);

    /**
     * Get the tags for a ref
     * @return The repositories
     */
    public abstract Repositories getRepositories();

    /**
     * Push an artifact using default push options
     * @param ref The container
     * @param artifactType The artifact type. Can be null
     * @param annotations The annotations
     * @param config The config
     * @param paths The paths
     * @return The manifest
     */
    public Manifest pushArtifact(
            T ref, ArtifactType artifactType, Annotations annotations, @Nullable Config config, LocalPath... paths) {
        return pushArtifact(ref, artifactType, annotations, config, PushOptions.defaults(), paths);
    }

    /**
     * Push an artifact
     * @param ref The container
     * @param artifactType The artifact type. Can be null
     * @param annotations The annotations
     * @param config The config
     * @param options The push options
     * @param paths The paths
     * @return The manifest
     */
    public abstract Manifest pushArtifact(
            T ref,
            ArtifactType artifactType,
            Annotations annotations,
            @Nullable Config config,
            PushOptions options,
            LocalPath... paths);

    /**
     * Pull an artifact using the given options
     * @param ref The reference of the artifact
     * @param path The path to save the artifact
     * @param options The pull options
     */
    public abstract void pullArtifact(T ref, Path path, PullOptions options);

    /**
     * Pull an artifact
     * @param ref The reference of the artifact
     * @param path The path to save the artifact
     * @param overwrite Overwrite the artifact if it exists
     */
    public void pullArtifact(T ref, Path path, boolean overwrite) {
        pullArtifact(ref, path, overwrite ? PullOptions.overwrite() : PullOptions.defaults());
    }

    /**
     * Push a manifest
     * @param ref The ref
     * @param manifest The manifest
     * @return The location
     */
    public abstract Manifest pushManifest(T ref, Manifest manifest);

    /**
     * Push an index
     * @param ref The ref
     * @param index The index
     * @return The index
     */
    public abstract Index pushIndex(T ref, Index index);

    /**
     * Retrieve an index
     * @param ref The ref
     * @return The index
     */
    public abstract Index getIndex(T ref);

    /**
     * Retrieve a manifest
     * @param ref The ref
     * @return The manifest
     */
    public abstract Manifest getManifest(T ref);

    /**
     * Retrieve a descriptor
     * @param ref The ref
     * @return The descriptor
     */
    public abstract Descriptor getDescriptor(T ref);

    /**
     * Probe a descriptor. Typically used to get digest, size and media type without the content
     * @param ref The ref
     * @return The descriptor
     */
    public abstract Descriptor probeDescriptor(T ref);

    /**
     * Get the blob for the given digest. Not be suitable for large blobs
     * @param ref The ref
     * @return The blob as bytes
     */
    public abstract byte[] getBlob(T ref);

    /**
     * Fetch blob and save it to file
     * @param ref The ref
     * @param path The path to save the blob
     */
    public abstract void fetchBlob(T ref, Path path);

    /**
     * Fetch blob and return it as input stream
     * @param ref The ref
     * @return The input stream
     */
    public abstract InputStream fetchBlob(T ref);

    /**
     * Fetch blob and return it's descriptor
     * @param ref The ref
     * @return The descriptor
     */
    public abstract Descriptor fetchBlobDescriptor(T ref);

    /**
     * Push a blob from file
     * @param ref The container
     * @param blob The blob
     * @param annotations The annotations
     * @return The layer
     */
    public abstract Layer pushBlob(T ref, Path blob, Map<String, String> annotations);

    /**
     * Push a blob from input stream with known digest and size
     * @param ref The container ref with digest
     * @param size The size of the blob
     * @param stream The input stream of the blob
     * @param annotations The annotations
     * @return The layer
     */
    public abstract Layer pushBlob(T ref, long size, Supplier<InputStream> stream, Map<String, String> annotations);

    /**
     * Push the blob for the given layer
     * @param ref The container ref
     * @param data The data
     * @return The layer
     */
    public abstract Layer pushBlob(T ref, byte[] data);

    /**
     * Get the referrers of a container
     * @param ref The ref
     * @param artifactType The optional artifact type
     * @return The referrers
     */
    public abstract Referrers getReferrers(T ref, @Nullable ArtifactType artifactType);

    /**
     * Attach file to an existing manifest
     * @param ref The ref
     * @param artifactType The artifact type
     * @param annotations The annotations
     * @param paths The paths
     * @return The manifest of the new artifact
     */
    public Manifest attachArtifact(T ref, ArtifactType artifactType, Annotations annotations, LocalPath... paths) {

        // Push layers
        List<Layer> layers = pushLayers(ref, annotations, true, paths);

        // Get the subject from the descriptor
        Descriptor descriptor = getDescriptor(ref);
        Subject subject = descriptor.toSubject();

        // Add created annotation if not present since we push with digest
        Map<String, String> manifestAnnotations = annotations.manifestAnnotations();
        if (!manifestAnnotations.containsKey(Const.ANNOTATION_CREATED)) {
            manifestAnnotations.put(Const.ANNOTATION_CREATED, Const.currentTimestamp());
        }

        // assemble manifest
        Manifest manifest = Manifest.empty()
                .withArtifactType(artifactType)
                .withAnnotations(manifestAnnotations)
                .withLayers(layers)
                .withSubject(subject);
        return pushManifest(
                ref.withDigest(
                        SupportedAlgorithm.getDefault().digest(manifest.toJson().getBytes(StandardCharsets.UTF_8))),
                manifest);
    }

    protected Layer pushLayer(T ref, Annotations annotations, boolean withDigest, LocalPath path) {
        return pushLayer(ref, annotations, withDigest, path, PushOptions.defaults());
    }

    protected Layer pushLayer(T ref, Annotations annotations, boolean withDigest, LocalPath path, PushOptions options) {
        try {
            // Create tar.gz archive for directory
            if (Files.isDirectory(path.getPath())) {
                SupportedCompression compression = SupportedCompression.fromMediaType(path.getMediaType());

                // If source need to be packed first
                boolean autoUnpack = compression.isAutoUnpack();
                LocalPath tempSource = autoUnpack ? ArchiveUtils.tar(path) : path;
                LocalPath tempArchive = ArchiveUtils.compress(tempSource, path.getMediaType());

                if (withDigest) {
                    ref = ref.withDigest(ref.getAlgorithm().digest(tempArchive.getPath()));
                }

                String title = path.getPath().isAbsolute()
                        ? path.getPath().getFileName().toString()
                        : path.getPath().toString();

                // We store the filename, based on directory name if we don't auto unpack
                if (!autoUnpack) {
                    title = "%s.%s".formatted(title, compression.getFileExtension());
                }
                LOG.debug("Uploading directory as archive with title: {}", title);

                Map<String, String> layerAnnotations = annotations.hasFileAnnotations(title)
                        ? annotations.getFileAnnotations(title)
                        : new LinkedHashMap<>(Map.of(Const.ANNOTATION_TITLE, title));

                // Add oras digest/unpack
                // For example zip can be packed application/zip but never unpacked by the runtime
                // This is convenience method to pack zip layer as directories
                if (compression.isAutoUnpack()) {
                    layerAnnotations.put(
                            Const.ANNOTATION_ORAS_CONTENT_DIGEST,
                            ref.getAlgorithm().digest(tempSource.getPath()));
                    layerAnnotations.put(Const.ANNOTATION_ORAS_UNPACK, "true");
                } else {
                    layerAnnotations.put(Const.ANNOTATION_ORAS_UNPACK, "false");
                }

                Layer layer = doPushBlob(ref, tempArchive.getPath(), options)
                        .withMediaType(path.getMediaType())
                        .withAnnotations(layerAnnotations);
                LOG.info("Uploaded directory: {}", layer.getDigest());
                Files.delete(tempArchive.getPath());
                return layer;
            } else {
                if (withDigest) {
                    ref = ref.withDigest(ref.getAlgorithm().digest(path.getPath()));
                }
                String title = path.getPath().getFileName().toString();
                Map<String, String> layerAnnotations = annotations.hasFileAnnotations(title)
                        ? annotations.getFileAnnotations(title)
                        : Map.of(Const.ANNOTATION_TITLE, title);

                Layer layer = doPushBlob(ref, path.getPath(), options)
                        .withMediaType(path.getMediaType())
                        .withAnnotations(layerAnnotations);
                LOG.info("Uploaded: {}", layer.getDigest());
                return layer;
            }
        } catch (IOException e) {
            throw new OrasException("Failed to push artifact", e);
        }
    }

    /**
     * Push a blob from a file path, respecting the given push options.
     * Subclasses may override to support chunked upload.
     * @param ref The ref
     * @param blob The blob file
     * @param options The push options
     * @return The layer
     */
    protected Layer doPushBlob(T ref, Path blob, PushOptions options) {
        try (InputStream is = Files.newInputStream(blob)) {
            return pushBlob(ref, is);
        } catch (IOException e) {
            throw new OrasException("Failed to push blob", e);
        }
    }
}
