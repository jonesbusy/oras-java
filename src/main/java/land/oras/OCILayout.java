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

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Supplier;
import land.oras.OCI.PullOptions;
import land.oras.OCI.PushOptions;
import land.oras.exception.OrasException;
import land.oras.utils.ArchiveUtils;
import land.oras.utils.Const;
import land.oras.utils.JsonUtils;
import land.oras.utils.SupportedAlgorithm;
import org.jspecify.annotations.Nullable;

/**
 * Index from an OCI layout
 */
@OrasModel
public final class OCILayout extends OCI<LayoutRef> {

    @SuppressWarnings("all")
    private final String imageLayoutVersion = "1.0.0";

    private final ExecutorService executors = Executors.newSingleThreadExecutor();

    /**
     * Path on the file system of the OCI Layout
     */
    private Path path;

    /**
     * When non-null the layout is backed by a tar file.
     * {@code path} then points to a temporary directory that holds the extracted contents.
     * Every mutating operation re-packs that temporary directory back into this tar file.
     */
    @Nullable
    private Path tarPath;

    /**
     * Private constructor
     */
    private OCILayout() {}

    @Override
    public boolean canMount(OCI<?> other, LayoutRef sourceRef, LayoutRef targetRef) {
        if (!(other instanceof OCILayout)) {
            return false;
        }
        // They reference the same layout
        return sourceRef.getFolder().equals(targetRef.getFolder());
    }

    @Override
    public boolean mountBlob(LayoutRef sourceRef, LayoutRef targetRef) {
        String digest = sourceRef.getTag();
        if (digest == null || !SupportedAlgorithm.isSupported(digest)) {
            throw new OrasException("Digest is required to mount blob");
        }
        ensureAlgorithmPath(digest);
        Path targetBlobPath = getBlobPath(targetRef);
        if (Files.exists(targetBlobPath)) {
            LOG.info("Blob already exists: {}", digest);
            return true;
        }
        // Compute source blob path from the source layout folder
        SupportedAlgorithm algorithm = SupportedAlgorithm.fromDigest(digest);
        Path sourceBlobPath = sourceRef
                .getFolder()
                .resolve(Const.OCI_LAYOUT_BLOBS)
                .resolve(algorithm.getPrefix())
                .resolve(SupportedAlgorithm.getDigest(digest));
        if (!Files.exists(sourceBlobPath)) {
            throw new OrasException("Source blob not found at: %s".formatted(sourceBlobPath));
        }
        try {
            Files.copy(sourceBlobPath, targetBlobPath);
            LOG.info("Blob mounted from {}: {}", sourceRef.getFolder(), digest);
        } catch (IOException e) {
            throw new OrasException("Failed to mount blob", e);
        }
        packToTar();
        return true;
    }

    /**
     * Return a new builder for this oci layout
     * @return The builder
     */
    public static OCILayout.Builder builder() {
        return OCILayout.Builder.builder();
    }

    @Override
    public ExecutorService getExecutorService() {
        return executors;
    }

    @Override
    public Manifest pushArtifact(
            LayoutRef ref,
            ArtifactType artifactType,
            Annotations annotations,
            @Nullable Config config,
            PushOptions options,
            LocalPath... paths) {

        Manifest manifest = Manifest.empty().withArtifactType(artifactType);
        Map<String, String> manifestAnnotations = new HashMap<>(annotations.manifestAnnotations());
        if (!manifestAnnotations.containsKey(Const.ANNOTATION_CREATED)) {
            manifestAnnotations.put(Const.ANNOTATION_CREATED, Const.currentTimestamp());
        }
        manifest = manifest.withAnnotations(manifestAnnotations);
        if (config != null) {
            config = config.withAnnotations(annotations);
            manifest = manifest.withConfig(config);
        }

        // Push layers
        List<Layer> layers = pushLayers(ref, annotations, true, options, paths);

        // Push the config like any other blob
        Config configToPush = config != null ? config : Config.empty();
        Config pushedConfig = pushConfig(ref.withTag(configToPush.getDigest()), configToPush);

        // Add layer and config
        manifest = manifest.withLayers(layers).withConfig(pushedConfig);

        // Push the manifest
        manifest = pushManifest(ref, manifest);
        LOG.debug("Manifest pushed to: {}", ref.withTag(manifest.getDescriptor().getDigest()));
        return manifest;
    }

    @Override
    public void pullArtifact(LayoutRef ref, Path path, PullOptions options) {
        if (ref.getTag() == null) {
            throw new OrasException("Tag is required to pull artifact from layout");
        }

        // Find manifest
        Manifest manifest = getManifest(ref);

        // Find the layer with title annotation
        Layer layer = manifest.getLayers().stream()
                .filter(l -> l.getAnnotations().containsKey(Const.ANNOTATION_TITLE))
                .findFirst()
                .orElseThrow(() -> new OrasException("Layer not found with title annotation"));

        Path blobPath = getBlobPath(layer);
        verifyBlobDigest(blobPath);

        // Copy the blob to the target path
        try {
            Path targetPath = path.resolve(layer.getAnnotations().get(Const.ANNOTATION_TITLE))
                    .normalize();
            if (!targetPath.startsWith(path.normalize())) {
                throw new OrasException("Refusing to pull layer: title annotation is not withing folder '%s'"
                        .formatted(layer.getAnnotations().get(Const.ANNOTATION_TITLE)));
            }
            if (options.isOverwrite()) {
                Files.copy(blobPath, targetPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } else {
                Files.copy(blobPath, targetPath);
            }
        } catch (IOException e) {
            throw new OrasException("Failed to copy blob", e);
        }
    }

    @Override
    public Manifest pushManifest(LayoutRef layoutRef, Manifest manifest) {

        // For portability each layer should have at least one entry
        if (manifest.getLayers().isEmpty()) {
            Config config = manifest.getConfig();
            Layer configLayer = Layer.fromJson(config.toJson());
            manifest = manifest.withLayers(List.of(configLayer));
        }

        byte[] manifestData = getDescriptorData(manifest);
        String manifestDigest = digest(layoutRef, manifest);

        ManifestDescriptor manifestDescriptor = ManifestDescriptor.of(
                        Const.DEFAULT_MANIFEST_MEDIA_TYPE, manifestDigest, manifestData.length)
                .withAnnotations(manifest.getAnnotations().isEmpty() ? null : manifest.getAnnotations())
                .withArtifactType(manifest.getArtifactType().getMediaType());
        if (layoutRef.getTag() != null && !layoutRef.isValidDigest()) {
            Map<String, String> newAnnotations = new HashMap<>();
            if (manifestDescriptor.getAnnotations() != null) {
                newAnnotations.putAll(manifestDescriptor.getAnnotations());
            }
            newAnnotations.put(Const.ANNOTATION_REF, layoutRef.getTag());
            manifestDescriptor = manifestDescriptor.withAnnotations(newAnnotations);
        }
        manifest = manifest.withDescriptor(manifestDescriptor);

        Index index = Index.fromPath(getIndexPath()).withNewManifests(manifestDescriptor);

        // Write blobs
        try {
            writeManifest(manifest);
            writeOCIIndex(index);
        } catch (IOException e) {
            throw new OrasException("Failed to write manifest", e);
        }
        packToTar();
        return manifest;
    }

    @Override
    public Index pushIndex(LayoutRef layoutRef, Index index) {

        byte[] indexData = getDescriptorData(index);
        String indexDigest = digest(layoutRef, index);

        ManifestDescriptor indexDescriptor = ManifestDescriptor.of(
                        Const.DEFAULT_INDEX_MEDIA_TYPE, indexDigest, indexData.length)
                .withAnnotations(
                        index.getAnnotations() == null || index.getAnnotations().isEmpty()
                                ? null
                                : index.getAnnotations())
                .withArtifactType(index.getMediaType());
        if (layoutRef.getTag() != null && !layoutRef.isValidDigest()) {
            Map<String, String> newAnnotations = new HashMap<>();
            if (index.getAnnotations() != null) {
                newAnnotations.putAll(index.getAnnotations());
            }
            newAnnotations.put(Const.ANNOTATION_REF, layoutRef.getTag());
            indexDescriptor = indexDescriptor.withAnnotations(newAnnotations);
        }
        index = index.withDescriptor(indexDescriptor);

        Index ociIndex = Index.fromPath(getIndexPath()).withNewManifests(indexDescriptor);

        // Write blobs
        try {
            writeIndex(index);
            writeOCIIndex(ociIndex);
        } catch (IOException e) {
            throw new OrasException("Failed to write manifest", e);
        }
        packToTar();
        return index;
    }

    @Override
    public Index getIndex(LayoutRef ref) {
        Path path = getIndexPath();
        return Index.fromPath(path);
    }

    @Override
    public Manifest getManifest(LayoutRef ref) {
        String tag = ref.getTag();
        if (tag == null) {
            throw new OrasException("Tag or digest is required to find manifest");
        }
        ManifestDescriptor descriptor = findManifestDescriptor(ref);
        Path manifestPath = getBlobPath(descriptor);
        if (!Files.exists(manifestPath)) {
            throw new OrasException("Blob not found: %s".formatted(manifestPath));
        }

        return Manifest.fromPath(manifestPath).withDescriptor(descriptor);
    }

    @Override
    public byte[] getBlob(LayoutRef layoutRef) {
        try (InputStream is = fetchBlob(layoutRef)) {
            return is.readAllBytes();
        } catch (IOException e) {
            throw new OrasException("Failed to get blob", e);
        }
    }

    @Override
    public void fetchBlob(LayoutRef ref, Path path) {
        InputStream is = fetchBlob(ref);
        try {
            Files.copy(is, path);
            LOG.info("Downloaded: {}", ref.getTag());
        } catch (IOException e) {
            throw new OrasException("Failed to fetch blob", e);
        }
    }

    @Override
    public InputStream fetchBlob(LayoutRef ref) {
        Path blobPath = getBlobPath(ref);
        verifyBlobDigest(blobPath);
        try {
            return Files.newInputStream(blobPath);
        } catch (IOException e) {
            throw new OrasException("Failed to fetch blob", e);
        }
    }

    void verifyBlobDigest(Path blobPath) {
        // A missing blob is left for the caller to surface (Files.newInputStream / Files.copy).
        if (!Files.exists(blobPath)) {
            return;
        }
        Path fileName = blobPath.getFileName();
        Path parent = blobPath.getParent();
        if (fileName == null || parent == null || parent.getFileName() == null) {
            throw new OrasException("Cannot resolve expected digest for blob path: %s".formatted(blobPath));
        }
        String expectedDigest = "%s:%s".formatted(parent.getFileName(), fileName);
        if (!SupportedAlgorithm.isSupported(expectedDigest)) {
            throw new OrasException("Blob is not stored at a content-addressed path: %s".formatted(blobPath));
        }
        String actualDigest = SupportedAlgorithm.fromDigest(expectedDigest).digest(blobPath);
        if (!expectedDigest.equals(actualDigest)) {
            throw new OrasException("Blob integrity check failed for %s: expected %s but on-disk content hashes to %s"
                    .formatted(blobPath, expectedDigest, actualDigest));
        }
    }

    @Override
    public Descriptor fetchBlobDescriptor(LayoutRef ref) {
        if (ref.getTag() == null) {
            throw new OrasException("Tag or digest is required to get blob from layout");
        }
        if (SupportedAlgorithm.isSupported(ref.getTag())) {
            return Descriptor.of(ref.getTag(), size(getBlobPath(ref)));
        }
        // A manifest
        else {
            return findManifestDescriptor(ref).toDescriptor();
        }
    }

    @Override
    public Layer pushBlob(LayoutRef ref, Path blob, Map<String, String> annotations) {
        if (ref.getTag() == null) {
            throw new OrasException("Missing ref");
        }
        if (!SupportedAlgorithm.isSupported(ref.getTag())) {
            throw new OrasException("Unsupported digest: %s".formatted(ref.getTag()));
        }
        String digest = ref.getTag();
        ensureAlgorithmPath(digest);
        Path blobPath = getBlobPath(ref);
        LOG.trace("Digest: {}", digest);
        try {
            if (Files.exists(blobPath)) {
                LOG.info("Blob already exists: {}", digest);
                return Layer.fromFile(blobPath, ref.getAlgorithm()).withAnnotations(annotations);
            }
            ensureDigest(ref, blob);
            Files.copy(blob, blobPath);
            Layer layer = Layer.fromFile(blobPath, ref.getAlgorithm()).withAnnotations(annotations);
            packToTar();
            LOG.debug("Blob pushed to OCI layout: {}", digest);
            return layer;
        } catch (IOException e) {
            throw new OrasException("Failed to push blob", e);
        }
    }

    @Override
    public Layer pushBlob(LayoutRef ref, long size, Supplier<InputStream> stream, Map<String, String> annotations) {
        String digest = ref.getTag();
        if (digest == null) {
            throw new OrasException("Digest is required to push blob to layout");
        }
        boolean isDigest = SupportedAlgorithm.isSupported(digest);
        if (!isDigest) {
            throw new OrasException("Unsupported digest: %s".formatted(digest));
        }
        ensureAlgorithmPath(digest);
        try {
            Path blobPath = getBlobPath(ref);
            if (Files.exists(blobPath)) {
                LOG.info("Blob already exists: {}", digest);
                return Layer.fromFile(blobPath, ref.getAlgorithm()).withAnnotations(annotations);
            }
            try (InputStream is = stream.get()) {
                Files.copy(is, blobPath);
            }
            ensureDigest(ref, blobPath);
            Layer layer = Layer.fromFile(blobPath, ref.getAlgorithm()).withAnnotations(annotations);
            packToTar();
            return layer;
        } catch (IOException e) {
            throw new OrasException("Failed to push blob", e);
        }
    }

    @Override
    public Layer pushBlob(LayoutRef ref, byte[] data) {
        try {
            if (ref.getTag() == null) {
                throw new OrasException("Missing ref");
            }
            if (!SupportedAlgorithm.isSupported(ref.getTag())) {
                throw new OrasException("Unsupported digest: %s".formatted(ref.getTag()));
            }
            String digest = ref.getAlgorithm().digest(data);
            if (!ref.getTag().equals(digest)) {
                throw new OrasException("Digest mismatch: %s != %s".formatted(ref.getTag(), digest));
            }
            ensureAlgorithmPath(digest);
            Path blobPath = getBlobAlgorithmPath(digest).resolve(SupportedAlgorithm.getDigest(digest));
            if (Files.exists(blobPath)) {
                LOG.info("Blob already exists: {}", digest);
                return Layer.fromFile(blobPath, ref.getAlgorithm()).withAnnotations(Map.of());
            }
            Files.write(blobPath, data);
            packToTar();
            LOG.debug("Blob pushed to OCI layout: {}", digest);
            return Layer.fromFile(blobPath, ref.getAlgorithm()).withAnnotations(Map.of());
        } catch (IOException e) {
            throw new OrasException("Failed to push blob to OCI layout", e);
        }
    }

    @Override
    public Tags getTags(LayoutRef ref) {
        Index index = Index.fromPath(getIndexPath());
        String name = ref.getFolder().getFileName().toString();
        List<String> tags = index.getManifests().stream()
                .filter(m -> m.getAnnotations() != null && m.getAnnotations().containsKey(Const.ANNOTATION_REF))
                .map(m -> m.getAnnotations().get(Const.ANNOTATION_REF))
                .sorted()
                .toList();
        return new Tags(name, tags);
    }

    @Override
    public Tags getTags(LayoutRef ref, int n, @Nullable String last) {
        Tags allTags = getTags(ref);
        String name = allTags.name();
        List<String> tags = allTags.tags();
        int startIndex = 0;
        if (last != null) {
            int lastIndex = tags.indexOf(last);
            if (lastIndex == -1) {
                throw new OrasException("Last tag not found: %s".formatted(last));
            }
        }
        return new Tags(name, tags.stream().skip(startIndex).limit(n).toList());
    }

    @Override
    public Repositories getRepositories() {
        // When tar-backed, report the tar file name rather than the temp-dir name
        Path reportPath = tarPath != null ? tarPath : path;
        return new Repositories(List.of(reportPath.getFileName().toString()));
    }

    @Override
    public Referrers getReferrers(LayoutRef ref, @Nullable ArtifactType artifactType) {
        Index index = Index.fromPath(getIndexPath());
        ManifestDescriptor currentDescriptor = findManifestDescriptor(ref);
        String currentDescriptorDigest = currentDescriptor.getDigest();
        LOG.info("Looking for referrers of manifest: {}", currentDescriptorDigest);
        List<ManifestDescriptor> manifestDescriptors = new LinkedList<>();
        for (ManifestDescriptor manifestDescriptor : index.getManifests()) {
            String digest = manifestDescriptor.getDigest();
            Descriptor descriptor = probeDescriptor(ref.withDigest(digest));
            Describable describable = isIndexMediaType(descriptor.getMediaType())
                    ? getIndex(ref.withDigest(digest))
                    : getManifest(ref.withDigest(digest));
            if (describable.getSubject() != null) {
                Subject subject = describable.getSubject();
                String subjectDigest = subject.getDigest();
                if (subjectDigest.equals(currentDescriptorDigest)) {
                    LOG.info("Subject with digest {} found for manifest: {}", subjectDigest, digest);
                    manifestDescriptors.add(manifestDescriptor);
                }
            }
        }
        return Referrers.from(manifestDescriptors);
    }

    /**
     * Remove all blobs that are not referenced by any manifest reachable from the root {@code index.json}.
     * @return the list of digests (in {@code <algorithm>:<hex>} format) that were removed
     */
    public List<String> garbageCollect() {
        Set<String> referencedDigests = new HashSet<>();
        Index rootIndex = Index.fromPath(getIndexPath());
        collectReferencedDigests(rootIndex, referencedDigests);

        List<String> removed = new ArrayList<>();
        Path blobsRoot = getBlobPath();
        try {
            if (!Files.exists(blobsRoot)) {
                return removed;
            }
            // Iterate over algorithm directories (e.g. blobs/sha256/)
            try (var algoDirs = Files.newDirectoryStream(blobsRoot)) {
                for (Path algoDir : algoDirs) {
                    String algoPrefix = algoDir.getFileName().toString();
                    try (var blobFiles = Files.newDirectoryStream(algoDir)) {
                        for (Path blobFile : blobFiles) {
                            String hex = blobFile.getFileName().toString();
                            String digest = algoPrefix + ":" + hex;
                            if (!referencedDigests.contains(digest)) {
                                LOG.info("Removing unreferenced blob: {}", digest);
                                Files.delete(blobFile);
                                removed.add(digest);
                            }
                        }
                    }
                }
            }
        } catch (IOException e) {
            throw new OrasException("Failed to garbage collect OCI layout", e);
        }
        if (!removed.isEmpty()) {
            packToTar();
        }
        return removed;
    }

    /**
     * Recursively collect all blob digests that are reachable from the given index.
     *
     * @param index the index to traverse
     * @param referencedDigests the set to populate with reachable digests
     */
    private void collectReferencedDigests(Index index, Set<String> referencedDigests) {
        for (ManifestDescriptor entry : index.getManifests()) {
            String entryDigest = entry.getDigest();
            referencedDigests.add(entryDigest);
            Path blobPath = getBlobPath(entry);

            // Nested index
            if (isIndexMediaType(entry.getMediaType())) {
                Index nestedIndex = Index.fromPath(blobPath);
                collectReferencedDigests(nestedIndex, referencedDigests);
            }
            // Manifest
            else {
                Manifest manifest = Manifest.fromPath(blobPath);
                Config config = manifest.getConfig();
                if (config != null && config.getDigest() != null) {
                    referencedDigests.add(config.getDigest());
                }
                for (Layer layer : manifest.getLayers()) {
                    if (layer.getDigest() != null && layer.getData() == null) {
                        referencedDigests.add(layer.getDigest());
                    }
                }
            }
        }
    }

    private void setPath(Path path) {
        this.path = path;
    }

    private void setTarPath(@Nullable Path tarPath) {
        this.tarPath = tarPath;
    }

    /**
     * Re-pack the working directory back into the backing tar file.
     * Called after every mutating operation when {@link #tarPath} is non-null.
     */
    private void packToTar() {
        if (tarPath == null) {
            return;
        }
        try {
            // Pack without directory-name prefix so entries sit at the root of the tar,
            // matching the OCI Image Layout tar format (blobs/, index.json, oci-layout …).
            LocalPath packed = ArchiveUtils.tar(LocalPath.of(path), false);
            // Atomically replace the backing tar file
            Files.move(packed.getPath(), tarPath, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new OrasException("Failed to repack OCI layout tar: " + tarPath, e);
        }
    }

    /**
     * Return the JSON representation of the referrers
     * @return The JSON string
     */
    public String toJson() {
        return JsonUtils.toJson(this);
    }

    /**
     * Create the OCI layout file from a JSON string
     * @param json The JSON string
     * @return The OCI layout
     */
    public static OCILayout fromJson(String json) {
        return JsonUtils.fromJson(json, OCILayout.class);
    }

    /**
     * Return the image layout version
     * @return The image layout version
     */
    public String getImageLayoutVersion() {
        return imageLayoutVersion;
    }

    private void ensureMinimalLayout() {
        try {
            Files.createDirectories(getBlobPath());
            if (!Files.exists(getOciLayoutPath())) {
                Files.writeString(getOciLayoutPath(), toJson());
            }
            if (!Files.exists(getIndexPath())) {
                Files.writeString(getIndexPath(), Index.fromManifests(List.of()).toJson());
            }
        } catch (IOException e) {
            throw new OrasException("Failed to create layout", e);
        }
    }

    private void ensureAlgorithmPath(String digest) {
        Path prefixDirectory = getBlobAlgorithmPath(digest);
        try {
            if (!Files.exists(prefixDirectory)) {
                Files.createDirectory(prefixDirectory);
            }
        } catch (IOException e) {
            throw new OrasException("Failed to create algorithm path", e);
        }
    }

    @Override
    public Descriptor getDescriptor(LayoutRef ref) {
        String tag = ref.getTag();
        if (tag == null) {
            throw new OrasException("Tag or digest is required to find manifest");
        }
        ManifestDescriptor manifestDescriptor = findManifestDescriptor(ref);
        return manifestDescriptor.toDescriptor();
    }

    @Override
    public Descriptor probeDescriptor(LayoutRef ref) {
        // We should probably optimize to avoid reading the descriptor and only get its attributes (JSON path?)
        return getDescriptor(ref).withRegistry(ref.getFolder().toString()).withJson(null);
    }

    private byte[] getDescriptorData(Descriptor descriptor) {
        if (descriptor.getJson() != null) {
            return descriptor.getJson().getBytes();
        }
        return descriptor.toJson().getBytes();
    }

    private String digest(LayoutRef layoutRef, Descriptor descriptor) {
        return layoutRef
                .getAlgorithm()
                .digest(
                        descriptor.getJson() != null
                                ? descriptor.getJson().getBytes()
                                : descriptor.toJson().getBytes());
    }

    private Path getOciLayoutPath() {
        return path.resolve(Const.OCI_LAYOUT_FILE);
    }

    private Path getBlobPath() {
        return path.resolve(Const.OCI_LAYOUT_BLOBS);
    }

    private Path getBlobPath(LayoutRef ref) {
        if (ref.getTag() == null) {
            throw new OrasException("Tag is required to get blob from layout");
        }
        boolean isDigest = SupportedAlgorithm.isSupported(ref.getTag());
        if (isDigest) {
            SupportedAlgorithm algorithm = SupportedAlgorithm.fromDigest(ref.getTag());
            return getBlobPath().resolve(algorithm.getPrefix()).resolve(SupportedAlgorithm.getDigest(ref.getTag()));
        }

        Manifest manifest = getManifest(ref);

        return getBlobPath(manifest.getDescriptor());
    }

    private long size(Path path) {
        try {
            return Files.size(path);
        } catch (IOException e) {
            throw new OrasException("Failed to get size", e);
        }
    }

    private ManifestDescriptor findManifestDescriptor(LayoutRef ref) {
        String tag = ref.getTag();
        if (tag == null) {
            throw new OrasException("Tag or digest is required to find manifest");
        }
        Index index = Index.fromPath(getIndexPath());
        return index.getManifests().stream()
                .filter(m -> (m.getAnnotations() != null
                                && tag.equals(m.getAnnotations().get(Const.ANNOTATION_REF))
                        || tag.equals(m.getDigest())))
                .findFirst()
                .orElseThrow(() -> new OrasException("Tag or digest not found: %s".formatted(tag)));
    }

    private Path getBlobPath(ManifestDescriptor manifestDescriptor) {
        String digest = manifestDescriptor.getDigest();
        SupportedAlgorithm algorithm = SupportedAlgorithm.fromDigest(digest);
        return getBlobPath().resolve(algorithm.getPrefix()).resolve(SupportedAlgorithm.getDigest(digest));
    }

    private Path getBlobPath(Layer layer) {
        String digest = layer.getDigest();
        SupportedAlgorithm algorithm = SupportedAlgorithm.fromDigest(digest);
        return getBlobPath().resolve(algorithm.getPrefix()).resolve(SupportedAlgorithm.getDigest(digest));
    }

    private Path getIndexPath() {
        return path.resolve(Const.OCI_LAYOUT_INDEX);
    }

    private Path getIndexBlobPath(Index index) {
        ManifestDescriptor descriptor = index.getDescriptor();
        if (descriptor == null)
            throw new OrasException("Index descriptor is required when writing index blob with existing JSON");
        String digest = descriptor.getDigest();
        return getBlobAlgorithmPath(digest).resolve(SupportedAlgorithm.getDigest(digest));
    }

    private Path getBlobAlgorithmPath(String digest) {
        SupportedAlgorithm algorithm = SupportedAlgorithm.fromDigest(digest);
        return getBlobPath().resolve(algorithm.getPrefix());
    }

    private void writeOCIIndex(Index index) throws IOException {
        Path indexFile = getIndexPath();
        Files.writeString(indexFile, index.getJson() != null ? index.getJson() : index.toJson());
        if (index.getJson() != null) {
            Files.writeString(getIndexBlobPath(index), index.getJson());
        }
    }

    private void writeManifest(Manifest manifest) throws IOException {
        ManifestDescriptor descriptor = manifest.getDescriptor();
        Path manifestFile = getBlobPath(descriptor);
        Path manifestPrefixDirectory =
                getBlobAlgorithmPath(manifest.getDescriptor().getDigest());

        if (!Files.exists(manifestPrefixDirectory)) {
            Files.createDirectory(manifestPrefixDirectory);
        }
        // Skip if already exists
        if (Files.exists(manifestFile)) {
            LOG.debug("Manifest already exists: {}", manifestFile);
            return;
        }
        if (manifest.getJson() == null) {
            LOG.debug("Writing new manifest: {}", manifestFile);
            Files.writeString(manifestFile, manifest.toJson());
        } else {
            LOG.debug("Writing existing manifest: {}", manifestFile);
            Files.writeString(manifestFile, manifest.getJson());
        }
    }

    private void writeIndex(Index index) throws IOException {
        ManifestDescriptor descriptor = index.getDescriptor();
        Path manifestFile = getBlobPath(descriptor);
        Path manifestPrefixDirectory =
                getBlobAlgorithmPath(index.getDescriptor().getDigest());

        if (!Files.exists(manifestPrefixDirectory)) {
            Files.createDirectory(manifestPrefixDirectory);
        }
        // Skip if already exists
        if (Files.exists(manifestFile)) {
            LOG.debug("Manifest already exists: {}", manifestFile);
            return;
        }
        if (index.getJson() == null) {
            LOG.debug("Writing new manifest: {}", manifestFile);
            Files.writeString(manifestFile, index.toJson());
        } else {
            LOG.debug("Writing existing manifest: {}", manifestFile);
            Files.writeString(manifestFile, index.getJson());
        }
    }

    private void ensureDigest(LayoutRef ref, Path path) {
        if (ref.getTag() == null) {
            throw new OrasException("Missing ref");
        }
        if (!SupportedAlgorithm.isSupported(ref.getTag())) {
            throw new OrasException("Unsupported digest: %s".formatted(ref.getTag()));
        }
        SupportedAlgorithm algorithm = SupportedAlgorithm.fromDigest(ref.getTag());
        String pathDigest = algorithm.digest(path);
        if (!ref.getTag().equals(pathDigest)) {
            throw new OrasException("Digest mismatch: %s != %s".formatted(ref.getTag(), pathDigest));
        }
    }

    /**
     * Return the OCI layout from the index.json file
     * @param layoutPath The path to the layout containing the index.json file
     * @return The OCI layout
     */
    public static OCILayout fromLayoutIndex(Path layoutPath) {
        OCILayout layout = JsonUtils.fromJson(layoutPath.resolve(Const.OCI_LAYOUT_INDEX), OCILayout.class);
        layout.path = layoutPath;
        return layout;
    }

    /**
     * Return the path to the OCI layout working directory.
     * <p>When the layout is tar-backed this is the temporary directory into which the tar
     * was extracted; use {@link #getTarPath()} to obtain the path of the backing tar file.</p>
     * @return The path to the OCI layout
     */
    @JsonIgnore
    public Path getPath() {
        return path;
    }

    /**
     * Return the path to the backing tar file, or {@code null} if the layout is directory-backed.
     * @return The tar file path, or {@code null}
     */
    @JsonIgnore
    @Nullable
    public Path getTarPath() {
        return tarPath;
    }

    /**
     * Builder for the registry
     */
    public static class Builder {

        private final OCILayout layout = new OCILayout();

        /**
         * Hidden constructor
         */
        private Builder() {
            // Hide constructor
        }

        /**
         * Return a new builder with default path.
         * <p>If {@code path} ends with {@code .tar} the layout is considered to be tar-backed.
         * When the tar file already exists it is extracted to a temporary directory; that
         * temporary directory is used as the working {@code path} for all operations.
         * After every mutating operation the working directory is re-packed into the original
         * tar file.  If the tar file does not yet exist a fresh, empty layout is created in
         * the temporary directory and packed once on the first mutation.</p>
         * @param path The path (directory or {@code .tar} file)
         * @return The builder
         */
        public OCILayout.Builder defaults(Path path) {
            String name = path.getFileName().toString();
            if (name.endsWith(".tar")) {
                // Tar-backed layout: work in a temp directory
                Path workDir = ArchiveUtils.createTempDir();
                if (Files.exists(path)) {
                    // Extract existing tar into the temp working directory
                    ArchiveUtils.untar(path, workDir);
                }
                layout.setPath(workDir);
                layout.setTarPath(path);
            } else {
                layout.setPath(path);
            }
            return this;
        }

        /**
         * Return a new builder
         * @return The builder
         */
        public static OCILayout.Builder builder() {
            return new OCILayout.Builder();
        }

        /**
         * Build the registry
         * @return The registry
         */
        public OCILayout build() {
            if (!Files.isDirectory(layout.path)) {
                try {
                    Files.createDirectory(layout.path);
                } catch (IOException e) {
                    throw new OrasException("Failed to create OCI layout directory", e);
                }
            }
            layout.ensureMinimalLayout();
            layout.packToTar();
            return layout;
        }
    }
}
