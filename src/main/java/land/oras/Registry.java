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

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Supplier;
import land.oras.auth.AuthProvider;
import land.oras.auth.AuthStoreAuthenticationProvider;
import land.oras.auth.BearerTokenProvider;
import land.oras.auth.HttpClient;
import land.oras.auth.NoAuthProvider;
import land.oras.auth.RegistriesConf;
import land.oras.auth.Scopes;
import land.oras.auth.UsernamePasswordProvider;
import land.oras.exception.OrasException;
import land.oras.utils.ArchiveUtils;
import land.oras.utils.Const;
import land.oras.utils.JsonUtils;
import land.oras.utils.SupportedAlgorithm;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/**
 * A registry is the main entry point for interacting with a container registry
 */
@NullMarked
public final class Registry extends OCI<ContainerRef> {

    private static final String HTTPS = "https";
    private static final String SCHEME_REGISTRY_PATH_FORMAT = "%s://%s/%s";

    /**
     * Max concurrent downloads and upload for blobs
     */
    private int maxConcurrentDownloads = 1;

    /**
     * The executor service for parallel operations
     */
    private ExecutorService executorService;

    /**
     * The registries configuration loaded from the environment
     */
    private RegistriesConf registriesConf;

    /**
     * The HTTP client
     */
    private HttpClient client;

    /**
     * The auth provider
     */
    private AuthProvider authProvider;

    /**
     * Insecure. Use HTTP instead of HTTPS
     */
    private boolean insecure;

    /**
     * The default registry to use. If null will use registry from the container ref
     */
    private @Nullable String registryName;

    /**
     * Skip TLS verification
     */
    private boolean skipTlsVerify;

    /**
     * Path to a PEM-encoded CA certificate or bundle for TLS verification
     */
    private @Nullable Path caFilePath;

    /**
     * PEM-encoded CA certificate or bundle content for TLS verification
     */
    private @Nullable String caContent;

    /**
     * The meter registry for metrics
     */
    private @Nullable MeterRegistry meterRegistry;

    /**
     * Constructor
     */
    private Registry() {
        this.authProvider = new NoAuthProvider();
        this.client = HttpClient.Builder.builder().build();
        this.registriesConf = RegistriesConf.newConf();
    }

    @Override
    public boolean canMount(OCI<?> other, ContainerRef sourceRef, ContainerRef targetRef) {
        if (!(other instanceof Registry otherRegistry)) {
            LOG.debug("Other OCI is not a registry, cannot mount");
            return false;
        }
        // Not the same registry
        String effectiveSourceRegistry = sourceRef.getEffectiveRegistry(this);
        String effectiveTargetRegistry = targetRef.getEffectiveRegistry(otherRegistry);
        if (!effectiveSourceRegistry.equals(effectiveTargetRegistry)) {
            LOG.debug(
                    "Cannot mount blob from registry {} to registry {}",
                    effectiveSourceRegistry,
                    effectiveTargetRegistry);
            return false;
        }
        // Not the same auth
        String authHeaderSource = authProvider.getAuthHeader(sourceRef);
        String authHeaderTarget = otherRegistry.authProvider.getAuthHeader(targetRef);
        if (!((authHeaderSource == null && authHeaderTarget == null)
                || (authHeaderSource != null
                        && authHeaderTarget != null
                        && MessageDigest.isEqual(
                                authHeaderSource.getBytes(StandardCharsets.UTF_8),
                                authHeaderTarget.getBytes(StandardCharsets.UTF_8))))) {
            LOG.debug("Authentication is different between source and target registry, cannot mount");
            return false;
        }
        LOG.debug("Blob can be mounted from registry {} to registry {}", sourceRef, targetRef);
        return true;
    }

    @Override
    public boolean mountBlob(ContainerRef sourceRef, ContainerRef targetRef) {
        String digest = sourceRef.getDigest();
        if (digest == null) {
            throw new OrasException("Digest is required to mount blob");
        }
        ContainerRef ref = targetRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return asInsecure().mountBlob(sourceRef, targetRef);
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getBlobsMountPath(this, sourceRef)));
        HttpClient.ResponseWrapper<String> response = client.post(
                uri,
                new byte[0],
                Map.of(Const.CONTENT_TYPE_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE),
                Scopes.of(ref),
                authProvider);
        logResponse(response);
        if (response.statusCode() == 201) {
            LOG.info("Blob mounted successfully from {}: {}", sourceRef.getFullRepository(), digest);
            return true;
        }
        if (response.statusCode() == 202) {
            LOG.info("Mount not supported by registry. Need to process with push {}", digest);
            return false;
        }
        handleError(response);
        return false;
    }

    /**
     * Get the registries configuration
     * @return The registries configuration
     */
    public RegistriesConf getRegistriesConf() {
        return registriesConf;
    }

    /**
     * Return a new builder for this registry
     * @return The builder
     */
    public static Builder builder() {
        return Builder.builder();
    }

    /**
     * Return this registry with insecure flag
     * @param insecure Insecure
     */
    private void setInsecure(boolean insecure) {
        this.insecure = insecure;
    }

    /**
     * Set the max concurrent downloads and uploads for blobs. Default to number of available processors
     * @param maxConcurrentDownloads Max concurrent downloads and uploads for blobs
     */
    private void setParallelism(int maxConcurrentDownloads) {
        this.maxConcurrentDownloads = maxConcurrentDownloads;
    }

    /**
     * Allow consumer to set custom executor service for parallel operations. If not set, a default one will be created with the given parallelism
     * @param executorService The executor service
     */
    private void setExecutorService(ExecutorService executorService) {
        this.executorService = executorService;
    }

    /**
     * Return if this registry is insecure
     * @return True if insecure
     */
    public boolean isInsecure() {
        return insecure;
    }

    /**
     * Return this registry with the auth provider
     * @param authProvider The auth provider
     */
    private void setAuthProvider(AuthProvider authProvider) {
        this.authProvider = authProvider;
    }

    /**
     * Return this registry with the registry URL
     * @param registry The registry URL
     */
    private void setRegistry(String registry) {
        this.registryName = registry;
    }

    /**
     * Return this registry with skip TLS verification
     * @param skipTlsVerify Skip TLS verification
     */
    private void setSkipTlsVerify(boolean skipTlsVerify) {
        this.skipTlsVerify = skipTlsVerify;
    }

    /**
     * Set the CA file path for TLS verification
     * @param caFilePath The path to a PEM-encoded CA certificate or bundle
     */
    private void setCaFilePath(Path caFilePath) {
        this.caFilePath = caFilePath;
    }

    /**
     * Set the CA certificate content for TLS verification
     * @param caContent The PEM-encoded CA certificate or bundle content
     */
    private void setCaContent(String caContent) {
        this.caContent = caContent;
    }

    /**
     * Set the meter registry for metrics
     * @param meterRegistry The meter registry
     */
    private void setMeterRegistry(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    /**
     * Build the provider
     * @return The provider
     */
    private Registry build() {
        HttpClient.Builder clientBuilder = HttpClient.Builder.builder().withSkipTlsVerify(skipTlsVerify);
        if (caFilePath != null) {
            clientBuilder = clientBuilder.withCaFile(caFilePath);
        }
        if (caContent != null) {
            clientBuilder = clientBuilder.withCaContent(caContent);
        }
        if (meterRegistry != null) {
            clientBuilder = clientBuilder.withMeterRegistry(meterRegistry);
        }
        client = clientBuilder.build();
        if (executorService == null) {
            executorService = Executors.newFixedThreadPool(maxConcurrentDownloads, r -> {
                Thread t = new Thread(r);
                t.setName("layer-transfer-worker-%d".formatted(t.getId()));
                return t;
            });
        }
        return this;
    }

    /**
     * Get the HTTP scheme depending on the insecure flag
     * @return The scheme
     */
    public String getScheme() {
        return insecure ? "http" : HTTPS;
    }

    /**
     * Return a new registry with the given registry URL but with same settings
     * @param newRegistry The new target registry URL to use in the new registry
     * @return The new registry
     */
    public Registry copy(String newRegistry) {
        return new Builder().from(this).withRegistry(newRegistry).build();
    }

    /**
     * Return a new registry with a new auth external token and same settings
     * @param authToken The new refreshed token
     * @return The new registry
     */
    public Registry withAuthToken(String authToken) {
        return new Builder().from(this).withAuthToken(authToken).build();
    }

    /**
     * Return a new registry as insecure but with same settings
     * @return The new registry
     */
    public Registry asInsecure() {
        return new Builder().from(this).withInsecure(true).build();
    }

    /**
     * Get the registry URL
     * @return The registry URL
     */
    public @Nullable String getRegistry() {
        return registryName;
    }

    @Override
    public ExecutorService getExecutorService() {
        return executorService;
    }

    @Override
    public Tags getTags(ContainerRef containerRef) {
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return asInsecure().getTags(containerRef);
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getTagsPath(this)));
        HttpClient.ResponseWrapper<String> response = client.get(
                uri, Map.of(Const.ACCEPT_HEADER, Const.DEFAULT_JSON_MEDIA_TYPE), Scopes.of(ref), authProvider);
        logResponse(response);
        handleError(response);
        return JsonUtils.fromJson(response.response(), Tags.class)
                .withLast(getLastFromLink(response).orElse(null));
    }

    @Override
    public Tags getTags(ContainerRef containerRef, int n, @Nullable String last) {
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return asInsecure().getTags(containerRef);
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getTagsPath(this, n, last)));
        HttpClient.ResponseWrapper<String> response = client.get(
                uri, Map.of(Const.ACCEPT_HEADER, Const.DEFAULT_JSON_MEDIA_TYPE), Scopes.of(ref), authProvider);
        logResponse(response);
        handleError(response);
        return JsonUtils.fromJson(response.response(), Tags.class)
                .withLast(getLastFromLink(response).orElse(null));
    }

    @Override
    public Repositories getRepositories() {
        if (registryName != null
                && getRegistriesConf().isInsecure(ContainerRef.parse(registryName).forRegistry(registryName))
                && !this.isInsecure()) {
            return asInsecure().getRepositories();
        }
        ContainerRef ref = ContainerRef.parse("default").forRegistry(this);
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getRepositoriesPath(this)));
        HttpClient.ResponseWrapper<String> response = client.get(
                uri, Map.of(Const.ACCEPT_HEADER, Const.DEFAULT_JSON_MEDIA_TYPE), Scopes.of(ref), authProvider);
        logResponse(response);
        handleError(response);
        return JsonUtils.fromJson(response.response(), Repositories.class);
    }

    @Override
    public Referrers getReferrers(ContainerRef containerRef, @Nullable ArtifactType artifactType) {
        if (containerRef.getDigest() == null) {
            throw new OrasException("Digest is required to get referrers");
        }
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return asInsecure().getReferrers(containerRef, artifactType);
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getReferrersPath(this, artifactType)));
        HttpClient.ResponseWrapper<String> response = client.get(
                uri, Map.of(Const.ACCEPT_HEADER, Const.DEFAULT_INDEX_MEDIA_TYPE), Scopes.of(ref), authProvider);
        logResponse(response);
        handleError(response);
        return JsonUtils.fromJson(response.response(), Referrers.class);
    }

    /**
     * Delete a manifest
     * @param containerRef The artifact
     */
    public void deleteManifest(ContainerRef containerRef) {
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            asInsecure().deleteManifest(containerRef);
            return;
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getManifestsPath(this)));
        HttpClient.ResponseWrapper<String> response = client.delete(uri, Map.of(), Scopes.of(ref), authProvider);
        logResponse(response);
        handleError(response);
    }

    @Override
    public Manifest pushManifest(ContainerRef containerRef, Manifest manifest) {

        Map<String, String> annotations = manifest.getAnnotations();

        // Only add created annotation if not already present or from original JSON
        if (!annotations.containsKey(Const.ANNOTATION_CREATED)
                && containerRef.getDigest() == null
                && manifest.getJson() == null) {
            Map<String, String> manifestAnnotations = new HashMap<>(annotations);
            manifestAnnotations.put(Const.ANNOTATION_CREATED, Const.currentTimestamp());
            manifest = manifest.withAnnotations(manifestAnnotations);
        }
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return asInsecure().pushManifest(ref, manifest);
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getManifestsPath(this)));
        byte[] manifestData = manifest.getJson() != null
                ? manifest.getJson().getBytes()
                : manifest.toJson().getBytes();
        LOG.debug("Manifest data to push: {}", new String(manifestData, StandardCharsets.UTF_8));
        HttpClient.ResponseWrapper<String> response = client.put(
                uri,
                manifestData,
                Map.of(Const.CONTENT_TYPE_HEADER, Const.DEFAULT_MANIFEST_MEDIA_TYPE),
                Scopes.of(ref),
                authProvider);
        logResponse(response);
        handleError(response);
        if (manifest.getSubject() != null) {
            // https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pushing-manifests-with-subject
            if (!response.headers().containsKey(Const.OCI_SUBJECT_HEADER.toLowerCase())) {
                throw new OrasException(
                        "Subject was set on manifest but not OCI subject header was returned. Legacy flow not implemented");
            }
        }
        return getManifest(ref);
    }

    @Override
    public Index pushIndex(ContainerRef containerRef, Index index) {

        Map<String, String> annotations = index.getAnnotations();

        // Only add created annotation if not already present or from original JSON
        if ((annotations == null || !annotations.containsKey(Const.ANNOTATION_CREATED))
                && containerRef.getDigest() == null
                && index.getJson() == null) {
            Map<String, String> indexAnnotations = new HashMap<>(annotations != null ? annotations : new HashMap<>());
            indexAnnotations.put(Const.ANNOTATION_CREATED, Const.currentTimestamp());
            index = index.withAnnotations(indexAnnotations);
        }

        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return asInsecure().pushIndex(containerRef, index);
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getManifestsPath(this)));
        byte[] indexData = JsonUtils.toJson(index).getBytes();
        LOG.debug("Index data to push: {}", new String(indexData, StandardCharsets.UTF_8));
        HttpClient.ResponseWrapper<String> response = client.put(
                uri,
                indexData,
                Map.of(Const.CONTENT_TYPE_HEADER, Const.DEFAULT_INDEX_MEDIA_TYPE),
                Scopes.of(ref),
                authProvider);
        logResponse(response);
        handleError(response);
        return getIndex(ref);
    }

    /**
     * Delete a blob
     * @param containerRef The container
     */
    public void deleteBlob(ContainerRef containerRef) {
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            asInsecure().deleteBlob(containerRef);
            return;
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getBlobsPath(this)));
        HttpClient.ResponseWrapper<String> response = client.delete(uri, Map.of(), Scopes.of(ref), authProvider);
        logResponse(response);
        handleError(response);
    }

    @Override
    public void pullArtifact(ContainerRef containerRef, Path path, boolean overwrite) {
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            asInsecure().pullArtifact(containerRef, path, overwrite);
            return;
        }
        // Only collect layer that are files
        String contentType = getContentType(ref);
        List<Layer> layers = collectLayers(ref, contentType, false);
        if (layers.isEmpty()
                || layers.stream().noneMatch(layer -> layer.getAnnotations().containsKey(Const.ANNOTATION_TITLE))) {
            LOG.info("Skipped pulling layers without file name in '{}'", Const.ANNOTATION_TITLE);
            return;
        }
        if (layers.stream().noneMatch(layer -> layer.getAnnotations().containsKey(Const.ANNOTATION_TITLE))) {
            LOG.info("Skipped pulling artifact without file name in '{}'", Const.ANNOTATION_TITLE);
            return;
        }
        // Pull layers in parallel
        CompletableFuture.allOf(layers.stream()
                        .filter(layer -> layer.getAnnotations().containsKey(Const.ANNOTATION_TITLE))
                        .map(layer -> CompletableFuture.runAsync(
                                () -> pullLayer(ref, layer, path, overwrite), getExecutorService()))
                        .toArray(CompletableFuture[]::new))
                .join();
    }

    @Override
    public Manifest pushArtifact(
            ContainerRef containerRef,
            ArtifactType artifactType,
            Annotations annotations,
            @Nullable Config config,
            LocalPath... paths) {
        Manifest manifest = Manifest.empty().withArtifactType(artifactType);
        Map<String, String> manifestAnnotations = new HashMap<>(annotations.manifestAnnotations());
        if (!manifestAnnotations.containsKey(Const.ANNOTATION_CREATED) && containerRef.getDigest() == null) {
            manifestAnnotations.put(Const.ANNOTATION_CREATED, Const.currentTimestamp());
        }
        manifest = manifest.withAnnotations(manifestAnnotations);
        if (config != null) {
            config = config.withAnnotations(annotations);
            manifest = manifest.withConfig(config);
        }

        // Push the config like any other blob
        Config pushedConfig = pushConfig(containerRef, config != null ? config : Config.empty());
        String resolvedRegistry = pushedConfig.getRegistry();
        Objects.requireNonNull(resolvedRegistry, "Pushed config must have a registry resolved");

        // Build the resolved ref including rewrite
        ContainerRef resolvedRef = containerRef.forRegistry(this).forRegistry(resolvedRegistry);

        // Push layers
        List<Layer> layers = pushLayers(resolvedRef, annotations, false, paths);

        // Add layer and config
        manifest = manifest.withLayers(layers).withConfig(pushedConfig);

        // Push the manifest
        manifest = pushManifest(resolvedRef, manifest);
        LOG.debug(
                "Manifest pushed to: {}",
                resolvedRef.withDigest(manifest.getDescriptor().getDigest()));
        return manifest;
    }

    @Override
    public Layer pushBlob(ContainerRef containerRef, Path blob, Map<String, String> annotations) {
        String digest = containerRef.getAlgorithm().digest(blob);
        LOG.debug("Digest: {}", digest);
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return asInsecure().pushBlob(ref, blob, annotations);
        }
        // This might not works with registries performing HEAD request
        if (hasBlob(ref.withDigest(digest))) {
            LOG.info("Blob already exists: {}", digest);
            return Layer.fromFile(blob, ref.getAlgorithm()).withAnnotations(annotations);
        }
        URI uri = URI.create(
                "%s://%s".formatted(getScheme(), ref.withDigest(digest).getBlobsUploadDigestPath(this)));
        HttpClient.ResponseWrapper<String> response = client.upload(
                "POST",
                uri,
                Map.of(Const.CONTENT_TYPE_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE),
                blob,
                Scopes.of(ref),
                authProvider);
        logResponse(response);

        // Accepted single POST push
        if (response.statusCode() == 201) {
            return Layer.fromFile(blob, ref.getAlgorithm()).withAnnotations(annotations);
        }

        // We need to push via PUT
        if (response.statusCode() == 202) {
            String location = response.headers().get(Const.LOCATION_HEADER.toLowerCase());
            // Ensure location is absolute URI
            if (!location.startsWith("http") && !location.startsWith(HTTPS)) {
                location =
                        SCHEME_REGISTRY_PATH_FORMAT.formatted(getScheme(), ref.getApiRegistry(this), location.replaceFirst("^/", ""));
            }
            LOG.debug("Location header: {}", location);

            URI uploadURI = createLocationWithDigest(location, digest);

            response = client.upload(
                    "PUT",
                    uploadURI,
                    Map.of(Const.CONTENT_TYPE_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE),
                    blob,
                    Scopes.of(ref),
                    authProvider);
            if (response.statusCode() == 201) {
                LOG.debug("Successful push: {}", response.response());
            } else {
                throw new OrasException("Failed to push layer: %s".formatted(response.response()));
            }
        }

        handleError(response);
        return Layer.fromFile(blob, containerRef.getAlgorithm()).withAnnotations(annotations);
    }

    @Override
    public Layer pushBlob(ContainerRef ref, long size, Supplier<InputStream> stream, Map<String, String> annotations) {
        String digest = ref.getDigest();
        if (digest == null) {
            throw new OrasException("Digest is required to push blob with stream");
        }
        ContainerRef containerRef = ref.forRegistry(this).checkBlocked(this);
        if (containerRef.isInsecure(this) && !this.isInsecure()) {
            return asInsecure().pushBlob(ref, size, stream, annotations);
        }
        if (hasBlob(containerRef)) {
            LOG.info("Blob already exists: {}", digest);
            return Layer.fromDigest(digest, size).withAnnotations(annotations);
        }
        // Empty post without digest
        URI uri = URI.create("%s://%s".formatted(getScheme(), containerRef.getBlobsUploadPath(this)));
        HttpClient.ResponseWrapper<String> response = client.post(
                uri,
                new byte[0],
                Map.of(Const.CONTENT_TYPE_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE),
                Scopes.of(containerRef),
                authProvider);
        logResponse(response);
        if (response.statusCode() != 202) {
            throw new OrasException("Failed to initiate blob upload: %s".formatted(response.response()));
        }
        String location = response.headers().get(Const.LOCATION_HEADER.toLowerCase());
        // Ensure location is absolute URI
        if (!location.startsWith("http") && !location.startsWith(HTTPS)) {
            location = SCHEME_REGISTRY_PATH_FORMAT.formatted(getScheme(), ref.getApiRegistry(this), location.replaceFirst("^/", ""));
        }
        LOG.debug("Location header: {}", location);

        URI uploadURI = createLocationWithDigest(location, digest);

        response = client.upload(
                uploadURI,
                size,
                Map.of(Const.CONTENT_TYPE_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE),
                stream,
                Scopes.of(containerRef),
                authProvider);
        logResponse(response);
        if (response.statusCode() == 201) {
            LOG.debug("Successful push: {}", response.response());
        } else {
            throw new OrasException("Failed to push layer: %s".formatted(response.response()));
        }
        handleError(response);
        return Layer.fromDigest(digest, size).withAnnotations(annotations);
    }

    @Override
    public Layer pushBlob(ContainerRef containerRef, byte[] data) {
        String digest = containerRef.getAlgorithm().digest(data);
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return asInsecure().pushBlob(containerRef, data);
        }
        if (ref.getDigest() != null) {
            ensureDigest(ref, data);
        }
        if (hasBlob(ref.withDigest(digest))) {
            LOG.info("Blob already exists: {}", digest);
            return Layer.fromData(ref, data);
        }
        URI uri = URI.create(
                "%s://%s".formatted(getScheme(), ref.withDigest(digest).getBlobsUploadDigestPath(this)));
        HttpClient.ResponseWrapper<String> response = client.post(
                uri,
                data,
                Map.of(Const.CONTENT_TYPE_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE),
                Scopes.of(ref),
                authProvider);
        logResponse(response);

        // Accepted single POST push
        if (response.statusCode() == 201) {
            return Layer.fromData(ref, data);
        }

        // We need to push via PUT
        if (response.statusCode() == 202) {
            String location = response.headers().get(Const.LOCATION_HEADER.toLowerCase());
            // Ensure location is absolute URI
            if (!location.startsWith("http") && !location.startsWith(HTTPS)) {
                location =
                        SCHEME_REGISTRY_PATH_FORMAT.formatted(getScheme(), ref.getApiRegistry(this), location.replaceFirst("^/", ""));
            }

            URI uploadURI = createLocationWithDigest(location, digest);

            LOG.debug("Location header: {}", location);
            response = client.put(
                    uploadURI,
                    data,
                    Map.of(Const.CONTENT_TYPE_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE),
                    Scopes.of(ref),
                    authProvider);
            if (response.statusCode() == 201) {
                LOG.debug("Successful push: {}", response.response());
            } else {
                throw new OrasException("Failed to push layer: %s".formatted(response.response()));
            }
        }

        handleError(response);
        return Layer.fromData(ref, data);
    }

    /**
     * Return if the registry contains already the blob
     * @param containerRef The container
     * @return True if the blob exists
     */
    private boolean hasBlob(ContainerRef containerRef) {
        HttpClient.ResponseWrapper<String> response = headBlob(containerRef);
        return response.statusCode() == 200;
    }

    private HttpClient.ResponseWrapper<String> headBlob(ContainerRef containerRef) {
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return asInsecure().headBlob(containerRef);
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getBlobsPath(this)));
        HttpClient.ResponseWrapper<String> response = client.head(
                uri,
                Map.of(Const.ACCEPT_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE),
                Scopes.of(containerRef),
                authProvider);
        logResponse(response);
        return response;
    }

    /**
     * Get the blob for the given digest. Not be suitable for large blobs
     * @param containerRef The container
     * @return The blob as bytes
     */
    @Override
    public byte[] getBlob(ContainerRef containerRef) {
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return asInsecure().getBlob(containerRef);
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getBlobsPath(this)));
        HttpClient.ResponseWrapper<String> response = client.get(
                uri,
                Map.of(Const.ACCEPT_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE),
                Scopes.of(ref),
                authProvider);
        logResponse(response);
        handleError(response);
        byte[] data = response.response().getBytes(StandardCharsets.UTF_8);
        validateDockerContentDigest(response, data);
        return data;
    }

    @Override
    public void fetchBlob(ContainerRef containerRef, Path path) {
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            asInsecure().fetchBlob(containerRef, path);
            return;
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getBlobsPath(this)));
        HttpClient.ResponseWrapper<Path> response = client.download(
                uri,
                Map.of(Const.ACCEPT_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE),
                path,
                Scopes.of(ref),
                authProvider);
        logResponse(response);
        handleError(response);
        validateDockerContentDigest(response, path);
    }

    @Override
    public InputStream fetchBlob(ContainerRef containerRef) {
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return asInsecure().fetchBlob(containerRef);
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getBlobsPath(this)));
        HttpClient.ResponseWrapper<InputStream> response = client.download(
                uri,
                Map.of(Const.ACCEPT_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE),
                Scopes.of(ref),
                authProvider);
        logResponse(response);
        handleError(response);
        validateDockerContentDigest(response);
        return response.response();
    }

    @Override
    public Descriptor fetchBlobDescriptor(ContainerRef containerRef) {
        HttpClient.ResponseWrapper<String> response = headBlob(containerRef);
        handleError(response);
        String size = response.headers().get(Const.CONTENT_LENGTH_HEADER.toLowerCase());
        return Descriptor.of(
                validateDockerContentDigest(response), Long.parseLong(size), Const.DEFAULT_DESCRIPTOR_MEDIA_TYPE);
    }

    @Override
    public Manifest getManifest(ContainerRef containerRef) {
        Descriptor descriptor = getDescriptor(containerRef);
        String contentType = descriptor.getMediaType();
        if (!isManifestMediaType(contentType)) {
            throw new OrasException(
                    "Expected manifest but got index. Probably a multi-platform image instead of artifact");
        }
        if (contentType.equals(Const.LEGACY_MANIFEST_MEDIA_TYPE)) {
            throw new OrasException(
                    "Schema version 1 with manifest media type '%s' is not supported. Please use schema version 2 or higher"
                            .formatted(contentType));
        }
        String json = descriptor.getJson();
        String digest = descriptor.getDigest();
        if (digest == null) {
            LOG.debug("Digest missing from header, using from reference");
            digest = containerRef.getDigest();
            if (digest == null) {
                LOG.debug("Digest missing from reference, computing from content");
                digest = containerRef.getAlgorithm().digest(json.getBytes(StandardCharsets.UTF_8));
                LOG.debug("Computed index digest: {}", digest);
            }
        }
        ManifestDescriptor manifestDescriptor = ManifestDescriptor.of(descriptor, digest);
        return Manifest.fromJson(json).withDescriptor(manifestDescriptor);
    }

    @Override
    public Index getIndex(ContainerRef containerRef) {
        Descriptor descriptor = getDescriptor(containerRef);
        String contentType = descriptor.getMediaType();
        if (!isIndexMediaType(contentType)) {
            throw new OrasException("Expected index but got %s".formatted(contentType));
        }
        String json = descriptor.getJson();
        String digest = descriptor.getDigest();
        if (digest == null) {
            LOG.debug("Digest missing from header, using from reference");
            digest = containerRef.getDigest();
            if (digest == null) {
                LOG.debug("Digest missing from reference, computing from content");
                digest = containerRef.getAlgorithm().digest(json.getBytes(StandardCharsets.UTF_8));
                LOG.debug("Computed index digest: {}", digest);
            }
        }
        ManifestDescriptor manifestDescriptor = ManifestDescriptor.of(descriptor, digest);
        return Index.fromJson(json).withDescriptor(manifestDescriptor);
    }

    @Override
    public Descriptor getDescriptor(ContainerRef containerRef) {
        HttpClient.ResponseWrapper<String> response = getManifestResponse(containerRef);
        logResponse(response);
        handleError(response);
        String size = response.headers().get(Const.CONTENT_LENGTH_HEADER.toLowerCase());
        String contentType = response.headers().get(Const.CONTENT_TYPE_HEADER.toLowerCase());
        return Descriptor.of(
                        validateDockerContentDigest(response),
                        Long.parseLong(
                                size == null
                                        ? String.valueOf(response.response().length())
                                        : size),
                        contentType)
                .withJson(response.response());
    }

    @Override
    public Descriptor probeDescriptor(ContainerRef ref) {
        ResolvedRegistry resolvedRegistry = getResolvedHeaders(ref);
        Map<String, String> headers = resolvedRegistry.headers();
        String registry = resolvedRegistry.registry();
        String digest = validateDockerContentDigest(headers);
        if (digest != null) {
            SupportedAlgorithm.fromDigest(digest);
        }
        String contentType = headers.get(Const.CONTENT_TYPE_HEADER.toLowerCase());
        return Descriptor.of(digest, 0L, contentType).withRegistry(registry);
    }

    /**
     * Return if the container ref manifests or index exists
     * @param containerRef The container
     * @return True if exists
     */
    boolean exists(ContainerRef containerRef) {
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return asInsecure().exists(containerRef);
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getManifestsPath(this)));
        HttpClient.ResponseWrapper<String> response =
                client.head(uri, Map.of(Const.ACCEPT_HEADER, Const.MANIFEST_ACCEPT_TYPE), Scopes.of(ref), authProvider);
        logResponse(response);
        return response.statusCode() == 200;
    }

    /**
     * Get a manifest response
     * @param containerRef The container
     * @return The response
     */
    private HttpClient.ResponseWrapper<String> getManifestResponse(ContainerRef containerRef) {
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return asInsecure().getManifestResponse(containerRef);
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getManifestsPath(this)));
        HttpClient.ResponseWrapper<String> response =
                client.head(uri, Map.of(Const.ACCEPT_HEADER, Const.MANIFEST_ACCEPT_TYPE), Scopes.of(ref), authProvider);
        logResponse(response);
        handleError(response);
        return client.get(uri, Map.of("Accept", Const.MANIFEST_ACCEPT_TYPE), Scopes.of(ref), authProvider);
    }

    private void validateDockerContentDigest(HttpClient.ResponseWrapper<String> response, byte[] data) {
        String digest = response.headers().get(Const.DOCKER_CONTENT_DIGEST_HEADER.toLowerCase());
        // This might happen when blob are hosted other storage.
        // We need a way to propagate the headers like scoped.
        // For now just skip validation
        if (digest == null) {
            LOG.debug("Docker-Content-Digest header not found in response. Skipping validation.");
            return;
        }
        String computedDigest = SupportedAlgorithm.fromDigest(digest).digest(data);
        ensureDigest(digest, computedDigest);
    }

    private void validateDockerContentDigest(HttpClient.ResponseWrapper<Path> response, Path path) {
        String digest = response.headers().get(Const.DOCKER_CONTENT_DIGEST_HEADER.toLowerCase());
        // This might happen when blob are hosted other storage.
        // We need a way to propagate the headers like scoped.
        // For now just skip validation
        if (digest == null) {
            LOG.debug("Docker-Content-Digest header not found in response. Skipping validation.");
            return;
        }
        String computedDigest = SupportedAlgorithm.fromDigest(digest).digest(path);
        ensureDigest(digest, computedDigest);
    }

    private @Nullable String validateDockerContentDigest(HttpClient.ResponseWrapper<?> response) {
        return validateDockerContentDigest(response.headers());
    }

    private @Nullable String validateDockerContentDigest(Map<String, String> headers) {
        String digest = headers.get(Const.DOCKER_CONTENT_DIGEST_HEADER.toLowerCase());
        // This might happen when blob are hosted other storage.
        // We need a way to propagate the headers like scoped.
        // For now just skip validation
        if (digest == null) {
            LOG.debug("Docker-Content-Digest header not found in response. Skipping validation.");
            return null;
        }
        SupportedAlgorithm.fromDigest(digest);
        return digest;
    }

    private void ensureDigest(ContainerRef ref, byte[] data) {
        if (ref.getDigest() == null) {
            throw new OrasException("Missing digest");
        }
        SupportedAlgorithm algorithm = SupportedAlgorithm.fromDigest(ref.getDigest());
        String dataDigest = algorithm.digest(data);
        ensureDigest(ref.getDigest(), dataDigest);
    }

    private void ensureDigest(String expected, @Nullable String current) {
        if (current == null) {
            throw new OrasException("Received null digest");
        }
        if (!expected.equals(current)) {
            throw new OrasException("Digest mismatch: %s != %s".formatted(expected, current));
        }
    }

    /**
     * Handle an error response
     * @param responseWrapper The response
     */
    @SuppressWarnings("unchecked")
    private void handleError(HttpClient.ResponseWrapper<?> responseWrapper) {
        if (responseWrapper.statusCode() >= 400) {
            if (responseWrapper.response() instanceof String) {
                LOG.debug("Response: {}", responseWrapper.response());
                throw new OrasException((HttpClient.ResponseWrapper<String>) responseWrapper);
            }
            throw new OrasException(new HttpClient.ResponseWrapper<>(
                    "", responseWrapper.statusCode(), Map.of(), responseWrapper.service()));
        }
    }

    /**
     * Log the response
     * @param response The response
     */
    private void logResponse(HttpClient.ResponseWrapper<?> response) {
        LOG.debug("Status Code: {}", response.statusCode());
        LOG.debug("Headers: {}", response.headers());
        LOG.debug("Service: {}", response.service());
        String contentType = response.headers().get(Const.CONTENT_TYPE_HEADER.toLowerCase());
        boolean isBinaryResponse = contentType != null && contentType.contains("octet-stream");
        // Only log non-binary responses
        if (response.response() instanceof String && !isBinaryResponse) {
            LOG.debug("Response: {}", response.response());
        } else {
            LOG.debug("Not logging binary response of content type: {}", contentType);
        }
    }

    /**
     * Get blob as stream to avoid loading into memory
     * @param containerRef The container ref
     * @return The input stream
     */
    public InputStream getBlobStream(ContainerRef containerRef) {
        // Similar to fetchBlob()
        return fetchBlob(containerRef);
    }

    /**
     * Get the content type of the container
     * @param containerRef The container
     * @return The content type
     */
    String getContentType(ContainerRef containerRef) {
        return getResolvedHeaders(containerRef).headers().get(Const.CONTENT_TYPE_HEADER.toLowerCase());
    }

    private void pullLayer(ContainerRef ref, Layer layer, Path path, boolean overwrite) {
        Objects.requireNonNull(layer.getDigest());
        try (InputStream is = fetchBlob(ref.withDigest(layer.getDigest()))) {
            // Unpack or just copy blob
            if (Boolean.parseBoolean(layer.getAnnotations().getOrDefault(Const.ANNOTATION_ORAS_UNPACK, "false"))) {
                LOG.debug("Extracting blob to: {}", path);

                // Uncompress the tar.gz archive and verify digest if present
                LocalPath tempArchive = ArchiveUtils.uncompress(is, layer.getMediaType());
                String expectedDigest = layer.getAnnotations().get(Const.ANNOTATION_ORAS_CONTENT_DIGEST);
                if (expectedDigest != null) {
                    LOG.trace("Expected digest: {}", expectedDigest);
                    String actualDigest = ref.getAlgorithm().digest(tempArchive.getPath());
                    LOG.trace("Actual digest: {}", actualDigest);
                    if (!expectedDigest.equals(actualDigest)) {
                        throw new OrasException(
                                "Digest mismatch: expected %s but got %s".formatted(expectedDigest, actualDigest));
                    }
                }

                // Extract the tar
                ArchiveUtils.untar(Files.newInputStream(tempArchive.getPath()), path);

            } else {
                Path targetPath = path.resolve(layer.getAnnotations().get(Const.ANNOTATION_TITLE))
                        .normalize();
                if (!targetPath.startsWith(path.normalize())) {
                    throw new OrasException(
                            "Refusing to pull layer: path is not withing folder in title annotation '%s'"
                                    .formatted(layer.getAnnotations().get(Const.ANNOTATION_TITLE)));
                }
                if (Files.exists(targetPath) && !overwrite) {
                    LOG.info("File already exists: {}", targetPath);
                    return;
                }
                LOG.debug("Copying blob to: {}", targetPath);
                Files.copy(is, targetPath, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new OrasException("Failed to pull artifact", e);
        }
    }

    /**
     * Append digest to location header returned from upload post
     * @param location The location header from upload post
     * @return URI with location + digest query parameter
     */
    URI createLocationWithDigest(String location, String digest) {
        URI uploadURI;
        try {
            uploadURI = new URI(location);

            // sometimes CI can add a query to this, so making sure we're using the right query param symbol
            if (uploadURI.getQuery() == null) {
                uploadURI = new URI(uploadURI + "?digest=%s".formatted(digest));
            } else {
                uploadURI = new URI(uploadURI + "&digest=%s".formatted(digest));
            }
        } catch (URISyntaxException e) {
            throw new OrasException("Failed parse location header: %s".formatted(location));
        }

        return uploadURI;
    }

    /**
     * Execute a head request on the manifest URL and return the headers
     * @param containerRef The container ref
     * @return The resolved registry and headers
     */
    ResolvedRegistry getResolvedHeaders(ContainerRef containerRef) {
        if (containerRef.isInsecure(this) && !this.isInsecure()) {
            return asInsecure().getResolvedHeaders(containerRef);
        }
        ContainerRef ref = containerRef.forRegistry(this);
        URI uri = URI.create(
                "%s://%s".formatted(getScheme(), ref.forRegistry(this).getManifestsPath(this)));
        HttpClient.ResponseWrapper<String> response =
                client.head(uri, Map.of(Const.ACCEPT_HEADER, Const.MANIFEST_ACCEPT_TYPE), Scopes.of(ref), authProvider);
        logResponse(response);
        handleError(response);
        return new ResolvedRegistry(ref.getRegistry(), response.headers());
    }

    private Optional<String> getLastFromLink(HttpClient.ResponseWrapper<String> response) {
        String linkHeader = response.headers().get(Const.LINK_HEADER.toLowerCase());
        if (linkHeader == null) {
            return Optional.empty();
        }

        int start = linkHeader.indexOf('<');
        int end = linkHeader.indexOf('>', start + 1);
        if (start == -1 || end == -1) {
            return Optional.empty();
        }

        String uri = linkHeader.substring(start + 1, end);
        int q = uri.indexOf('?');
        if (q == -1) {
            return Optional.empty();
        }

        String query = uri.substring(q + 1);
        for (String param : query.split("&")) {
            int eq = param.indexOf('=');
            if (eq > 0 && "last".equals(param.substring(0, eq))) {
                return Optional.of(param.substring(eq + 1));
            }
        }

        return Optional.empty();
    }

    /**
     * Holds a resolved registry to avoid resolution on every request (specially like blob)
     * @param registry The registry URL
     * @param headers The headers to use for the registry
     */
    private record ResolvedRegistry(String registry, Map<String, String> headers) {}

    /**
     * Builder for the registry
     */
    public static class Builder {

        private final Registry registry = new Registry();

        /**
         * Hidden constructor
         */
        private Builder() {
            // Hide constructor
        }

        /**
         * Return a new builder with default authentication using existing host auth
         * @return The builder
         */
        public Builder defaults() {
            registry.setAuthProvider(new AuthStoreAuthenticationProvider());
            return this;
        }

        /**
         * Return a new builder with default authentication using existing host auth and registry url
         * @param registry The registry URL (ex: localhost:5000)
         * @return The builder
         */
        public Builder defaults(String registry) {
            return defaults().withRegistry(registry);
        }

        /**
         * Return a new builder with the same configuration as the given registry
         * @param registry The registry to copy the configuration from
         * @return The builder
         */
        public Builder from(Registry registry) {
            this.registry.setAuthProvider(registry.authProvider);
            this.registry.setInsecure(registry.insecure);
            this.registry.setRegistry(registry.registryName);
            this.registry.setSkipTlsVerify(registry.skipTlsVerify);
            this.registry.setExecutorService(registry.executorService);
            this.registry.setParallelism(registry.maxConcurrentDownloads);
            if (registry.meterRegistry != null) {
                this.registry.setMeterRegistry(registry.meterRegistry);
            }
            return this;
        }

        /**
         * Set username and password authentication
         * @param username The username
         * @param password The password
         * @return The builder
         */
        public Builder defaults(String username, String password) {
            registry.setAuthProvider(new UsernamePasswordProvider(username, password));
            return this;
        }

        /**
         * Set username and password authentication
         * @param registry The registry URL (ex: localhost:5000)
         * @param username The username
         * @param password The password
         * @return The builder
         */
        public Builder defaults(String registry, String username, String password) {
            return defaults(username, password).withRegistry(registry);
        }

        /**
         * Set insecure communication and no authentification
         * @return The builder
         */
        public Builder insecure() {
            registry.setInsecure(true);
            registry.setSkipTlsVerify(true);
            registry.setAuthProvider(new NoAuthProvider());
            return this;
        }

        /**
         * Set insecure communication and no authentification
         * @param registry The registry (ex: localhost:5000)
         * @return The builder
         */
        public Builder insecure(String registry) {
            return insecure().withRegistry(registry);
        }

        /**
         * Return a new insecure builder with username and password authentication
         * @param registry The registry (ex: localhost:5000)
         * @param username The username
         * @param password The password
         * @return The builder
         */
        public Builder insecure(String registry, String username, String password) {
            return insecure().defaults(registry, username, password);
        }

        /**
         * Set the registry URL
         * @param registry The registry URL
         * @return The builder
         */
        public Builder withRegistry(String registry) {
            this.registry.setRegistry(registry);
            return this;
        }

        /**
         * Set the auth provider
         * @param authProvider The auth provider
         * @return The builder
         */
        public Builder withAuthProvider(AuthProvider authProvider) {
            registry.setAuthProvider(authProvider);
            return this;
        }

        /**
         * Use given auth token for the registry.
         * Useful when the auth token is obtained by other mean (like a token exchange).
         * Caller are responsible to handle token expiration if any
         * @param authToken The auth token
         * @return The builder
         */
        public Builder withAuthToken(String authToken) {
            registry.setAuthProvider(new BearerTokenProvider(authToken));
            return this;
        }

        /**
         * Set the maximum number of concurrent downloads when pulling an artifact with multiple layers. Default is 4.
         * @param parallelism The maximum number of parallel uploads/download
         * @return The builder
         */
        public Builder withParallelism(int parallelism) {
            registry.setParallelism(parallelism);
            return this;
        }

        /**
         * Set the executor service to use for parallel uploads/downloads. By default it uses a parallelism level given by withParallelism() and a fixed thread pool.
         * Only uses for layers upload/download, not for manifest or index upload/download.
         * @param executorService The executor service
         * @return The builder
         */
        public Builder withExecutorService(ExecutorService executorService) {
            registry.setExecutorService(executorService);
            return this;
        }

        /**
         * Set the insecure flag
         * @param insecure Insecure
         * @return The builder
         */
        public Builder withInsecure(boolean insecure) {
            registry.setInsecure(insecure);
            return this;
        }

        /**
         * Set the skip TLS verify flag
         * @param skipTlsVerify Skip TLS verify
         * @return The builder
         */
        public Builder withSkipTlsVerify(boolean skipTlsVerify) {
            registry.setSkipTlsVerify(skipTlsVerify);
            return this;
        }

        /**
         * Set the CA file for TLS verification
         * @param caFilePath The path to a PEM-encoded CA certificate or bundle
         * @return The builder
         */
        public Builder withCaFile(Path caFilePath) {
            registry.setCaFilePath(caFilePath);
            return this;
        }

        /**
         * Set the CA file for TLS verification
         * @param caFilePath The path to a PEM-encoded CA certificate or bundle
         * @return The builder
         */
        public Builder withCaFile(String caFilePath) {
            return withCaFile(Path.of(caFilePath));
        }

        /**
         * Set the CA certificates from PEM-encoded content
         * @param caContent The PEM-encoded CA certificate or bundle content
         * @return The builder
         */
        public Builder withCaContent(String caContent) {
            registry.setCaContent(caContent);
            return this;
        }

        /**
         * Set the meter registry for metrics. Following Micrometer best practices for libraries,
         * a {@link SimpleMeterRegistry} is used by default when no registry is provided.
         * @param meterRegistry The meter registry
         * @return The builder
         */
        public Builder withMeterRegistry(MeterRegistry meterRegistry) {
            registry.setMeterRegistry(meterRegistry);
            return this;
        }

        /**
         * Return a new builder
         * @return The builder
         */
        public static Builder builder() {
            return new Builder();
        }

        /**
         * Build the registry
         * @return The registry
         */
        public Registry build() {
            return registry.build();
        }
    }
}
