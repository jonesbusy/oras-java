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
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.BiFunction;
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
import land.oras.policy.ContainersPolicy;
import land.oras.policy.PolicyContext;
import land.oras.policy.Transport;
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
    private @Nullable String registry;

    /**
     * Skip TLS verification
     */
    private boolean skipTlsVerify;

    /**
     * Whether the transport (HTTP vs HTTPS) has been explicitly decided for this registry and must
     * not be re-resolved from registries.conf. Set when a registry is derived to contact a specific
     * mirror so that a registry-level {@code insecure} entry for the mirror host cannot silently
     * downgrade an explicitly-secure per-mirror connection to plaintext HTTP.
     */
    private boolean transportLocked;

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
     * Maximum number of attempts for retryable requests (1 = no retry)
     */
    private int maxRetries = 3;

    /**
     * Initial delay between retries in milliseconds
     */
    private long retryDelayMs = 500L;

    /**
     * Upper bound on retry delay in milliseconds
     */
    private long maxRetryDelayMs = 30_000L;

    /**
     * The containers policy for trust verification
     */
    private ContainersPolicy containersPolicy;

    /**
     * Constructor
     */
    private Registry() {
        this.authProvider = new NoAuthProvider();
        this.client = HttpClient.Builder.builder().build();
        this.registriesConf = RegistriesConf.newConf();
        this.containersPolicy = ContainersPolicy.newPolicy(); // Load from standard locations or accept-all
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
        if (!(authHeaderSource == authHeaderTarget
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
            return copyForNewTransport(ref.getRegistry(), true).mountBlob(sourceRef, ref);
        }
        if (!ref.isInsecure(this) && this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), false).mountBlob(sourceRef, ref);
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
     * Return whether the transport has been explicitly decided and must not be re-resolved from
     * registries.conf. Used for mirror connections so a registry-level insecure entry cannot
     * downgrade an explicitly-secure mirror.
     * @return True if the transport is locked
     */
    boolean isTransportLocked() {
        return transportLocked;
    }

    /**
     * Return the containers policy used for trust verification.
     * @return the containers policy
     */
    public ContainersPolicy getContainersPolicy() {
        return containersPolicy;
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
        this.registry = registry;
    }

    /**
     * Return this registry with skip TLS verification
     * @param skipTlsVerify Skip TLS verification
     */
    private void setSkipTlsVerify(boolean skipTlsVerify) {
        this.skipTlsVerify = skipTlsVerify;
    }

    /**
     * Lock or unlock the transport decision for this registry
     * @param transportLocked Whether the transport is explicitly decided
     */
    private void setTransportLocked(boolean transportLocked) {
        this.transportLocked = transportLocked;
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

    private void setMaxRetries(int maxRetries) {
        this.maxRetries = maxRetries;
    }

    private void setRetryDelayMs(long retryDelayMs) {
        this.retryDelayMs = retryDelayMs;
    }

    private void setMaxRetryDelayMs(long maxRetryDelayMs) {
        this.maxRetryDelayMs = maxRetryDelayMs;
    }

    private void setContainersPolicy(ContainersPolicy containersPolicy) {
        this.containersPolicy = containersPolicy;
    }

    /**
     * Build the provider
     * @return The provider
     */
    private Registry build() {
        HttpClient.Builder clientBuilder = HttpClient.Builder.builder()
                .withSkipTlsVerify(skipTlsVerify)
                .withMaxRetries(maxRetries)
                .withRetryDelay(retryDelayMs)
                .withMaxRetryDelay(maxRetryDelayMs);
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
        return insecure ? "http" : "https";
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
    Registry asInsecure() {
        LOG.debug("Creating a new registry as insecure (HTTP)");
        return new Builder().from(this).withInsecure(true).build();
    }

    /**
     * Return a new registry as secure (HTTPS, TLS verified) but with same settings
     * @return The new registry
     */
    Registry asSecure() {
        LOG.debug("Creating a new registry as secure (HTTPS, TLS verified)");
        return new Builder()
                .from(this)
                .withInsecure(false)
                .withSkipTlsVerify(false)
                .build();
    }

    /**
     * Return a new registry scoped to a specific host with new transport (HTTP/HTTPS), with the same settings as this registry
     * except transport and credentials, which are taken from the mirror configuration:
     * @param mirrorHost The mirror host[:port] to contact
     * @param insecureMirror Whether the mirror connection is plaintext HTTP
     * @return The new registry scoped to the mirror
     */
    private Registry copyForNewTransport(String mirrorHost, boolean insecureMirror) {

        // Never send credentials over a plaintext connection to a mirror.
        AuthProvider mirrorAuthProvider = null;
        if (insecureMirror) {
            LOG.warn(
                    "Using no authentication due to downgrade to insecure mirror from '{}' to '{}'",
                    registry,
                    mirrorHost);
            mirrorAuthProvider = new NoAuthProvider();
        }

        // Same host as the parent registry: the credentials already belong to this host.
        if (mirrorHost.equalsIgnoreCase(registry)) {
            LOG.debug("Reusing same auth provider for mirror");
            mirrorAuthProvider = this.authProvider;
        }

        // Safe to reuse
        if (authProvider instanceof AuthStoreAuthenticationProvider) {
            LOG.debug("Using auth store authentication provider for mirror");
            mirrorAuthProvider = authProvider;
        }

        if (mirrorAuthProvider == null) {
            LOG.debug("Using no authentication provider for mirror");
            mirrorAuthProvider = new NoAuthProvider();
        }

        return new Builder()
                .from(this)
                .withRegistry(mirrorHost)
                .withInsecure(insecureMirror)
                .withSkipTlsVerify(insecureMirror && skipTlsVerify)
                .withTransportLocked(true)
                .withAuthProvider(mirrorAuthProvider)
                .build();
    }

    /**
     * Get the registry URL
     * @return The registry URL
     */
    public @Nullable String getRegistry() {
        return registry;
    }

    @Override
    public ExecutorService getExecutorService() {
        return executorService;
    }

    @Override
    public Tags getTags(ContainerRef containerRef) {
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), true).getTags(ref);
        }
        if (!ref.isInsecure(this) && this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), false).getTags(ref);
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
            return copyForNewTransport(ref.getRegistry(), true).getTags(ref);
        }
        if (!ref.isInsecure(this) && this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), false).getTags(ref);
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
        if (registry != null
                && getRegistriesConf()
                        .isInsecure(this, ContainerRef.parse(registry).forRegistry(registry))
                && !this.isInsecure()) {
            return asInsecure().getRepositories();
        }
        if (registry != null
                && !getRegistriesConf()
                        .isInsecure(this, ContainerRef.parse(registry).forRegistry(registry))
                && this.isInsecure()) {
            return asSecure().getRepositories();
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
            return copyForNewTransport(ref.getRegistry(), true).getReferrers(ref, artifactType);
        }
        if (!ref.isInsecure(this) && this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), false).getReferrers(ref, artifactType);
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
        if (!ref.isInsecure(this) && this.isInsecure()) {
            asSecure().deleteManifest(containerRef);
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
            return copyForNewTransport(ref.getRegistry(), true).pushManifest(ref, manifest);
        }
        if (!ref.isInsecure(this) && this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), false).pushManifest(ref, manifest);
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
            return copyForNewTransport(ref.getRegistry(), true).pushIndex(ref, index);
        }
        if (!ref.isInsecure(this) && this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), false).pushIndex(ref, index);
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
        if (!ref.isInsecure(this) && this.isInsecure()) {
            asSecure().deleteBlob(containerRef);
            return;
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getBlobsPath(this)));
        HttpClient.ResponseWrapper<String> response = client.delete(uri, Map.of(), Scopes.of(ref), authProvider);
        logResponse(response);
        handleError(response);
    }

    @Override
    public void pullArtifact(ContainerRef containerRef, Path path, PullOptions options) {
        withMirrorFallback(containerRef, (reg, ref) -> {
            reg.pullArtifactDirect(ref, path, options);
            return null;
        });
    }

    private void pullArtifactDirect(ContainerRef containerRef, Path path, PullOptions options) {
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            asInsecure().pullArtifactDirect(containerRef, path, options);
            return;
        }
        if (!ref.isInsecure(this) && this.isInsecure()) {
            asSecure().pullArtifactDirect(containerRef, path, options);
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
                                () -> pullLayer(ref, layer, path, options.isOverwrite()), getExecutorService()))
                        .toArray(CompletableFuture[]::new))
                .join();
    }

    @Override
    public Manifest pushArtifact(
            ContainerRef containerRef,
            ArtifactType artifactType,
            Annotations annotations,
            @Nullable Config config,
            PushOptions options,
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
        List<Layer> layers = pushLayers(resolvedRef, annotations, false, options, paths);

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
    protected Layer doPushBlob(ContainerRef ref, Path blob, PushOptions options) {
        if (options.isChunked()) {
            return pushBlobChunked(ref, blob, options.chunkSize());
        }
        return super.doPushBlob(ref, blob, options);
    }

    @Override
    public Layer pushBlob(ContainerRef containerRef, Path blob, Map<String, String> annotations) {
        String digest = containerRef.getAlgorithm().digest(blob);
        LOG.debug("Digest: {}", digest);
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), true).pushBlob(ref, blob, annotations);
        }
        if (!ref.isInsecure(this) && this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), false).pushBlob(ref, blob, annotations);
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
            if (!location.startsWith("http") && !location.startsWith("https")) {
                location =
                        "%s://%s/%s".formatted(getScheme(), ref.getApiRegistry(this), location.replaceFirst("^/", ""));
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
            return copyForNewTransport(ref.getRegistry(), true).pushBlob(ref, size, stream, annotations);
        }
        if (!containerRef.isInsecure(this) && this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), false).pushBlob(ref, size, stream, annotations);
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
        if (!location.startsWith("http") && !location.startsWith("https")) {
            location = "%s://%s/%s".formatted(getScheme(), ref.getApiRegistry(this), location.replaceFirst("^/", ""));
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
            return copyForNewTransport(ref.getRegistry(), true).pushBlob(ref, data);
        }
        if (!ref.isInsecure(this) && this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), false).pushBlob(ref, data);
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
            if (!location.startsWith("http") && !location.startsWith("https")) {
                location =
                        "%s://%s/%s".formatted(getScheme(), ref.getApiRegistry(this), location.replaceFirst("^/", ""));
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
     * Push a blob using chunked upload
     *
     * @param containerRef The container reference
     * @param blob The blob file to upload
     * @param chunkSize Maximum number of bytes per chunk. Must be &gt; 0.
     * @return The {@link Layer} descriptor for the uploaded blob.
     * @throws OrasException if the upload fails at any stage.
     */
    public Layer pushBlobChunked(ContainerRef containerRef, Path blob, long chunkSize) {
        if (chunkSize <= 0) {
            throw new OrasException("chunkSize must be greater than 0");
        }
        String digest = containerRef.getAlgorithm().digest(blob);
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), true).pushBlobChunked(ref, blob, chunkSize);
        }
        if (!ref.isInsecure(this) && this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), false).pushBlobChunked(ref, blob, chunkSize);
        }
        if (hasBlob(ref.withDigest(digest))) {
            LOG.info("Blob already exists: {}", digest);
            return Layer.fromFile(blob, ref.getAlgorithm());
        }
        String location = initiateChunkedUpload(ref);
        try (InputStream is = Files.newInputStream(blob)) {
            long totalSize = Files.size(blob);
            location = uploadChunks(ref, is, totalSize, chunkSize, location);
        } catch (IOException e) {
            throw new OrasException("Failed to read blob for chunked upload: %s".formatted(blob), e);
        }
        finalizeChunkedUpload(ref, location, digest);
        return Layer.fromFile(blob, ref.getAlgorithm());
    }

    /**
     * Push a blob using chunked upload
     *
     * @param containerRef The container reference
     * @param stream Input stream
     * @param totalSize Total size of the stream
     * @param chunkSize Maximum number of bytes per chunk. Must be &gt; 0.
     * @return The {@link Layer} descriptor for the uploaded blob.
     * @throws OrasException if the upload fails at any stage.
     */
    public Layer pushBlobChunked(ContainerRef containerRef, InputStream stream, long totalSize, long chunkSize) {
        String digest = containerRef.getDigest();
        if (digest == null) {
            throw new OrasException("Digest is required to push blob with chunked stream upload");
        }
        if (chunkSize <= 0) {
            throw new OrasException("chunkSize must be greater than 0");
        }
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), true).pushBlobChunked(ref, stream, totalSize, chunkSize);
        }
        if (!ref.isInsecure(this) && this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), false).pushBlobChunked(ref, stream, totalSize, chunkSize);
        }
        if (hasBlob(ref)) {
            LOG.info("Blob already exists: {}", digest);
            return Layer.fromDigest(digest, totalSize);
        }
        String location = initiateChunkedUpload(ref);
        location = uploadChunks(ref, stream, totalSize, chunkSize, location);
        finalizeChunkedUpload(ref, location, digest);
        return Layer.fromDigest(digest, totalSize);
    }

    private String initiateChunkedUpload(ContainerRef ref) {
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getBlobsUploadPath(this)));
        HttpClient.ResponseWrapper<String> response = client.post(
                uri,
                new byte[0],
                Map.of(Const.CONTENT_TYPE_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE),
                Scopes.of(ref),
                authProvider);
        logResponse(response);
        if (response.statusCode() != 202) {
            throw new OrasException(
                    "Failed to initiate chunked blob upload: status %d".formatted(response.statusCode()));
        }
        String location = response.headers().get(Const.LOCATION_HEADER.toLowerCase());
        if (!location.startsWith("http://") && !location.startsWith("https://")) {
            location = "%s://%s/%s".formatted(getScheme(), ref.getApiRegistry(this), location.replaceFirst("^/", ""));
        }
        LOG.debug("Chunked upload session location: {}", location);
        return location;
    }

    private String uploadChunks(ContainerRef ref, InputStream stream, long totalSize, long chunkSize, String location) {
        long offset = 0;
        byte[] buffer = new byte[(int) Math.min(chunkSize, Integer.MAX_VALUE)];
        try {
            while (offset < totalSize) {
                long remaining = totalSize - offset;
                int toRead = (int) Math.min(chunkSize, remaining);
                int read = stream.readNBytes(buffer, 0, toRead);
                if (read == 0) {
                    break;
                }
                long rangeEnd = offset + read - 1;
                String contentRange = "%d-%d".formatted(offset, rangeEnd);
                final byte[] chunk = java.util.Arrays.copyOf(buffer, read);
                URI patchUri = URI.create(location);
                HttpClient.ResponseWrapper<String> patchResponse = client.patch(
                        patchUri,
                        read,
                        Map.of(
                                Const.CONTENT_TYPE_HEADER,
                                Const.APPLICATION_OCTET_STREAM_HEADER_VALUE,
                                Const.CONTENT_RANGE_HEADER,
                                contentRange),
                        () -> new java.io.ByteArrayInputStream(chunk),
                        Scopes.of(ref),
                        authProvider);
                logResponse(patchResponse);
                if (patchResponse.statusCode() != 202) {
                    throw new OrasException("Chunked upload PATCH failed for range %s: status %d"
                            .formatted(contentRange, patchResponse.statusCode()));
                }
                // The registry MAY return a new location after each PATCH
                String newLocation = patchResponse.headers().get(Const.LOCATION_HEADER.toLowerCase());
                if (newLocation != null && !newLocation.isBlank()) {
                    if (!newLocation.startsWith("http://") && !newLocation.startsWith("https://")) {
                        newLocation = "%s://%s/%s"
                                .formatted(getScheme(), ref.getApiRegistry(this), newLocation.replaceFirst("^/", ""));
                    }
                    location = newLocation;
                    LOG.debug("Chunked upload location updated: {}", location);
                }
                offset += read;
                LOG.debug("Uploaded chunk {}-{} ({} bytes)", offset - read, rangeEnd, read);
            }
        } catch (IOException e) {
            throw new OrasException("Failed during chunked blob upload", e);
        }
        return location;
    }

    private void finalizeChunkedUpload(ContainerRef ref, String location, String digest) {
        URI putUri = createLocationWithDigest(location, digest);
        HttpClient.ResponseWrapper<String> putResponse = client.put(
                putUri,
                new byte[0],
                Map.of(Const.CONTENT_TYPE_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE),
                Scopes.of(ref),
                authProvider);
        logResponse(putResponse);
        if (putResponse.statusCode() != 201) {
            throw new OrasException(
                    "Failed to finalize chunked blob upload: status %d".formatted(putResponse.statusCode()));
        }
        LOG.debug("Chunked upload finalized successfully for digest: {}", digest);
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
            return copyForNewTransport(ref.getRegistry(), true).headBlob(ref);
        }
        if (!ref.isInsecure(this) && this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), false).headBlob(ref);
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
        return withMirrorFallback(containerRef, (reg, ref) -> reg.getBlobDirect(ref));
    }

    private byte[] getBlobDirect(ContainerRef containerRef) {
        try (InputStream is = fetchBlobDirect(containerRef)) {
            return is.readAllBytes();
        } catch (IOException e) {
            throw new OrasException("Failed to get blob", e);
        }
    }

    @Override
    public void fetchBlob(ContainerRef containerRef, Path path) {
        withMirrorFallback(containerRef, (reg, ref) -> {
            reg.fetchBlobDirect(ref, path);
            return null;
        });
    }

    private void fetchBlobDirect(ContainerRef containerRef, Path path) {
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            asInsecure().fetchBlobDirect(containerRef, path);
            return;
        }
        if (!ref.isInsecure(this) && this.isInsecure()) {
            asSecure().fetchBlobDirect(containerRef, path);
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
        verifyBlobDigest(ref, path, response.headers());
    }

    @Override
    public InputStream fetchBlob(ContainerRef containerRef) {
        return withMirrorFallback(containerRef, (reg, ref) -> reg.fetchBlobDirect(ref));
    }

    private InputStream fetchBlobDirect(ContainerRef containerRef) {
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), true).fetchBlobDirect(ref);
        }
        if (!ref.isInsecure(this) && this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), false).fetchBlobDirect(ref);
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getBlobsPath(this)));
        HttpClient.ResponseWrapper<InputStream> response = client.download(
                uri,
                Map.of(Const.ACCEPT_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE),
                Scopes.of(ref),
                authProvider);
        logResponse(response);
        handleError(response);
        // Verify the content digest incrementally
        List<String> expected = expectedBlobDigests(ref, response.headers());
        if (expected.isEmpty()) {
            return response.response();
        }
        return new DigestVerifyingInputStream(response.response(), expected);
    }

    /**
     * Collect the digests a downloaded blob must match: the caller-pinned digest (when it is a supported
     * digest and not a plain tag) and the server-advertised {@code Docker-Content-Digest} header (when
     * present). Duplicates are collapsed so the content is hashed once per distinct algorithm.
     */
    private static List<String> expectedBlobDigests(ContainerRef ref, Map<String, String> headers) {
        List<String> expected = new ArrayList<>(2);
        String pinned = ref.getDigest();
        if (pinned != null && SupportedAlgorithm.isSupported(pinned)) {
            expected.add(pinned);
        }
        String header = headers.get(Const.DOCKER_CONTENT_DIGEST_HEADER.toLowerCase());
        if (header != null && !expected.contains(header)) {
            expected.add(header);
        }
        return expected;
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
        Manifest manifest = Manifest.fromJson(json).withDescriptor(manifestDescriptor);

        verifyContainersPolicy(containerRef, digest);

        return manifest;
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
        verifyContainersPolicy(containerRef, digest);
        return Index.fromJson(json).withDescriptor(manifestDescriptor);
    }

    @Override
    public Descriptor getDescriptor(ContainerRef containerRef) {
        HttpClient.ResponseWrapper<String> response = getManifestResponse(containerRef);
        logResponse(response);
        handleError(response);
        String json = response.response();
        // When the reference is pinned to a digest, verify the returned manifest/index bytes against it
        verifyPinnedDigest(containerRef, json.getBytes(StandardCharsets.UTF_8));
        String size = response.headers().get(Const.CONTENT_LENGTH_HEADER.toLowerCase());
        String contentType = response.headers().get(Const.CONTENT_TYPE_HEADER.toLowerCase());
        return Descriptor.of(
                        validateDockerContentDigest(response),
                        Long.parseLong(size == null ? String.valueOf(json.length()) : size),
                        contentType)
                .withJson(json);
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
            return copyForNewTransport(ref.getRegistry(), true).exists(ref);
        }
        if (!ref.isInsecure(this) && this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), false).exists(ref);
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getManifestsPath(this)));
        HttpClient.ResponseWrapper<String> response =
                client.head(uri, Map.of(Const.ACCEPT_HEADER, Const.MANIFEST_ACCEPT_TYPE), Scopes.of(ref), authProvider);
        logResponse(response);
        return response.statusCode() == 200;
    }

    /**
     * Execute an operation with mirror fallback. Mirrors are tried in order; if all fail the
     * operation is retried against the original registry.
     * @param containerRef The original container reference used to look up mirrors
     * @param operation A function (registry, ref) → result; called for each candidate
     * @return The result from the first successful invocation
     */
    private <T> T withMirrorFallback(ContainerRef containerRef, BiFunction<Registry, ContainerRef, T> operation) {
        List<RegistriesConf.MirrorConfig> mirrors = registriesConf.getApplicableMirrors(containerRef);
        for (RegistriesConf.MirrorConfig mirror : mirrors) {
            String mirrorLocation = mirror.location();
            if (mirrorLocation == null || mirrorLocation.isBlank()) continue;
            ContainerRef mirrorRef = registriesConf.rewriteForMirror(containerRef, mirror);
            // Use only the host[:port] for copyForMirror() — the path prefix is already baked into
            // mirrorRef by rewriteForMirror, so including it here would double-apply the path.
            // Strip any scheme (e.g., "https://") before extracting the host.
            String locationNoScheme = mirrorLocation.contains("://")
                    ? mirrorLocation.substring(mirrorLocation.indexOf("://") + 3)
                    : mirrorLocation;
            String mirrorHost = locationNoScheme.contains("/")
                    ? locationNoScheme.substring(0, locationNoScheme.indexOf('/'))
                    : locationNoScheme;
            Registry mirrorRegistry = copyForNewTransport(mirrorHost, mirror.isInsecure());
            try {
                LOG.debug("Trying mirror {} for {}", mirrorLocation, containerRef);
                return operation.apply(mirrorRegistry, mirrorRef);
            } catch (OrasException e) {
                LOG.warn("Mirror {} failed for {}: {}", mirrorLocation, containerRef, e.getMessage());
            }
        }
        return operation.apply(this, containerRef);
    }

    /**
     * Get a manifest response, trying configured mirrors before the original registry.
     * @param containerRef The container
     * @return The response
     */
    private HttpClient.ResponseWrapper<String> getManifestResponse(ContainerRef containerRef) {
        return withMirrorFallback(containerRef, (reg, ref) -> reg.getManifestResponseDirect(ref));
    }

    private HttpClient.ResponseWrapper<String> getManifestResponseDirect(ContainerRef containerRef) {
        ContainerRef ref = containerRef.forRegistry(this).checkBlocked(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), true).getManifestResponseDirect(ref);
        }
        if (!ref.isInsecure(this) && this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), false).getManifestResponseDirect(ref);
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), ref.getManifestsPath(this)));
        HttpClient.ResponseWrapper<String> response =
                client.head(uri, Map.of(Const.ACCEPT_HEADER, Const.MANIFEST_ACCEPT_TYPE), Scopes.of(ref), authProvider);
        logResponse(response);
        handleError(response);
        return client.get(uri, Map.of("Accept", Const.MANIFEST_ACCEPT_TYPE), Scopes.of(ref), authProvider);
    }

    /**
     * Verify in-memory content against the digest pinned in the reference. No-op when the reference is
     * not digest-pinned (e.g. pulled by tag), since there is then no trusted value to check against.
     * @param ref The reference the content was requested for
     * @param content The bytes returned by the registry
     */
    private void verifyPinnedDigest(ContainerRef ref, byte[] content) {
        String digest = ref.getDigest();
        if (digest == null || !SupportedAlgorithm.isSupported(digest)) {
            return;
        }
        ensureDigest(digest, SupportedAlgorithm.fromDigest(digest).digest(content));
    }

    /**
     * Verify a downloaded blob against every digest that applies (pinned or from header)
     * @param ref The reference the blob was requested for
     * @param content The path the registry response was written to
     * @param headers The response headers
     */
    private void verifyBlobDigest(ContainerRef ref, Path content, Map<String, String> headers) {
        String pinned = ref.getDigest();
        String verified = null;
        if (pinned != null && SupportedAlgorithm.isSupported(pinned)) {
            ensureDigest(pinned, SupportedAlgorithm.fromDigest(pinned).digest(content));
            verified = pinned;
        }
        String header = headers.get(Const.DOCKER_CONTENT_DIGEST_HEADER.toLowerCase());
        if (header != null && !header.equals(verified)) {
            ensureDigest(header, SupportedAlgorithm.fromDigest(header).digest(content));
        }
    }

    private @Nullable String validateDockerContentDigest(HttpClient.ResponseWrapper<?> response) {
        return validateDockerContentDigest(response.headers());
    }

    private @Nullable String validateDockerContentDigest(Map<String, String> headers) {
        String digest = headers.get(Const.DOCKER_CONTENT_DIGEST_HEADER.toLowerCase());
        // Not mandatory, but require validation if present
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

    private void verifyContainersPolicy(ContainerRef containerRef, String digest) {
        String effectiveRegistry = containerRef.getEffectiveRegistry(this);
        ContainerRef effectiveRef = containerRef.forRegistry(effectiveRegistry);
        String scope = effectiveRef.toString().replaceFirst("(:[^/@]+)?(@[^/]+)?$", "");
        ContainerRef digestRef = effectiveRef.withDigest(digest);
        PolicyContext context = new PolicyContext(
                Transport.DOCKER, scope, digest, effectiveRef.toString(), () -> fetchSigstoreBundles(digestRef));
        containersPolicy.verify(context);
    }

    private List<byte[]> fetchSigstoreBundles(ContainerRef digestRef) {
        List<byte[]> bundles = new ArrayList<>();
        try {
            Referrers referrers = getReferrers(digestRef, ArtifactType.from(Const.SIGSTORE_BUNDLE_MEDIA_TYPE));
            for (ManifestDescriptor referrer : referrers.getManifests()) {
                // Some registries ignore the artifactType filter
                if (!Const.SIGSTORE_BUNDLE_MEDIA_TYPE.equals(referrer.getArtifactType())) {
                    continue;
                }
                Descriptor descriptor = getDescriptor(digestRef.withDigest(referrer.getDigest()));
                Manifest signatureManifest = Manifest.fromJson(descriptor.getJson());
                for (Layer layer : signatureManifest.getLayers()) {
                    if (Const.SIGSTORE_BUNDLE_MEDIA_TYPE.equals(layer.getMediaType())) {
                        bundles.add(getBlob(digestRef.withDigest(layer.getDigest())));
                    }
                }
            }
        } catch (Exception e) {
            LOG.warn("Failed to fetch Sigstore signatures for {}: {}", digestRef, e.getMessage());
        }
        return bundles;
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
        ContainerRef ref = containerRef.forRegistry(this);
        if (ref.isInsecure(this) && !this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), true).getResolvedHeaders(ref);
        }
        if (!ref.isInsecure(this) && this.isInsecure()) {
            return copyForNewTransport(ref.getRegistry(), false).getResolvedHeaders(ref);
        }
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
            this.registry.setRegistry(registry.registry);
            this.registry.setSkipTlsVerify(registry.skipTlsVerify);
            this.registry.setTransportLocked(registry.transportLocked);
            this.registry.setExecutorService(registry.executorService);
            this.registry.setParallelism(registry.maxConcurrentDownloads);
            this.registry.setMaxRetries(registry.maxRetries);
            this.registry.setRetryDelayMs(registry.retryDelayMs);
            this.registry.setMaxRetryDelayMs(registry.maxRetryDelayMs);
            this.registry.setContainersPolicy(registry.containersPolicy);
            if (registry.meterRegistry != null) {
                this.registry.setMeterRegistry(registry.meterRegistry);
            }
            if (registry.caFilePath != null) {
                this.registry.setCaFilePath(registry.caFilePath);
            }
            if (registry.caContent != null) {
                this.registry.setCaContent(registry.caContent);
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
         * Lock the transport decision so it is taken from the {@code insecure} flag of this builder
         * rather than re-resolved from registries.conf. Used for mirror connections.
         * @param transportLocked Whether the transport is explicitly decided
         * @return The builder
         */
        Builder withTransportLocked(boolean transportLocked) {
            registry.setTransportLocked(transportLocked);
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
         * Set the maximum number of attempts for retryable requests (default: 3).
         * A value of 1 disables retries entirely.
         * Retryable conditions: HTTP 429, HTTP 5xx, network errors (IOException / timeout).
         * Token-refresh requests are never retried regardless of this setting.
         * @param maxRetries Maximum attempts (must be &gt;= 1)
         * @return The builder
         */
        public Builder withMaxRetries(int maxRetries) {
            registry.setMaxRetries(maxRetries);
            return this;
        }

        /**
         * Set the initial delay before the first retry in milliseconds (default: 500).
         * Subsequent delays are doubled up to the limit set by {@link #withMaxRetryDelay}.
         * @param retryDelayMs Initial delay in milliseconds (must be &gt;= 0)
         * @return The builder
         */
        public Builder withRetryDelay(long retryDelayMs) {
            registry.setRetryDelayMs(retryDelayMs);
            return this;
        }

        /**
         * Set the upper bound on retry delay in milliseconds (default: 30 000).
         * @param maxRetryDelayMs Maximum delay cap in milliseconds (must be &gt;= 0)
         * @return The builder
         */
        public Builder withMaxRetryDelay(long maxRetryDelayMs) {
            registry.setMaxRetryDelayMs(maxRetryDelayMs);
            return this;
        }

        /**
         * Set the containers trust policy to enforce during pull operations.
         *
         * <p>When set, all image manifest pulls will be evaluated against the policy before
         * being returned. The {@code insecureAcceptAnything}, {@code reject}, and
         * {@code sigstoreSigned} (keyed verification of attached Sigstore bundles) requirements are
         * enforced. The {@code signedBy} (GPG simple signing) requirement is not implemented and will
         * log a warning and accept the image without verification.
         *
         * <p>By default, the policy is loaded from standard locations
         * ({@code $HOME/.config/containers/policy.json} or {@code /etc/containers/policy.json}).
         * If no policy file is found, an accept-all policy is used.
         *
         * @param policy the containers policy to enforce.
         * @return the builder
         * @see ContainersPolicy#newPolicy()
         */
        public Builder withPolicy(ContainersPolicy policy) {
            registry.setContainersPolicy(policy);
            return this;
        }

        /**
         * Load and set the containers trust policy from the given path.
         *
         * @param policyPath the path to the policy.json file.
         * @return the builder
         * @throws OrasException if the file cannot be read or parsed.
         * @see ContainersPolicy#newPolicy(Path)
         */
        public Builder withPolicy(Path policyPath) {
            registry.setContainersPolicy(ContainersPolicy.newPolicy(policyPath));
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

    /**
     * A stream that verifies the content digest incrementally as it is read, without buffering to a
     * temporary file. It updates one {@link MessageDigest} per distinct algorithm as bytes pass through
     * and, at end-of-stream
     */
    private static final class DigestVerifyingInputStream extends FilterInputStream {

        private final List<String> expectedDigests;
        private final Map<String, MessageDigest> digestsByPrefix = new HashMap<>();
        private boolean verified;

        private DigestVerifyingInputStream(InputStream in, List<String> expectedDigests) {
            super(in);
            this.expectedDigests = expectedDigests;
            for (String expected : expectedDigests) {
                SupportedAlgorithm algorithm = SupportedAlgorithm.fromDigest(expected);
                digestsByPrefix.computeIfAbsent(algorithm.getPrefix(), p -> {
                    try {
                        return MessageDigest.getInstance(algorithm.getAlgorithmName());
                    } catch (NoSuchAlgorithmException e) {
                        throw new OrasException("Unsupported digest algorithm: " + algorithm.getAlgorithmName(), e);
                    }
                });
            }
        }

        @Override
        public int read(byte[] buffer, int off, int len) throws IOException {
            int read = super.read(buffer, off, len);
            if (read > 0) {
                for (MessageDigest digest : digestsByPrefix.values()) {
                    digest.update(buffer, off, read);
                }
            } else if (read < 0) {
                verify();
            }
            return read;
        }

        private void verify() {
            if (verified) {
                return;
            }
            verified = true;
            Map<String, String> actualByPrefix = new HashMap<>();
            digestsByPrefix.forEach((prefix, digest) ->
                    actualByPrefix.put(prefix, prefix + ":" + HexFormat.of().formatHex(digest.digest())));
            for (String expected : expectedDigests) {
                String prefix = SupportedAlgorithm.fromDigest(expected).getPrefix();
                String actual = actualByPrefix.get(prefix);
                if (!expected.equals(actual)) {
                    throw new OrasException("Digest mismatch: %s != %s".formatted(expected, actual));
                }
            }
        }
    }
}
