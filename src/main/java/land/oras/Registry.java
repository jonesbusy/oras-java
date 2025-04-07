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

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import land.oras.auth.AuthProvider;
import land.oras.auth.AuthStoreAuthenticationProvider;
import land.oras.auth.BearerTokenProvider;
import land.oras.auth.NoAuthProvider;
import land.oras.auth.UsernamePasswordProvider;
import land.oras.exception.OrasException;
import land.oras.utils.ArchiveUtils;
import land.oras.utils.Const;
import land.oras.utils.JsonUtils;
import land.oras.utils.OrasHttpClient;
import land.oras.utils.SupportedAlgorithm;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/**
 * A registry is the main entry point for interacting with a container registry
 */
@NullMarked
public final class Registry extends OCI<ContainerRef> {

    /**
     * The HTTP client
     */
    private OrasHttpClient client;

    /**
     * The auth provider
     */
    private AuthProvider authProvider;

    /**
     * Insecure. Use HTTP instead of HTTPS
     */
    private boolean insecure;

    /**
     * Skip TLS verification
     */
    private boolean skipTlsVerify;

    /**
     * Constructor
     */
    private Registry() {
        this.authProvider = new NoAuthProvider();
        this.client = OrasHttpClient.Builder.builder().build();
    }

    /**
     * Return this registry with insecure flag
     * @param insecure Insecure
     */
    private void setInsecure(boolean insecure) {
        this.insecure = insecure;
    }

    /**
     * Return this registry with skip TLS verification
     * @param skipTlsVerify Skip TLS verification
     */
    private void setSkipTlsVerify(boolean skipTlsVerify) {
        this.skipTlsVerify = skipTlsVerify;
    }

    /**
     * Return this registry with auth provider
     * @param authProvider The auth provider
     */
    private void setAuthProvider(AuthProvider authProvider) {
        this.authProvider = authProvider;
        client.updateAuthentication(authProvider);
    }

    /**
     * Build the provider
     * @return The provider
     */
    private Registry build() {
        client = OrasHttpClient.Builder.builder()
                .withAuthentication(authProvider)
                .withSkipTlsVerify(skipTlsVerify)
                .build();
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
     * Get the tags of a container
     * @param containerRef The container
     * @return The tags
     */
    public List<String> getTags(ContainerRef containerRef) {
        URI uri = URI.create("%s://%s".formatted(getScheme(), containerRef.getTagsPath()));
        OrasHttpClient.ResponseWrapper<String> response =
                client.get(uri, Map.of(Const.ACCEPT_HEADER, Const.DEFAULT_JSON_MEDIA_TYPE));
        if (switchTokenAuth(containerRef, response)) {
            response = client.get(uri, Map.of(Const.ACCEPT_HEADER, Const.DEFAULT_JSON_MEDIA_TYPE));
        }
        handleError(response);
        return JsonUtils.fromJson(response.response(), Tags.class).tags();
    }

    /**
     * Get the referrers of a container
     * @param containerRef The container
     * @param artifactType The optional artifact type
     * @return The referrers
     */
    public Referrers getReferrers(ContainerRef containerRef, @Nullable ArtifactType artifactType) {
        if (containerRef.getDigest() == null) {
            throw new OrasException("Digest is required to get referrers");
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), containerRef.getReferrersPath(artifactType)));
        OrasHttpClient.ResponseWrapper<String> response =
                client.get(uri, Map.of(Const.ACCEPT_HEADER, Const.DEFAULT_INDEX_MEDIA_TYPE));
        if (switchTokenAuth(containerRef, response)) {
            response = client.get(uri, Map.of(Const.ACCEPT_HEADER, Const.DEFAULT_INDEX_MEDIA_TYPE));
        }
        handleError(response);
        return JsonUtils.fromJson(response.response(), Referrers.class);
    }

    /**
     * Delete a manifest
     * @param containerRef The artifact
     */
    public void deleteManifest(ContainerRef containerRef) {
        URI uri = URI.create("%s://%s".formatted(getScheme(), containerRef.getManifestsPath()));
        OrasHttpClient.ResponseWrapper<String> response = client.delete(uri, Map.of());
        logResponse(response);
        if (switchTokenAuth(containerRef, response)) {
            response = client.delete(uri, Map.of());
            logResponse(response);
        }
        handleError(response);
    }

    @Override
    public Manifest pushManifest(ContainerRef containerRef, Manifest manifest) {

        Map<String, String> annotations = manifest.getAnnotations();
        if (!annotations.containsKey(Const.ANNOTATION_CREATED) && containerRef.getDigest() == null) {
            Map<String, String> manifestAnnotations = new HashMap<>(annotations);
            manifestAnnotations.put(Const.ANNOTATION_CREATED, Const.currentTimestamp());
            manifest = manifest.withAnnotations(manifestAnnotations);
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), containerRef.getManifestsPath()));
        byte[] manifestData = manifest.getJson() != null
                ? manifest.getJson().getBytes()
                : manifest.toJson().getBytes();
        OrasHttpClient.ResponseWrapper<String> response =
                client.put(uri, manifestData, Map.of(Const.CONTENT_TYPE_HEADER, Const.DEFAULT_MANIFEST_MEDIA_TYPE));
        if (switchTokenAuth(containerRef, response)) {
            response =
                    client.put(uri, manifestData, Map.of(Const.CONTENT_TYPE_HEADER, Const.DEFAULT_MANIFEST_MEDIA_TYPE));
        }
        logResponse(response);
        handleError(response);
        if (manifest.getSubject() != null) {
            // https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pushing-manifests-with-subject
            if (!response.headers().containsKey(Const.OCI_SUBJECT_HEADER.toLowerCase())) {
                throw new OrasException(
                        "Subject was set on manifest but not OCI subject header was returned. Legacy flow not implemented");
            }
        }
        return getManifest(containerRef);
    }

    @Override
    public Index pushIndex(ContainerRef containerRef, Index index) {
        URI uri = URI.create("%s://%s".formatted(getScheme(), containerRef.getManifestsPath()));
        OrasHttpClient.ResponseWrapper<String> response = client.put(
                uri,
                JsonUtils.toJson(index).getBytes(),
                Map.of(Const.CONTENT_TYPE_HEADER, Const.DEFAULT_INDEX_MEDIA_TYPE));
        if (switchTokenAuth(containerRef, response)) {
            response = client.put(
                    uri,
                    JsonUtils.toJson(index).getBytes(),
                    Map.of(Const.CONTENT_TYPE_HEADER, Const.DEFAULT_INDEX_MEDIA_TYPE));
        }
        logResponse(response);
        handleError(response);
        return getIndex(containerRef);
    }

    /**
     * Delete a blob
     * @param containerRef The container
     */
    public void deleteBlob(ContainerRef containerRef) {
        URI uri = URI.create("%s://%s".formatted(getScheme(), containerRef.getBlobsPath()));
        OrasHttpClient.ResponseWrapper<String> response = client.delete(uri, Map.of());
        logResponse(response);
        // Switch to bearer auth if needed and retry first request
        if (switchTokenAuth(containerRef, response)) {
            response = client.delete(uri, Map.of());
            logResponse(response);
        }
        handleError(response);
    }

    @Override
    public void pullArtifact(ContainerRef containerRef, Path path, boolean overwrite) {

        // Only collect layer that are files
        String contentType = getContentType(containerRef);
        List<Layer> layers = collectLayers(containerRef, contentType, false);
        if (layers.isEmpty()) {
            LOG.info("Skipped pulling layers without file name in '{}'", Const.ANNOTATION_TITLE);
            return;
        }
        for (Layer layer : layers) {
            try (InputStream is = fetchBlob(containerRef.withDigest(layer.getDigest()))) {
                // Unpack or just copy blob
                if (Boolean.parseBoolean(layer.getAnnotations().getOrDefault(Const.ANNOTATION_ORAS_UNPACK, "false"))) {
                    LOG.debug("Extracting blob to: {}", path);

                    // Uncompress the tar.gz archive and verify digest if present
                    LocalPath tempArchive = ArchiveUtils.uncompress(is, layer.getMediaType());
                    String expectedDigest = layer.getAnnotations().get(Const.ANNOTATION_ORAS_CONTENT_DIGEST);
                    if (expectedDigest != null) {
                        LOG.trace("Expected digest: {}", expectedDigest);
                        String actualDigest = containerRef.getAlgorithm().digest(tempArchive.getPath());
                        LOG.trace("Actual digest: {}", actualDigest);
                        if (!expectedDigest.equals(actualDigest)) {
                            throw new OrasException(
                                    "Digest mismatch: expected %s but got %s".formatted(expectedDigest, actualDigest));
                        }
                    }

                    // Extract the tar
                    ArchiveUtils.untar(Files.newInputStream(tempArchive.getPath()), path);

                } else {
                    Path targetPath = path.resolve(
                            layer.getAnnotations().getOrDefault(Const.ANNOTATION_TITLE, layer.getDigest()));
                    LOG.debug("Copying blob to: {}", targetPath);
                    Files.copy(
                            is,
                            targetPath,
                            overwrite ? StandardCopyOption.REPLACE_EXISTING : StandardCopyOption.ATOMIC_MOVE);
                }
            } catch (IOException e) {
                throw new OrasException("Failed to pull artifact", e);
            }
        }
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

        // Push layers
        List<Layer> layers = pushLayers(containerRef, false, paths);

        // Push the config like any other blob
        Config pushedConfig = pushConfig(containerRef, config != null ? config : Config.empty());

        // Add layer and config
        manifest = manifest.withLayers(layers).withConfig(pushedConfig);

        // Push the manifest
        manifest = pushManifest(containerRef, manifest);
        LOG.debug(
                "Manifest pushed to: {}",
                containerRef.withDigest(manifest.getDescriptor().getDigest()));
        return manifest;
    }

    /**
     * Copy an artifact from one container to another
     * @param targetRegistry The target registry
     * @param sourceContainer The source container
     * @param targetContainer The target container
     */
    public void copy(Registry targetRegistry, ContainerRef sourceContainer, ContainerRef targetContainer) {
        throw new OrasException("Not implemented");
    }

    @Override
    public Layer pushBlob(ContainerRef containerRef, Path blob, Map<String, String> annotations) {
        String digest = containerRef.getAlgorithm().digest(blob);
        LOG.debug("Digest: {}", digest);
        if (hasBlob(containerRef.withDigest(digest))) {
            LOG.info("Blob already exists: {}", digest);
            return Layer.fromFile(blob, containerRef.getAlgorithm()).withAnnotations(annotations);
        }
        URI uri = URI.create(
                "%s://%s".formatted(getScheme(), containerRef.withDigest(digest).getBlobsUploadDigestPath()));
        OrasHttpClient.ResponseWrapper<String> response = client.upload(
                "POST", uri, Map.of(Const.CONTENT_TYPE_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE), blob);
        logResponse(response);

        // Switch to bearer auth if needed and retry first request
        if (switchTokenAuth(containerRef, response)) {
            response = client.upload(
                    "POST", uri, Map.of(Const.CONTENT_TYPE_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE), blob);
            logResponse(response);
        }

        // Accepted single POST push
        if (response.statusCode() == 201) {
            return Layer.fromFile(blob, containerRef.getAlgorithm()).withAnnotations(annotations);
        }

        // We need to push via PUT
        if (response.statusCode() == 202) {
            String location = response.headers().get(Const.LOCATION_HEADER.toLowerCase());
            // Ensure location is absolute URI
            if (!location.startsWith("http") && !location.startsWith("https")) {
                location = "%s://%s/%s"
                        .formatted(getScheme(), containerRef.getApiRegistry(), location.replaceFirst("^/", ""));
            }
            LOG.debug("Location header: {}", location);
            response = client.upload(
                    "PUT",
                    URI.create("%s&digest=%s".formatted(location, digest)),
                    Map.of(Const.CONTENT_TYPE_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE),
                    blob);
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
    public Layer pushBlob(ContainerRef containerRef, byte[] data) {
        String digest = containerRef.getAlgorithm().digest(data);
        if (containerRef.getDigest() != null) {
            ensureDigest(containerRef, data);
        }
        if (hasBlob(containerRef.withDigest(digest))) {
            LOG.info("Blob already exists: {}", digest);
            return Layer.fromData(containerRef, data);
        }
        URI uri = URI.create(
                "%s://%s".formatted(getScheme(), containerRef.withDigest(digest).getBlobsUploadDigestPath()));
        OrasHttpClient.ResponseWrapper<String> response =
                client.post(uri, data, Map.of(Const.CONTENT_TYPE_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE));
        logResponse(response);

        // Switch to bearer auth if needed and retry first request
        if (switchTokenAuth(containerRef, response)) {
            response = client.post(
                    uri, data, Map.of(Const.CONTENT_TYPE_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE));
            logResponse(response);
        }

        // Accepted single POST push
        if (response.statusCode() == 201) {
            return Layer.fromData(containerRef, data);
        }

        // We need to push via PUT
        if (response.statusCode() == 202) {
            String location = response.headers().get(Const.LOCATION_HEADER.toLowerCase());
            // Ensure location is absolute URI
            if (!location.startsWith("http") && !location.startsWith("https")) {
                location = "%s://%s/%s"
                        .formatted(getScheme(), containerRef.getApiRegistry(), location.replaceFirst("^/", ""));
            }
            LOG.debug("Location header: {}", location);
            response = client.put(
                    URI.create("%s&digest=%s".formatted(location, digest)),
                    data,
                    Map.of(Const.CONTENT_TYPE_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE));
            if (response.statusCode() == 201) {
                LOG.debug("Successful push: {}", response.response());
            } else {
                throw new OrasException("Failed to push layer: %s".formatted(response.response()));
            }
        }

        handleError(response);
        return Layer.fromData(containerRef, data);
    }

    /**
     * Return if the registry contains already the blob
     * @param containerRef The container
     * @return True if the blob exists
     */
    private boolean hasBlob(ContainerRef containerRef) {
        OrasHttpClient.ResponseWrapper<String> response = headBlob(containerRef);
        return response.statusCode() == 200;
    }

    private OrasHttpClient.ResponseWrapper<String> headBlob(ContainerRef containerRef) {
        URI uri = URI.create("%s://%s".formatted(getScheme(), containerRef.getBlobsPath()));
        OrasHttpClient.ResponseWrapper<String> response =
                client.head(uri, Map.of(Const.ACCEPT_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE));
        logResponse(response);

        // Switch to bearer auth if needed and retry first request
        if (switchTokenAuth(containerRef, response)) {
            response = client.head(uri, Map.of(Const.ACCEPT_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE));
            logResponse(response);
        }
        return response;
    }

    /**
     * Get the blob for the given digest. Not be suitable for large blobs
     * @param containerRef The container
     * @return The blob as bytes
     */
    @Override
    public byte[] getBlob(ContainerRef containerRef) {
        try (InputStream is = fetchBlob(containerRef)) {
            return ensureDigest(containerRef, is.readAllBytes());
        } catch (IOException e) {
            throw new OrasException("Failed to get blob", e);
        }
    }

    @Override
    public void fetchBlob(ContainerRef containerRef, Path path) {
        if (!hasBlob(containerRef)) {
            throw new OrasException(new OrasHttpClient.ResponseWrapper<>("", 404, Map.of()));
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), containerRef.getBlobsPath()));
        OrasHttpClient.ResponseWrapper<Path> response =
                client.download(uri, Map.of(Const.ACCEPT_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE), path);
        logResponse(response);
        handleError(response);
    }

    @Override
    public InputStream fetchBlob(ContainerRef containerRef) {
        if (!hasBlob(containerRef)) {
            throw new OrasException(new OrasHttpClient.ResponseWrapper<>("", 404, Map.of()));
        }
        URI uri = URI.create("%s://%s".formatted(getScheme(), containerRef.getBlobsPath()));
        OrasHttpClient.ResponseWrapper<InputStream> response =
                client.download(uri, Map.of(Const.ACCEPT_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE));
        logResponse(response);
        handleError(response);
        return response.response();
    }

    @Override
    public Descriptor fetchBlobDescriptor(ContainerRef containerRef) {
        OrasHttpClient.ResponseWrapper<String> response = headBlob(containerRef);
        handleError(response);
        String size = response.headers().get(Const.CONTENT_LENGTH_HEADER.toLowerCase());
        String digest = response.headers().get(Const.DOCKER_CONTENT_DIGEST_HEADER.toLowerCase());
        return Descriptor.of(digest, Long.parseLong(size), Const.DEFAULT_DESCRIPTOR_MEDIA_TYPE);
    }

    @Override
    public Manifest getManifest(ContainerRef containerRef) {
        Descriptor descriptor = getDescriptor(containerRef);
        String contentType = descriptor.getMediaType();
        if (!isManifestMediaType(contentType)) {
            throw new OrasException(
                    "Expected manifest but got index. Probably a multi-platform image instead of artifact");
        }
        ManifestDescriptor manifestDescriptor = ManifestDescriptor.of(descriptor);
        return Manifest.fromJson(descriptor.getJson()).withDescriptor(manifestDescriptor);
    }

    @Override
    public Index getIndex(ContainerRef containerRef) {
        Descriptor descriptor = getDescriptor(containerRef);
        String contentType = descriptor.getMediaType();
        if (!isIndexMediaType(contentType)) {
            throw new OrasException("Expected index but got %s".formatted(contentType));
        }
        ManifestDescriptor manifestDescriptor = ManifestDescriptor.of(descriptor);
        return Index.fromJson(descriptor.getJson()).withDescriptor(manifestDescriptor);
    }

    @Override
    public Descriptor getDescriptor(ContainerRef containerRef) {
        OrasHttpClient.ResponseWrapper<String> response = getManifestResponse(containerRef);
        handleError(response);
        String size = response.headers().get(Const.CONTENT_LENGTH_HEADER.toLowerCase());
        String digest = response.headers().get(Const.DOCKER_CONTENT_DIGEST_HEADER.toLowerCase());
        String contentType = response.headers().get(Const.CONTENT_TYPE_HEADER.toLowerCase());
        return Descriptor.of(digest, Long.parseLong(size), contentType).withJson(response.response());
    }

    @Override
    public Descriptor probeDescriptor(ContainerRef ref) {
        Map<String, String> headers = getHeaders(ref);
        String digest = headers.get(Const.DOCKER_CONTENT_DIGEST_HEADER.toLowerCase());
        String contentType = headers.get(Const.CONTENT_TYPE_HEADER.toLowerCase());
        return Descriptor.of(digest, 0L, contentType);
    }

    /**
     * Get a manifest response
     * @param containerRef The container
     * @return The response
     */
    private OrasHttpClient.ResponseWrapper<String> getManifestResponse(ContainerRef containerRef) {
        URI uri = URI.create("%s://%s".formatted(getScheme(), containerRef.getManifestsPath()));
        OrasHttpClient.ResponseWrapper<String> response =
                client.head(uri, Map.of(Const.ACCEPT_HEADER, Const.MANIFEST_ACCEPT_TYPE));
        logResponse(response);

        // Switch to bearer auth if needed and retry first request
        if (switchTokenAuth(containerRef, response)) {
            response = client.head(uri, Map.of(Const.ACCEPT_HEADER, Const.MANIFEST_ACCEPT_TYPE));
            logResponse(response);
        }
        handleError(response);
        return client.get(uri, Map.of("Accept", Const.MANIFEST_ACCEPT_TYPE));
    }

    private byte[] ensureDigest(ContainerRef ref, byte[] data) {
        if (ref.getDigest() == null) {
            throw new OrasException("Missing digest");
        }
        SupportedAlgorithm algorithm = SupportedAlgorithm.fromDigest(ref.getDigest());
        String dataDigest = algorithm.digest(data);
        if (!ref.getDigest().equals(dataDigest)) {
            throw new OrasException("Digest mismatch: %s != %s".formatted(ref.getDigest(), dataDigest));
        }
        return data;
    }

    /**
     * Switch the current authentication to token auth
     * @param response The response
     */
    private boolean switchTokenAuth(ContainerRef containerRef, OrasHttpClient.ResponseWrapper<String> response) {
        if (response.statusCode() == 401 && !(authProvider instanceof BearerTokenProvider)) {
            LOG.debug("Requesting token with token flow");
            setAuthProvider(new BearerTokenProvider(authProvider).refreshToken(containerRef, client, response));
            return true;
        }
        // Need token refresh (expired or wrong scope)
        if ((response.statusCode() == 401 || response.statusCode() == 403)
                && authProvider instanceof BearerTokenProvider) {
            LOG.debug("Requesting new token with username password flow");
            setAuthProvider(((BearerTokenProvider) authProvider).refreshToken(containerRef, client, response));
            return true;
        }
        return false;
    }

    /**
     * Handle an error response
     * @param responseWrapper The response
     */
    @SuppressWarnings("unchecked")
    private void handleError(OrasHttpClient.ResponseWrapper<?> responseWrapper) {
        if (responseWrapper.statusCode() >= 400) {
            if (responseWrapper.response() instanceof String) {
                LOG.debug("Response: {}", responseWrapper.response());
                throw new OrasException((OrasHttpClient.ResponseWrapper<String>) responseWrapper);
            }
            throw new OrasException(new OrasHttpClient.ResponseWrapper<>("", responseWrapper.statusCode(), Map.of()));
        }
    }

    /**
     * Log the response
     * @param response The response
     */
    private void logResponse(OrasHttpClient.ResponseWrapper<?> response) {
        LOG.debug("Status Code: {}", response.statusCode());
        LOG.debug("Headers: {}", response.headers());
        // Only log non-binary responses
        if (response.response() instanceof String) {
            LOG.debug("Response: {}", response.response());
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
        return getHeaders(containerRef).get(Const.CONTENT_TYPE_HEADER.toLowerCase());
    }

    /**
     * Execute a head request on the manifest URL and return the headers
     * @param containerRef The container
     * @return The headers
     */
    Map<String, String> getHeaders(ContainerRef containerRef) {
        URI uri = URI.create("%s://%s".formatted(getScheme(), containerRef.getManifestsPath()));
        OrasHttpClient.ResponseWrapper<String> response =
                client.head(uri, Map.of(Const.ACCEPT_HEADER, Const.MANIFEST_ACCEPT_TYPE));
        logResponse(response);

        // Switch to bearer auth if needed and retry first request
        if (switchTokenAuth(containerRef, response)) {
            response = client.head(uri, Map.of(Const.ACCEPT_HEADER, Const.MANIFEST_ACCEPT_TYPE));
            logResponse(response);
        }
        handleError(response);
        return response.headers();
    }

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
         * Return a new builder with username and password authentication
         * @param username The username
         * @param password The password
         * @return The builder
         */
        public Builder defaults(String username, String password) {
            registry.setAuthProvider(new UsernamePasswordProvider(username, password));
            return this;
        }

        /**
         * Return a new builder with insecure communication and not authentification
         * @return The builder
         */
        public Builder insecure() {
            registry.setInsecure(true);
            registry.setSkipTlsVerify(true);
            registry.setAuthProvider(new NoAuthProvider());
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
