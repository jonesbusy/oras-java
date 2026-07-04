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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import land.oras.exception.OrasException;
import land.oras.policy.Transport;
import land.oras.utils.Const;
import land.oras.utils.SupportedAlgorithm;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A referer of a container on a {@link Registry}.
 */
@NullMarked
@OrasModel
public final class ContainerRef extends Ref<ContainerRef> {

    /**
     * The logger for this class.
     */
    public static final Logger LOG = LoggerFactory.getLogger(ContainerRef.class);

    /**
     * The regex pattern to parse the container name including the registry, namespace, repository, tag and digest.
     */
    private static final Pattern NAME_REGEX = Pattern.compile(
            "(?:([^/@]+[.:][^/@]*)/)?" // registry
                    + "((?:[^:@/]+/)+)?" // namespace
                    + "([^:@/]+)" // repository
                    + "(?::([^:@]+))?" // tag
                    + "(?:@(.+))?" // digest
                    + "$");

    /**
     * The registry where the container is stored.
     */
    private final String registry;

    /**
     * The repository where the container is stored.
     */
    private final String repository;

    /**
     * The namespace of the container.
     */
    private final @Nullable String namespace;

    /**
     * The digest of the container.
     */
    private final @Nullable String digest;

    /**
     * Whether the container reference is unqualified without registry
     */
    private final boolean unqualified;

    /**
     * Private constructor
     * @param registry The registry where the container is stored.
     * @param unqualified Whether the container reference is unqualified without registry
     * @param namespace The namespace of the container.
     * @param repository The repository where the container is stored
     * @param tag The tag of the container.
     * @param digest The digest of the container.
     */
    private ContainerRef(
            String registry,
            boolean unqualified,
            @Nullable String namespace,
            String repository,
            @Nullable String tag,
            @Nullable String digest) {
        super(tag);
        this.unqualified = unqualified;
        this.registry = registry;
        this.namespace = namespace;
        this.repository = repository;
        this.digest = digest;
    }

    /**
     * Create a new container reference
     * @return The new container reference
     */
    public String getRegistry() {
        return registry;
    }

    /**
     * Whether the container reference is unqualified without registry
     * @return True if unqualified
     */
    public boolean isUnqualified() {
        return unqualified;
    }

    /**
     * Get the full repository name including the namespace if any
     * @param registry The registry
     * @return The full repository name
     */
    public String getFullRepository(@Nullable Registry registry) {
        String namespace = getNamespace(registry);
        if (namespace != null) {
            return "%s/%s".formatted(namespace, repository);
        }
        return repository;
    }

    /**
     * Get the full repository name including the namespace if any
     * @return The full repository name
     */
    public String getFullRepository() {
        return getFullRepository(null);
    }

    /**
     * Get the API registry
     * @param target The target registry
     * @return The API registry
     */
    public String getApiRegistry(@Nullable Registry target) {
        String registry = target != null && target.getRegistry() != null ? target.getRegistry() : getRegistry();
        if (registry.equals("docker.io")) {
            return "registry-1.docker.io";
        }
        return registry;
    }

    /**
     * Get the API registry
     * @return The API registry
     */
    public String getApiRegistry() {
        return getApiRegistry(null);
    }

    /**
     * Get the namespace
     * @return The namespace
     */
    public @Nullable String getNamespace() {
        String registry = getRegistry();
        if (namespace == null && registry.equals("docker.io")) {
            return "library";
        }
        return namespace;
    }

    /**
     * Get the effective namespace based on given registry traget
     * @param target The target registry
     * @return The effective namespace
     */
    public @Nullable String getNamespace(@Nullable Registry target) {
        if (target == null || target.getRegistry() == null) {
            return getNamespace();
        }
        if (namespace == null && target.getRegistry().equals("docker.io")) {
            return "library";
        }
        return namespace;
    }

    /**
     * Get the repository
     * @return The repository
     */
    public String getRepository() {
        return repository;
    }

    /**
     * Get the digest
     * @return The digest
     */
    public @Nullable String getDigest() {
        return digest;
    }

    @Override
    public ContainerRef withDigest(String digest) {
        // Ensure to set tag to null when setting digest
        return new ContainerRef(registry, unqualified, namespace, repository, null, digest);
    }

    /**
     * Return a copy of reference with the given tag
     * @param tag The tag
     * @return The container reference with the given tag
     */
    public ContainerRef withTag(String tag) {
        return new ContainerRef(registry, unqualified, namespace, repository, tag, digest);
    }

    @Override
    public SupportedAlgorithm getAlgorithm() {
        // Default if not set
        if (digest == null) {
            return SupportedAlgorithm.getDefault();
        }
        // See https://github.com/opencontainers/image-spec/blob/main/descriptor.md#digests
        return SupportedAlgorithm.fromDigest(digest);
    }

    /**
     * Get the API prefix
     * @param target The target registry
     * @return The API prefix
     */
    private String getApiPrefix(@Nullable Registry target) {
        String namespace = getNamespace(target);
        if (namespace != null) {
            return "%s/v2/%s/%s".formatted(getApiRegistry(target), namespace, repository);
        }
        return "%s/v2/%s".formatted(getApiRegistry(target), repository);
    }

    /**
     * Return the catalog repositories URL
     * @param target The target registry
     * @return The tag URL
     */
    public String getRepositoriesPath(@Nullable Registry target) {
        return "%s/v2/_catalog".formatted(getApiRegistry(target));
    }

    /**
     * Return the catalog repositories URL
     * @return The tag URL
     */
    public String getRepositoriesPath() {
        return getRepositoriesPath(null);
    }

    /**
     * Return the tag URL
     * @param target The target registry
     * @return The tag URL
     */
    public String getTagsPath(@Nullable Registry target) {
        return "%s/tags/list".formatted(getApiPrefix(target));
    }

    /**
     * Return the tag URL
     * @param n The optional number of tags to return, for pagination
     * @param last The optional last tag index, for pagination
     * @return The tag URL
     */
    public String getTagsPath(@Nullable Integer n, @Nullable String last) {
        return getTagsPath(null, n, last);
    }

    /**
     * Return the tag URL
     * @param n The optional number of tags to return, for pagination
     * @param last The optional last tag index, for pagination
     * @param target The target registry
     * @return The tag URL
     */
    public String getTagsPath(@Nullable Registry target, @Nullable Integer n, @Nullable String last) {
        if (n == null && last == null) {
            return getTagsPath(target);
        }
        StringBuilder url = new StringBuilder(getTagsPath(target)).append("?");
        if (n != null) {
            url.append("n=").append(n);
        }
        if (last != null) {
            if (n != null) {
                url.append("&");
            }
            url.append("last=").append(URLEncoder.encode(last, StandardCharsets.UTF_8));
        }
        return url.toString();
    }

    /**
     * Return the tag URL
     * @return The tag URL
     */
    public String getTagsPath() {
        return getTagsPath(null, null);
    }

    /**
     * Return the blobs mount URL for cross-repository blob mounting
     * @param sourceRef The source container reference to mount the blob from
     * @return The blobs mount URL
     */
    public String getBlobsMountPath(ContainerRef sourceRef) {
        return getBlobsMountPath(null, sourceRef);
    }

    /**
     * Return the blobs mount URL for cross-repository blob mounting
     * @param registry The registry
     * @param sourceRef The source container reference to mount the blob from
     * @return The blobs mount URL
     */
    public String getBlobsMountPath(@Nullable Registry registry, ContainerRef sourceRef) {
        if (digest == null) {
            throw new OrasException("You are required to include a digest");
        }
        return "%s/blobs/uploads/?mount=%s&from=%s"
                .formatted(
                        getApiPrefix(registry),
                        digest,
                        URLEncoder.encode(sourceRef.getFullRepository(registry), StandardCharsets.UTF_8));
    }

    /**
     * Return the referrers URL for this container referrer
     * @param artifactType The optional artifact type
     * @param registry The optional registry
     * @return The referrers URL
     */
    public String getReferrersPath(@Nullable Registry registry, @Nullable ArtifactType artifactType) {
        if (artifactType == null) {
            return "%s/referrers/%s".formatted(getApiPrefix(registry), digest);
        }
        return "%s/referrers/%s?artifactType=%s"
                .formatted(
                        getApiPrefix(registry),
                        digest,
                        URLEncoder.encode(artifactType.toString(), StandardCharsets.UTF_8));
    }

    /**
     * Return the referrers URL for this container referrer with a pagination cursor
     * @param registry The optional registry
     * @param artifactType The optional artifact type filter
     * @param last The pagination cursor (the last digest seen), or null to start from the beginning
     * @return The referrers URL with query parameters
     */
    public String getReferrersPath(
            @Nullable Registry registry, @Nullable ArtifactType artifactType, @Nullable String last) {
        if (last == null) {
            return getReferrersPath(registry, artifactType);
        }
        StringBuilder url = new StringBuilder(getReferrersPath(registry, artifactType));
        if (artifactType == null) {
            url.append("?last=").append(URLEncoder.encode(last, StandardCharsets.UTF_8));
        } else {
            url.append("&last=").append(URLEncoder.encode(last, StandardCharsets.UTF_8));
        }
        return url.toString();
    }

    /**
     * Return the referrers URL for this container referrer
     * @param artifactType The optional artifact type
     * @return The referrers URL
     */
    public String getReferrersPath(@Nullable ArtifactType artifactType) {
        return getReferrersPath(null, artifactType);
    }

    /**
     * Return the manifests URL
     * @param registry The registry
     * @return The manifests URL
     */
    public String getManifestsPath(@Nullable Registry registry) {
        return "%s/manifests/%s".formatted(getApiPrefix(registry), digest == null ? tag : digest);
    }

    /**
     * Return the manifests URL
     * @return The manifests URL
     */
    public String getManifestsPath() {
        return getManifestsPath(null);
    }

    /**
     * Return the blobs upload URL with the digest for single POST upload
     * @param registry The registry
     * @return The blobs upload URL
     */
    public String getBlobsUploadDigestPath(Registry registry) {
        if (digest == null) {
            throw new OrasException("You are required to include a digest");
        }
        return "%s/blobs/uploads/?digest=%s".formatted(getApiPrefix(registry), digest);
    }

    /**
     * Return the blobs upload URL for POST upload to get the upload location
     * @param registry The registry
     * @return The blobs upload URL
     */
    public String getBlobsUploadPath(Registry registry) {
        return "%s/blobs/uploads/".formatted(getApiPrefix(registry));
    }

    /**
     * Return the blobs URL
     * @param registry The registry
     * @return The blobs URL
     */
    public String getBlobsPath(@Nullable Registry registry) {
        if (digest == null) {
            throw new OrasException("You are required to include a digest");
        }
        return "%s/blobs/%s".formatted(getApiPrefix(registry), digest);
    }

    /**
     * Parse the container name into registry, repository and tag.
     * @param name The full name of the container to parse with any components.
     * @return The container object with the registry, repository and tag.
     */
    public static ContainerRef parse(String name) {

        // Strip prefix http:// or https:// or oci://
        name = name.replaceAll("^(http://|https://|oci://)", "");

        Matcher matcher = NAME_REGEX.matcher(name);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid container name format");
        }

        // Extract the parts of the container name
        String registry = matcher.group(1);
        String namespace = matcher.group(2);
        String repository = matcher.group(3);
        String tag = matcher.group(4);
        String digest = matcher.group(5);
        boolean unqualified = false;
        if (repository == null) {
            throw new IllegalArgumentException("You are minimally required to include a <namespace>/<repository>");
        }
        if (registry == null) {
            registry = Const.DEFAULT_REGISTRY;
            unqualified = true;
        }
        if (tag == null && digest == null) {
            tag = Const.DEFAULT_TAG;
        }
        // Strip the trailing slash from the namespace
        if (namespace != null) {
            namespace = namespace.substring(0, namespace.length() - 1);
        }

        // Validate digest algorithm
        if (digest != null) {
            SupportedAlgorithm.fromDigest(digest);
        }

        return new ContainerRef(registry, unqualified, namespace, repository, tag, digest);
    }

    /**
     * Get the effective registry based on given target
     * This methods will perform HEAD request to determine the first unqualified search registry that contains the container reference if the reference is unqualified, otherwise return the registry of the reference.
     * This only works with Manifests and Index but now direct blob access.
     * See {@link #forRegistry(String)} to set correct registry when getting blobs outside high level API like {@link Registry#pullArtifact(ContainerRef, Path, OCI.PullOptions)}.
     * @param target The target registry
     * @return The effective registry
     */
    public String getEffectiveRegistry(Registry target) {
        if (isUnqualified()) {
            String key = target.getRegistriesConf().getAliasKey(this);
            if (target.getRegistry() == null && target.getRegistriesConf().hasAlias(key)) {
                // Extract everything before the first slash (if any) as the registry for alias lookup, otherwise use
                // the repository as the key
                String value = target.getRegistriesConf().getAliases().get(key);
                String domain = value.split("/")[0];
                LOG.debug("Effective registry for alias {} is {}", key, domain);
                return domain;
            }
            return target.getRegistry() != null
                    ? target.getRegistry()
                    : determineFirstUnqualifiedSearchRegistry(target);
        }
        // The effective registry can be rewritten by the registry configuration.
        // Ensure to return it
        ContainerRef rewrite = target.getRegistriesConf().rewrite(this);
        return rewrite.getRegistry();
    }
    /**
     * Return a copy of reference for a registry other registry
     * @param registry The registry
     * @return The container reference
     */
    public ContainerRef forRegistry(String registry) {
        return new ContainerRef(registry, false, namespace, repository, tag, digest);
    }

    /**
     * Check if access to this container reference is insecure by the registry configuration
     * @param registry The registry
     * @return True if access to this container reference is insecure, false otherwise
     */
    public boolean isInsecure(Registry registry) {
        // When the transport has been explicitly decided (e.g. for a specific mirror), honor it
        // rather than re-resolving from registries.conf, so a registry-level insecure entry cannot
        // silently downgrade an explicitly-secure connection to plaintext HTTP.
        if (registry.isTransportLocked()) {
            return registry.isInsecure();
        }
        String effectiveRegistry = getEffectiveRegistry(registry);
        ContainerRef effectiveRef = forRegistry(effectiveRegistry);
        // Configuration is authoritative over the current registry
        if (registry.getRegistriesConf().isInsecure(registry, effectiveRef)) {
            LOG.debug(
                    "Access to container reference {} is insecure by location configuration for registry {}",
                    this,
                    effectiveRegistry);
            return true;
        }
        return false;
    }

    /**
     * Check if access to this container reference is blocked by the registry configuration or policies
     * @param registry The registry
     * @return True if access to this container reference is blocked, false otherwise
     */
    public boolean isBlocked(Registry registry) {
        String effectiveRegistry = getEffectiveRegistry(registry);
        ContainerRef effectiveRef = forRegistry(effectiveRegistry);
        if (registry.getRegistriesConf().isBlocked(effectiveRef)) {
            LOG.info(
                    "Access to container reference {} is blocked by location/prefix configuration for registry {}",
                    this,
                    effectiveRef);
            return true;
        }

        // Check containers policy. Strip a trailing ":tag" and/or "@digest" without touching a
        // "host:port" registry (the tag colon always follows the last "/").
        String scope = effectiveRef.toString().replaceFirst("(:[^/@]+)?(@[^/]+)?$", "");
        boolean allowed = registry.getContainersPolicy().isAllowed(Transport.DOCKER, scope);
        if (!allowed) {
            throw new OrasException("Image '%s' rejected by containers policy".formatted(this));
        }

        return false;
    }

    /**
     * Check if this container reference is allowed (not blocked by registry configuration or policy)
     * @param registry The registry
     * @throws OrasException if access to this container reference is blocked by the registry configuration or policy
     */
    ContainerRef checkBlocked(Registry registry) throws OrasException {
        // Check registry configuration (blocked registries)
        if (isBlocked(registry)) {
            throw new OrasException(
                    "Access to container reference %s is blocked by registry configuration".formatted(this));
        }
        return this;
    }

    @Override
    public ContainerRef forTarget(String target) {
        return forRegistry(target);
    }

    @Override
    public ContainerRef forTarget(OCI<ContainerRef> target) {
        return forRegistry((Registry) target);
    }

    @Override
    public String getTarget(OCI<ContainerRef> target) {
        return getEffectiveRegistry((Registry) target);
    }

    /**
     * Return a copy of reference for a registry other registry
     * @param registry The registry
     * @return The container reference
     */
    public ContainerRef forRegistry(Registry registry) {
        if (isUnqualified() && registry.getRegistry() == null) {
            String key = registry.getRegistriesConf().getAliasKey(this);
            if (registry.getRegistry() == null && registry.getRegistriesConf().hasAlias(key)) {
                String newLocation = registry.getRegistriesConf().getAliases().get(key);
                String newRefString = "%s:%s".formatted(newLocation, tag);
                LOG.debug("Using {} as an alias to {}", key, newRefString);
                return ContainerRef.parse(newRefString);
            }
            LOG.debug(
                    "The container reference {} was created without a registry. Will try to resolve using unqualified-search-registries in order",
                    this);
            return new ContainerRef(
                    determineFirstUnqualifiedSearchRegistry(registry), false, namespace, repository, tag, digest);
        }
        if (registry.getRegistry() == null) {
            return registry.getRegistriesConf().rewrite(this);
        }
        return new ContainerRef(
                registry.getRegistry(),
                false, // not unqualified if registry is set
                namespace,
                repository,
                tag,
                digest);
    }

    private String determineFirstUnqualifiedSearchRegistry(Registry registry) {
        // No settings, keep old behavior of defaulting to docker.io for unqualified reference
        if (registry.getRegistriesConf().getUnqualifiedRegistries().isEmpty()) {
            return Const.DEFAULT_REGISTRY;
        }
        LOG.debug(
                "Found registries in unqualified-search-registries: {}",
                registry.getRegistriesConf().getUnqualifiedRegistries());
        registry.getRegistriesConf().enforceShortNameMode();
        List<String> unqualifiedRegistries = registry.getRegistriesConf().getUnqualifiedRegistries();
        for (String searchRegistry : unqualifiedRegistries) {
            Registry targetRegistry = registry.copy(searchRegistry);
            LOG.debug("Checking if container {} exists in unqualified search registry {}", this, searchRegistry);
            if (targetRegistry.exists(this)) {
                LOG.debug("Found container {} in unqualified search registry {}", this, searchRegistry);
                return searchRegistry;
            }
            LOG.debug("Container {} does not exist in unqualified search registry {}", this, searchRegistry);
        }
        throw new OrasException(
                "Container reference %s is unqualified and cannot be found in any of the unqualified search registries: %s"
                        .formatted(this, registry.getRegistriesConf().getUnqualifiedRegistries()));
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        ContainerRef that = (ContainerRef) o;
        return Objects.equals(getRegistry(), that.getRegistry())
                && Objects.equals(getRepository(), that.getRepository())
                && Objects.equals(getNamespace(), that.getNamespace())
                && Objects.equals(getDigest(), that.getDigest())
                && Objects.equals(getTag(), that.getTag());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getRegistry(), getRepository(), getNamespace(), getDigest(), getTag());
    }

    @Override
    public String toString() {
        String ref = digest != null ? "@" + digest : (tag != null ? ":" + tag : "");

        if (isUnqualified()) {
            if (namespace != null && !namespace.isEmpty()) {
                return "%s/%s%s".formatted(namespace, repository, ref);
            }
            return "%s%s".formatted(repository, ref);
        }

        if (namespace != null && !namespace.isEmpty()) {
            return "%s/%s/%s%s".formatted(registry, namespace, repository, ref);
        }
        return "%s/%s%s".formatted(registry, repository, ref);
    }
}
