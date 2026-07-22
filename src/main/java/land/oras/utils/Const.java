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

package land.oras.utils;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import org.jspecify.annotations.NullMarked;

/**
 * Constants used in the SDK.
 */
@NullMarked
public final class Const {

    /**
     * Hidden constructor
     */
    private Const() {
        // Private constructor
    }

    /**
     * JSON property for media type
     */
    public static final String JSON_PROPERTY_MEDIA_TYPE = "mediaType";

    /**
     * JSON property for artifact type
     */
    public static final String JSON_PROPERTY_ARTIFACT_TYPE = "artifactType";

    /**
     * JSON property for schema version
     */
    public static final String JSON_PROPERTY_SCHEMA_VERSION = "schemaVersion";

    /**
     * JSON property for subject
     */
    public static final String JSON_PROPERTY_SUBJECT = "subject";

    /**
     * JSON property for config
     */
    public static final String JSON_PROPERTY_CONFIG = "config";

    /**
     * JSON property for layers
     */
    public static final String JSON_PROPERTY_LAYERS = "layers";

    /**
     * JSON property for digest
     */
    public static final String JSON_PROPERTY_DIGEST = "digest";

    /**
     * JSON property for size
     */
    public static final String JSON_PROPERTY_SIZE = "size";

    /**
     * JSON property for annotations
     */
    public static final String JSON_PROPERTY_ANNOTATIONS = "annotations";

    /**
     * JSON property for platform
     */
    public static final String JSON_PROPERTY_PLATFORM = "platform";

    /**
     * JSON property for manifests
     */
    public static final String JSON_PROPERTY_MANIFESTS = "manifests";

    /**
     * JSON property for data (base64 encoded)
     */
    public static final String JSON_PROPERTY_DATA = "data";

    /**
     * Default registry when no unqualified-search-registries is set in the config
     */
    public static final String DEFAULT_REGISTRY = "docker.io";

    /**
     * Last query param for tag iteration
     */
    public static final String QUERY_PARAM_LAST = "last";

    /**
     * The N query param
     */
    public static final String QUERY_PARAM_N = "n";

    /**
     * Default tag
     */
    public static final String DEFAULT_TAG = "latest";

    /**
     * Index file in OCI layout
     */
    public static final String OCI_LAYOUT_INDEX = "index.json";

    /**
     * Layout folder in OCI layout
     */
    public static final String OCI_LAYOUT_FILE = "oci-layout";

    /**
     * Blobs folder in OCI layout
     */
    public static final String OCI_LAYOUT_BLOBS = "blobs";

    /**
     * The default blob directory media type
     */
    public static final String DEFAULT_BLOB_DIR_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip";

    /**
     * The blob directory media type for zstd compression
     */
    public static final String BLOB_DIR_ZSTD_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar+zstd";

    /**
     * Zip media type
     */
    public static final String ZIP_MEDIA_TYPE = "application/zip";

    /**
     * The default artifact media type if not specified
     */
    public static final String DEFAULT_ARTIFACT_MEDIA_TYPE = "application/vnd.unknown.artifact.v1";

    /**
     * The default blob media type if file type cannot be determined
     */
    public static final String DEFAULT_BLOB_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar";

    /**
     * The default descriptor media type
     */
    public static final String DEFAULT_DESCRIPTOR_MEDIA_TYPE = "application/octet-stream";

    /**
     * The default JSON media type
     */
    public static final String DEFAULT_JSON_MEDIA_TYPE = "application/json";

    /**
     * The default empty media type
     */
    public static final String DEFAULT_EMPTY_MEDIA_TYPE = "application/vnd.oci.empty.v1+json";

    /**
     * Default index media type
     */
    public static final String DEFAULT_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json";

    /**
     * Legacy manifest media type for Docker distribution manifest v1, which is a JWS (JSON Web Signature) format and is not widely used anymore, but some registries may still support it for backward compatibility
     * Ensure to raise a proper error message when we encounter this media type, as it is not supported by the SDK
     */
    public static final String LEGACY_MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v1+prettyjws";

    /**
     * The artifact manifest media type
     */
    public static final String ARTIFACT_MANIFEST_MEDIA_TYPE = "application/vnd.oci.artifact.manifest.v1+json";

    /**
     * Docker distribution manifest type
     */
    public static final String DOCKER_MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json";

    /**
     * Docker index media type (manifest list or fat manifest)
     */
    public static final String DOCKER_INDEX_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.list.v2+json";

    /**
     * The default manifest media type
     */
    public static final String DEFAULT_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json";

    /**
     * Media type for config of running container
     */
    public static final String CONFIG_RUNNING_CONTAINER_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json";

    /**
     * Media type for config of running docker
     */
    public static final String CONFIG_RUNNING_DOCKER_MEDIA_TYPE = "application/vnd.docker.container.image.v1+json";

    /**
     * The default accept type for the manifest
     */
    public static final String MANIFEST_ACCEPT_TYPE = "%s, %s, %s, %s, %s"
            .formatted(
                    DEFAULT_INDEX_MEDIA_TYPE,
                    DEFAULT_MANIFEST_MEDIA_TYPE,
                    ARTIFACT_MANIFEST_MEDIA_TYPE,
                    DOCKER_INDEX_MEDIA_TYPE,
                    DOCKER_MANIFEST_MEDIA_TYPE);

    /**
     * Annotation for the title
     */
    public static final String ANNOTATION_TITLE = "org.opencontainers.image.title";

    /**
     * Annotation for the description
     */
    public static final String ANNOTATION_DESCRIPTION = "org.opencontainers.image.description";

    /**
     * Annotation for the crated date
     */
    public static final String ANNOTATION_CREATED = "org.opencontainers.image.created";

    /**
     * Annotation for the ref name
     */
    public static final String ANNOTATION_REF = "org.opencontainers.image.ref.name";

    /**
     * Annotation for the source
     */
    public static final String ANNOTATION_SOURCE = "org.opencontainers.image.source";

    /**
     * Annotation for the revision
     */
    public static final String ANNOTATION_REVISION = "org.opencontainers.image.revision";

    /**
     * Annotation for the base image name
     */
    public static final String ANNOTATION_IMAGE_BASE_NAME = "org.opencontainers.image.base.name";

    /**
     * Annotation for the image URL
     */
    public static final String ANNOTATION_IMAGE_URL = "org.opencontainers.image.url";

    /**
     * Annotation for the image version
     */
    public static final String ANNOTATION_IMAGE_VERSION = "org.opencontainers.image.version";

    /**
     * The platform OS key
     */
    public static final String PLATFORM_OS = "os";

    /**
     * The platform architecture key
     */
    public static final String PLATFORM_ARCHITECTURE = "architecture";

    /**
     * The platform variant key, which can be used in the annotation "variant" to specify the variant of the architecture, such as armv7 or armv8
     */
    public static final String PLATFORM_VARIANT = "variant";

    /**
     * The platform OS version key, which can be used in the annotation "os.version" to specify the version of the OS, such as ubuntu 20.04 or alpine 3.14
     */
    public static final String PLATFORM_OS_VERSION = "os.version";

    /**
     * The platform OS features key, which can be used in the annotation "os.features" to specify the features of the OS, such as sse4 or aes
     */
    public static final String PLATFORM_OS_FEATURES = "os.features";

    /**
     * The platform features key, which can be used in the annotation "features" to specify the features of the platform, such as gpu or fpga
     */
    public static final String PLATFORM_FEATURES = "features";

    /**
     * The default value for unknown platform information
     */
    public static final String PLATFORM_UNKNOWN = "unknown";

    /**
     * The platform value for linux os
     */
    public static final String PLATFORM_LINUX = "linux";

    /**
     * The platform value for windows OS
     */
    public static final String PLATFORM_WINDOWS = "windows";

    /**
     * The platform value for amd64 architecture
     */
    public static final String PLATFORM_ARCHITECTURE_AMD64 = "amd64";

    /**
     * The platform value for 386 architecture
     */
    public static final String PLATFORM_ARCHITECTURE_386 = "386";

    /**
     * The platform value for arm architecture
     */
    public static final String PLATFORM_ARCHITECTURE_ARM = "arm";

    /**
     * The platform value for arm64 architecture
     */
    public static final String PLATFORM_ARCHITECTURE_ARM64 = "arm64";

    /**
     * The platform value for ppc64le architecture
     */
    public static final String PLATFORM_ARCHITECTURE_PPC64LE = "ppc64le";

    /**
     * The platform value for riscv64 architecture
     */
    public static final String PLATFORM_ARCHITECTURE_RISCV64 = "riscv64";

    /**
     * The platform value for s390x architecture
     */
    public static final String PLATFORM_ARCHITECTURE_S390X = "s390x";

    /**
     * The v5 variant for arm architecture, which can be used in the annotation "variant" to specify the variant of the arm architecture
     */
    public static final String VARIANT_V5 = "v5";

    /**
     * The v6 variant for arm architecture, which can be used in the annotation "variant" to specify the variant of the arm architecture
     */
    public static final String VARIANT_V6 = "v6";

    /**
     * The v7 variant for arm architecture, which can be used in the annotation "variant" to specify the variant of the arm architecture
     */
    public static final String VARIANT_V7 = "v7";

    /**
     * The v8 variant for arm architecture, which can be used in the annotation "variant" to specify the variant of the arm architecture
     */
    public static final String VARIANT_V8 = "v8";

    /**
     * Get the current timestamp for the created annotation
     * @return The current timestamp
     */
    public static String currentTimestamp() {
        return Instant.now()
                .truncatedTo(java.time.temporal.ChronoUnit.SECONDS)
                .atOffset(ZoneOffset.UTC)
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
    }

    /**
     * Annotation of the uncompressed dir content
     */
    public static final String ANNOTATION_ORAS_CONTENT_DIGEST = "io.deis.oras.content.digest";

    /**
     * Annotation to unpack the content
     */
    public static final String ANNOTATION_ORAS_UNPACK = "io.deis.oras.content.unpack";

    /**
     * Authorization header
     */
    public static final String AUTHORIZATION_HEADER = "Authorization";

    /**
     * Link header, which is used for pagination in the registry API
     */
    public static final String LINK_HEADER = "Link";

    /**
     * User agent header
     */
    public static final String USER_AGENT_HEADER = "User-Agent";

    /**
     * Content type header
     */
    public static final String CONTENT_TYPE_HEADER = "Content-Type";

    /**
     * Content length header
     */
    public static final String CONTENT_LENGTH_HEADER = "Content-Length";

    /**
     * The Docker content digest header
     */
    public static final String DOCKER_CONTENT_DIGEST_HEADER = "Docker-Content-Digest";

    /**
     * OCI subject header
     */
    public static final String OCI_SUBJECT_HEADER = "OCI-Subject";

    /**
     * Accept header
     */
    public static final String ACCEPT_HEADER = "Accept";

    /**
     * Location header
     */
    public static final String LOCATION_HEADER = "Location";

    /**
     * WWW-Authenticate header
     */
    public static final String WWW_AUTHENTICATE_HEADER = "WWW-Authenticate";

    /**
     * Application octet stream header value
     */
    public static final String APPLICATION_OCTET_STREAM_HEADER_VALUE = "application/octet-stream";

    /**
     * Content Range header
     */
    public static final String CONTENT_RANGE_HEADER = "Content-Range";

    /**
     * Range header
     */
    public static final String RANGE_HEADER = "Range";

    /**
     * OCI Chunk Minimum Length header
     */
    public static final String OCI_CHUNK_MIN_LENGTH_HEADER = "OCI-Chunk-Min-Length";

    /**
     * Metric name for token refresh counter
     */
    public static final String METRIC_TOKEN_REFRESH = "land.oras.auth.token.refresh";

    /**
     * Metric name for HTTP request
     */
    public static final String METRIC_HTTP_REQUESTS = "land.oras.http.client.requests";

    /**
     * Metric name for HTTP retries
     */
    public static final String METRIC_HTTP_RETRIES = "land.oras.http.client.retries";

    /**
     * Metric name for token refresh duration
     */
    public static final String METRIC_TAG_SERVICE = "service";

    /**
     * Metric name for token refresh duration
     */
    public static final String METRIC_TAG_REALM = "realm";

    /**
     * Flux CD config media type
     */
    public static final String FLUX_CD_CONFIG_MEDIA_TYPE = "application/vnd.cncf.flux.config.v1+json";

    /**
     * Flux CD content media type
     */
    public static final String FLUX_CD_CONTENT_MEDIA_TYPE = "application/vnd.cncf.flux.content.v1.tar+gzip";

    /**
     * Helm config media type
     */
    public static final String HELM_CONFIG_MEDIA_TYPE = "application/vnd.cncf.helm.config.v1+json";

    /**
     * Helm content media type
     */
    public static final String HELM_CONTENT_MEDIA_TYPE = "application/vnd.cncf.helm.chart.content.v1.tar+gzip";

    /**
     * Sigstore bundle media type, used both as the referrer {@code artifactType} and as the layer
     * media type of an attached Sigstore signature (the format produced by recent
     * {@code cosign sign} with the new bundle format).
     */
    public static final String SIGSTORE_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json";

    /**
     * The payload type used inside a Sigstore DSSE envelope: an in-toto statement.
     */
    public static final String IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";

    /**
     * Annotation describing the content of a Sigstore bundle (e.g. {@code dsse-envelope}).
     */
    public static final String ANNOTATION_SIGSTORE_BUNDLE_CONTENT = "dev.sigstore.bundle.content";

    /**
     * Annotation value for {@link #ANNOTATION_SIGSTORE_BUNDLE_CONTENT} indicating the bundle wraps
     * a DSSE envelope.
     */
    public static final String SIGSTORE_BUNDLE_CONTENT_DSSE = "dsse-envelope";

    /**
     * Annotation describing the predicate type of a Sigstore bundle (e.g.
     * {@code https://sigstore.dev/cosign/sign/v1}).
     */
    public static final String ANNOTATION_SIGSTORE_BUNDLE_PREDICATE_TYPE = "dev.sigstore.bundle.predicateType";

    /**
     * The only supported key algorithm for now
     */
    public static final String KEY_EC_ALGORITHM = "EC";

    /**
     * The full signature algorithm
     */
    public static final String KEY_SHA256_ECDSA_SIGNATURE_ALGORITHM = "SHA256withECDSA";
}
