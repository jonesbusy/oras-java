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

package land.oras.policy;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import java.security.PublicKey;
import java.util.List;
import land.oras.OrasModel;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A single requirement entry inside a containers policy scope.
 */
@NullMarked
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(
            value = PolicyRequirement.InsecureAcceptAnything.class,
            name = PolicyRequirement.InsecureAcceptAnything.TYPE),
    @JsonSubTypes.Type(value = PolicyRequirement.Reject.class, name = PolicyRequirement.Reject.TYPE),
    @JsonSubTypes.Type(value = PolicyRequirement.SignedBy.class, name = PolicyRequirement.SignedBy.TYPE),
    @JsonSubTypes.Type(value = PolicyRequirement.SigstoreSigned.class, name = PolicyRequirement.SigstoreSigned.TYPE),
})
@OrasModel
public abstract sealed class PolicyRequirement
        permits PolicyRequirement.InsecureAcceptAnything,
                PolicyRequirement.Reject,
                PolicyRequirement.SignedBy,
                PolicyRequirement.SigstoreSigned {

    /**
     * Private constructor
     */
    PolicyRequirement() {}

    /**
     * Return the type name of this requirement as it appears in the policy JSON.
     *
     * @return the type string, e.g. {@code "insecureAcceptAnything"}.
     */
    public abstract String getType();

    /**
     * Verify this requirement against the given {@link PolicyContext}.
     *
     * <p>The context may be <em>content-free</em> ({@link PolicyContext#hasContent()} is {@code false}),
     * which is the lightweight scope gate used by {@link ContainersPolicy#isAllowed(Transport, String)} on
     * any operation (including push). Signature-based requirements cannot be enforced in that case and
     * should allow the operation to proceed; their cryptographic check runs only once the image has
     * been resolved during a pull, when the context carries the digest and a {@link SigstoreSignatureFetcher}.
     *
     * @param context the policy context.
     * @return {@code true} if the requirement passes, {@code false} otherwise.
     */
    abstract boolean verify(PolicyContext context);

    @Override
    public String toString() {
        return getType();
    }

    /**
     * Accept any image unconditionally – no signature or digest verification is performed.
     *
     * <p>JSON example:
     * <pre>{@code {"type": "insecureAcceptAnything"}}</pre>
     */
    @OrasModel
    public static final class InsecureAcceptAnything extends PolicyRequirement {

        /**
         * The {@code "type"} value of this requirement in the policy JSON.
         */
        public static final String TYPE = "insecureAcceptAnything";

        /**
         * Logger
         */
        private static final Logger LOG = LoggerFactory.getLogger(InsecureAcceptAnything.class);

        /**
         * Constructor
         */
        public InsecureAcceptAnything() {}

        @Override
        public String getType() {
            return TYPE;
        }

        @Override
        boolean verify(PolicyContext context) {
            LOG.warn(
                    "Policy requirement '{}' for transport {} and scope {} (no signature verification)",
                    getType(),
                    context.getTransport(),
                    context.getScope());
            return true;
        }
    }

    /**
     * Reject every image unconditionally.
     *
     * <p>JSON example:
     * <pre>{@code {"type": "reject"}}</pre>
     */
    @OrasModel
    public static final class Reject extends PolicyRequirement {

        /**
         * The {@code "type"} value of this requirement in the policy JSON.
         */
        public static final String TYPE = "reject";

        /**
         * Logger
         */
        private static final Logger LOG = LoggerFactory.getLogger(Reject.class);

        /**
         * Constructor
         */
        public Reject() {}

        @Override
        public String getType() {
            return TYPE;
        }

        @Override
        boolean verify(PolicyContext context) {
            LOG.debug(
                    "Policy requirement '{}' for transport {} and scope {}",
                    getType(),
                    context.getTransport(),
                    context.getScope());
            return false;
        }
    }

    /**
     * Require a GPG "simple signing" signature.
     * Not supported. Legacy replaced by cosign/Sigstore
     */
    @OrasModel
    public static final class SignedBy extends PolicyRequirement {

        /**
         * The {@code "type"} value of this requirement in the policy JSON.
         */
        public static final String TYPE = "signedBy";

        /**
         * Logger
         */
        private static final Logger LOG = LoggerFactory.getLogger(SignedBy.class);

        /**
         * Constructor. Any JSON fields on a {@code signedBy} requirement are ignored.
         */
        public SignedBy() {}

        @Override
        public String getType() {
            return TYPE;
        }

        @Override
        boolean verify(PolicyContext context) {
            if (context.hasContent()) {
                LOG.warn(
                        "Policy requirement '{}' (GPG) is not implemented. Rejecting {}",
                        getType(),
                        context.getReference());
            }
            return false;
        }
    }

    /**
     * Require a valid keyed Sigstore/Cosign signature attached to the image as an OCI referrer.
     *
     * <p>Exactly one of {@code keyPath}, {@code keyPaths}, {@code keyData}, or {@code keyDatas} must
     * be present; keyless verification is not supported.
     *
     * <ul>
     *   <li>{@code keyPath} / {@code keyData} – a single Sigstore public key; only signatures made
     *       by this key are accepted.</li>
     *   <li>{@code keyPaths} / {@code keyDatas} – a list of Sigstore public keys; signatures made
     *       by <em>any</em> key in the list are accepted.</li>
     * </ul>
     *
     * <p>JSON examples ({@code signedIdentity}, if present, is ignored):
     * <pre>{@code
     * {"type": "sigstoreSigned", "keyPath": "/etc/pki/containers/cosign.pub"}
     * {"type": "sigstoreSigned", "keyPaths": ["/etc/pki/a.pub", "/etc/pki/b.pub"]}
     * {"type": "sigstoreSigned", "keyDatas": ["<base64-pem>", "<base64-pem>"]}
     * }</pre>
     */
    @OrasModel
    public static final class SigstoreSigned extends PolicyRequirement {

        /**
         * The {@code "type"} value of this requirement in the policy JSON.
         */
        public static final String TYPE = "sigstoreSigned";

        /**
         * Logger
         */
        private static final Logger LOG = LoggerFactory.getLogger(SigstoreSigned.class);

        private final @Nullable String keyPath;
        private final @Nullable String keyData;
        private final @Nullable List<String> keyPaths;
        private final @Nullable List<String> keyDatas;

        /**
         * Creates a new {@link SigstoreSigned} requirement.
         *
         * @param keyPath  path to a single Sigstore/Cosign public key file.
         * @param keyData  base64-encoded single Sigstore/Cosign public key.
         * @param keyPaths list of paths to Sigstore/Cosign public key files.
         * @param keyDatas list of base64-encoded Sigstore/Cosign public keys.
         */
        @JsonCreator
        public SigstoreSigned(
                @JsonProperty("keyPath") @Nullable String keyPath,
                @JsonProperty("keyData") @Nullable String keyData,
                @JsonProperty("keyPaths") @Nullable List<String> keyPaths,
                @JsonProperty("keyDatas") @Nullable List<String> keyDatas) {
            this.keyPath = keyPath;
            this.keyData = keyData;
            this.keyPaths = keyPaths;
            this.keyDatas = keyDatas;
        }

        /**
         * Convenience constructor for a single key (backward compatibility).
         *
         * @param keyPath path to a Sigstore/Cosign public key file (mutually exclusive with {@code keyData}).
         * @param keyData base64-encoded Sigstore/Cosign public key (mutually exclusive with {@code keyPath}).
         */
        public SigstoreSigned(@Nullable String keyPath, @Nullable String keyData) {
            this(keyPath, keyData, null, null);
        }

        @Override
        public String getType() {
            return TYPE;
        }

        @Override
        boolean verify(PolicyContext context) {
            String imageDigest = context.getImageDigest();
            if (imageDigest == null) {
                LOG.debug(
                        "Policy requirement '{}' deferred to content verification for transport {} and scope {}",
                        getType(),
                        context.getTransport(),
                        context.getScope());
                return true;
            }
            if (keyPath == null && keyData == null && keyPaths == null && keyDatas == null) {
                LOG.warn(
                        "Policy requirement '{}' for {} has no keyPath, keyPaths, keyData, or keyDatas "
                                + "(keyless verification is not supported); rejecting",
                        getType(),
                        context.getReference());
                return false;
            }
            List<PublicKey> keys = SigstoreVerifier.loadKeys(this);
            if (keys.isEmpty()) {
                LOG.warn(
                        "Policy requirement '{}' for {} could not load any configured public key; rejecting",
                        getType(),
                        context.getReference());
                return false;
            }
            List<byte[]> bundles = context.fetchSignatureBundle();
            boolean verified = SigstoreVerifier.verifyWithAnyKey(bundles, imageDigest, keys);
            if (!verified) {
                LOG.warn(
                        "Policy requirement '{}' failed: no valid signature for {}", getType(), context.getReference());
            }
            return verified;
        }

        /**
         * Return the path to the Sigstore/Cosign public key file, or {@code null} if not set.
         *
         * @return the key path, may be {@code null}.
         */
        public @Nullable String getKeyPath() {
            return keyPath;
        }

        /**
         * Return the base64-encoded Sigstore/Cosign public key, or {@code null} if not set.
         *
         * @return the key data, may be {@code null}.
         */
        public @Nullable String getKeyData() {
            return keyData;
        }

        /**
         * Return the list of paths to Sigstore/Cosign public key files, or {@code null} if not set.
         *
         * @return the key paths list, may be {@code null}.
         */
        public @Nullable List<String> getKeyPaths() {
            return keyPaths;
        }

        /**
         * Return the list of base64-encoded Sigstore/Cosign public keys, or {@code null} if not set.
         *
         * @return the key datas list, may be {@code null}.
         */
        public @Nullable List<String> getKeyDatas() {
            return keyDatas;
        }
    }
}
