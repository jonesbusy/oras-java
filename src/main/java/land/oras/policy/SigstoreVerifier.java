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

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import land.oras.OrasModel;
import land.oras.exception.OrasException;
import land.oras.utils.Const;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/**
 * Verifies keyed <a href="https://docs.sigstore.dev/about/bundle/">Sigstore bundles</a> attached to
 * an OCI image as referrers, using only the JDK's native cryptography (no Sigstore/BouncyCastle
 * dependency).
 *
 * <p>This implements the <em>keyed</em> verification path used by {@code cosign sign --key} with the
 * new bundle format ({@code application/vnd.dev.sigstore.bundle.v0.3+json}). The bundle wraps a
 * <a href="https://github.com/secure-systems-lab/dsse">DSSE</a> envelope whose payload is an in-toto
 * statement binding the signed image digest. Verification performs two checks:
 *
 * <ol>
 *   <li>The DSSE signature over the
 *       <a href="https://github.com/secure-systems-lab/dsse/blob/master/protocol.md">PAE</a>-encoded
 *       payload validates against one of the configured public keys (ECDSA/SHA-256).</li>
 *   <li>The in-toto statement {@code subject[].digest.sha256} matches the image digest being
 *       pulled.</li>
 * </ol>
 *
 * <p><strong>Out of scope</strong> (intentionally not verified here): Rekor transparency-log
 * inclusion proofs and RFC&nbsp;3161 timestamps. Those require the Sigstore trust root and are only
 * relevant to keyless verification; when you trust a public key directly, the DSSE signature is the
 * trust boundary.
 *
 * @see PolicyRequirement.SigstoreSigned
 */
@NullMarked
final class SigstoreVerifier {

    /**
     * Logger
     */
    private static final Logger LOG = LoggerFactory.getLogger(SigstoreVerifier.class);

    /**
     * The JSON mapper for parsing Sigstore bundles and in-toto statements.
     */
    private static final ObjectMapper MAPPER = JsonMapper.builder().build();

    /**
     * DSSE prefix as byte
     */
    private static final byte[] DSSE_PREFIX = "DSSEv1".getBytes(StandardCharsets.UTF_8);

    /**
     * Private constructor
     */
    private SigstoreVerifier() {}

    /**
     * Verify that at least one of the given Sigstore bundles is a valid signature, made by the trusted
     * key, over the given image digest.
     *
     * @param bundles     the raw bundle blob bytes fetched from the registry (one per referrer).
     * @param imageDigest the full image digest being pulled, e.g. {@code "sha256:abc..."}.
     * @param trustedKey  the public key configured in the policy requirement.
     * @return {@code true} if at least one bundle verifies and binds to {@code imageDigest}.
     */
    static boolean verify(List<byte[]> bundles, String imageDigest, PublicKey trustedKey) {
        return verifyWithAnyKey(bundles, imageDigest, List.of(trustedKey));
    }

    /**
     * Verify that at least one of the given Sigstore bundles is a valid signature, made by
     * <em>any</em> of the trusted keys, over the given image digest.
     *
     * @param bundles     the raw bundle blob bytes fetched from the registry (one per referrer).
     * @param imageDigest the full image digest being pulled, e.g. {@code "sha256:abc..."}.
     * @param trustedKeys the list of public keys configured in the policy requirement.
     * @return {@code true} if at least one bundle verifies and binds to {@code imageDigest}.
     */
    static boolean verifyWithAnyKey(List<byte[]> bundles, String imageDigest, List<PublicKey> trustedKeys) {
        if (bundles.isEmpty()) {
            LOG.debug("No Sigstore bundles attached to image {}", imageDigest);
            return false;
        }
        for (byte[] bundle : bundles) {
            for (PublicKey key : trustedKeys) {
                if (verifyBundle(bundle, imageDigest, key)) {
                    return true;
                }
            }
        }
        LOG.debug("No attached Sigstore bundle verified for artifact with digest {}", imageDigest);
        return false;
    }

    /**
     * Verify a single Sigstore bundle against the image digest and the trusted key.
     *
     * @param bundleBytes the raw bundle JSON bytes.
     * @param imageDigest the full image digest, e.g. {@code "sha256:abc..."}.
     * @param trustedKey  the trusted public key.
     * @return {@code true} if the bundle is a valid signature binding {@code imageDigest}.
     */
    static boolean verifyBundle(byte[] bundleBytes, String imageDigest, PublicKey trustedKey) {
        Bundle bundle;
        try {
            bundle = MAPPER.readValue(bundleBytes, Bundle.class);
        } catch (Exception e) {
            LOG.warn("Failed to parse Sigstore bundle: {}", e.getMessage());
            return false;
        }
        DsseEnvelope envelope = bundle.dsseEnvelope();
        if (envelope == null || envelope.payload() == null || envelope.signatures() == null) {
            LOG.warn("Sigstore bundle does not contain a DSSE envelope with a payload and signatures");
            return false;
        }

        byte[] payload;
        try {
            payload = Base64.getDecoder().decode(envelope.payload());
        } catch (IllegalArgumentException e) {
            LOG.warn("Sigstore bundle payload is not valid base64");
            return false;
        }

        // The in-toto statement subject digest must match the image being pulled.
        if (!digestMatches(payload, imageDigest)) {
            LOG.warn("Sigstore bundle subject digest does not match image digest {}", imageDigest);
            return false;
        }

        // The DSSE signature over PAE(payloadType, payload) must validate against the trusted key.
        String payloadType = envelope.payloadType() != null ? envelope.payloadType() : "";
        byte[] pae = preAuthEncoding(payloadType, payload);
        for (DsseSignature sig : envelope.signatures()) {
            if (sig.sig() == null) {
                continue;
            }
            byte[] signature = Base64.getDecoder().decode(sig.sig());
            if (verifySignature(trustedKey, pae, signature)) {
                LOG.debug("Sigstore bundle verified for image {}", imageDigest);
                return true;
            }
        }
        LOG.debug("Sigstore bundle DSSE signature did not verify for image {}", imageDigest);
        return false;
    }

    /**
     * Check whether the in-toto statement carried in the DSSE payload references the given image
     * digest in one of its subjects.
     */
    private static boolean digestMatches(byte[] payload, String imageDigest) {
        InTotoStatement statement = MAPPER.readValue(payload, InTotoStatement.class);
        if (statement.subject() == null) {
            LOG.warn("Sigstore bundle in-toto statement does not contain any subjects");
            return false;
        }

        // The statement stores it as {"<algo>": "<hex>"}.
        int colon = imageDigest.indexOf(':');
        String algo = imageDigest.substring(0, colon);
        String hex = imageDigest.substring(colon + 1);
        for (Subject subject : statement.subject()) {
            Map<String, String> digest = subject.digest();
            if (digest != null && hex.equals(digest.get(algo))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Verify an ECDSA (or RSA / EdDSA) signature over the given content with the given public key.
     * The signature scheme is selected from the key algorithm; cosign's default is EC P-256, which
     * uses {@code SHA256withECDSA}.
     */
    private static boolean verifySignature(PublicKey key, byte[] content, byte[] signature) {
        // Might support other algorithm in the future
        String algorithm =
                switch (key.getAlgorithm()) {
                    case Const.KEY_EC_ALGORITHM -> Const.KEY_SHA256_ECDSA_SIGNATURE_ALGORITHM;
                    default -> null;
                };
        if (algorithm == null) {
            LOG.warn("Unsupported public key algorithm for Sigstore verification: {}", key.getAlgorithm());
            return false;
        }
        try {
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(key);
            verifier.update(content);
            return verifier.verify(signature);
        } catch (Exception e) {
            LOG.debug("Signature verification failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Compute the DSSE Pre-Authentication Encoding (PAE) of a payload:
     *
     * <pre>{@code PAE = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body}</pre>
     *
     * where {@code LEN} is the ASCII-decimal byte length and {@code SP} is a single space.
     */
    static byte[] preAuthEncoding(String payloadType, byte[] payload) {
        byte[] typeBytes = payloadType.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(DSSE_PREFIX);
            out.write(' ');
            out.write(Integer.toString(typeBytes.length).getBytes(StandardCharsets.UTF_8));
            out.write(' ');
            out.write(typeBytes);
            out.write(' ');
            out.write(Integer.toString(payload.length).getBytes(StandardCharsets.UTF_8));
            out.write(' ');
            out.write(payload);
        } catch (IOException e) {
            throw new OrasException("Failed to compute DSSE pre-auth encoding", e);
        }
        return out.toByteArray();
    }

    /**
     * Load the single public key configured on a {@link PolicyRequirement.SigstoreSigned} requirement
     * from its {@code keyPath} or {@code keyData} field ({@code keyPath} takes precedence).
     *
     * @param requirement the policy requirement.
     * @return the parsed public key, or {@code null} if none is configured or it cannot be parsed.
     */
    static @Nullable PublicKey loadKey(PolicyRequirement.SigstoreSigned requirement) {
        String keyPath = requirement.getKeyPath();
        if (keyPath != null) {
            return loadKeyFromPath(keyPath);
        }
        String keyData = requirement.getKeyData();
        if (keyData != null) {
            return loadKeyFromData(keyData);
        }
        return null;
    }

    /**
     * Load all public keys configured on a {@link PolicyRequirement.SigstoreSigned} requirement.
     * Considers {@code keyPath}, {@code keyData}, {@code keyPaths}, and {@code keyDatas}.
     * Keys that fail to load are skipped with a warning.
     *
     * @param requirement the policy requirement.
     * @return a non-null (possibly empty) list of successfully loaded public keys.
     */
    static List<PublicKey> loadKeys(PolicyRequirement.SigstoreSigned requirement) {
        java.util.List<PublicKey> keys = new java.util.ArrayList<>();

        // Single-key fields
        PublicKey single = loadKey(requirement);
        if (single != null) {
            keys.add(single);
        }

        // keyPaths list
        List<String> keyPaths = requirement.getKeyPaths();
        if (keyPaths != null) {
            for (String path : keyPaths) {
                PublicKey k = loadKeyFromPath(path);
                if (k != null) {
                    keys.add(k);
                } else {
                    LOG.warn("Failed to load public key from keyPaths entry: {}", path);
                }
            }
        }

        // keyDatas list
        List<String> keyDatas = requirement.getKeyDatas();
        if (keyDatas != null) {
            for (String data : keyDatas) {
                PublicKey k = loadKeyFromData(data);
                if (k != null) {
                    keys.add(k);
                } else {
                    LOG.warn("Failed to load public key from keyDatas entry");
                }
            }
        }

        return keys;
    }

    private static @Nullable PublicKey loadKeyFromPath(String path) {
        String pem;
        try {
            pem = Files.readString(Path.of(path));
        } catch (Exception e) {
            LOG.warn("Failed to read sigstore public key from {}: {}", path, e.getMessage());
            return null;
        }
        return parsePublicKey(pem);
    }

    private static @Nullable PublicKey loadKeyFromData(String data) {
        return parsePublicKey(new String(Base64.getDecoder().decode(data), StandardCharsets.UTF_8));
    }

    /**
     * Parse a PEM-encoded {@code PUBLIC KEY} (PKIX/SubjectPublicKeyInfo) block into a
     * {@link PublicKey}. The encoded algorithm is auto-detected by trying EC, then RSA, then Ed25519.
     *
     * @param pem the PEM document.
     * @return the parsed key, or {@code null} if it cannot be parsed.
     */
    static @Nullable PublicKey parsePublicKey(String pem) {
        String base64 = pem.replaceAll("-----BEGIN [^-]*-----", "")
                .replaceAll("-----END [^-]*-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(base64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        try {
            return KeyFactory.getInstance(Const.KEY_EC_ALGORITHM).generatePublic(spec);
        } catch (Exception e) {
            LOG.warn("Failed to parse public key: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Minimal model of a Sigstore bundle ({@code application/vnd.dev.sigstore.bundle.v0.3+json}).
     * Only the DSSE envelope is modeled; verification material (tlog/timestamps) is ignored.
     */
    @OrasModel
    record Bundle(@JsonProperty("dsseEnvelope") @Nullable DsseEnvelope dsseEnvelope) {}

    /**
     * DSSE envelope containing a base64-encoded payload and one or more signatures.
     * @param payload The payload
     * @param payloadType Type of payload
     * @param signatures List of signatures
     */
    @OrasModel
    record DsseEnvelope(
            @JsonProperty("payload") @Nullable String payload,
            @JsonProperty("payloadType") @Nullable String payloadType,
            @JsonProperty("signatures") @Nullable List<DsseSignature> signatures) {}

    /**
     * A single DSSE signature (base64-encoded, DER for ECDSA)
     * @param sig Signature
     */
    @OrasModel
    record DsseSignature(@JsonProperty("sig") @Nullable String sig) {}

    /**
     * Minimal model of an in-toto statement, capturing only its subjects
     * @param subject The subject
     */
    @OrasModel
    record InTotoStatement(@JsonProperty("subject") @Nullable List<Subject> subject) {}

    /**
     * An in-toto subject: a map of digest algorithm to hex value
     * @param digest The digest
     */
    @OrasModel
    record Subject(@JsonProperty("digest") @Nullable Map<String, String> digest) {}
}
