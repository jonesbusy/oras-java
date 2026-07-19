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

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;
import land.oras.exception.OrasException;
import land.oras.utils.Const;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Tests for {@link SigstoreVerifier}, exercising the full keyed DSSE verification path with
 * EC P-256 keys generated and signed using only the JDK's native cryptography.
 */
@Execution(ExecutionMode.CONCURRENT)
class SigstoreVerifierTest {

    private static final String IMAGE_DIGEST =
            "sha256:0c8c08023a23cfb81a65a895c0b70d41be8e54d52eda6a67c18487cc56ffd45d";
    private static final String IMAGE_HEX = IMAGE_DIGEST.substring("sha256:".length());

    @Test
    void verifiesValidBundleWithMatchingKeyAndDigest() throws Exception {
        KeyPair kp = generateEcKeyPair();
        byte[] bundle = buildBundle(kp.getPrivate(), IMAGE_HEX, Const.KEY_SHA256_ECDSA_SIGNATURE_ALGORITHM);

        assertTrue(SigstoreVerifier.verifyBundle(bundle, IMAGE_DIGEST, kp.getPublic()));
        assertTrue(SigstoreVerifier.verify(List.of(bundle), IMAGE_DIGEST, kp.getPublic()));
    }

    @Test
    void rejectsBundleSignedByDifferentKey() throws Exception {
        KeyPair signing = generateEcKeyPair();
        KeyPair other = generateEcKeyPair();
        byte[] bundle = buildBundle(signing.getPrivate(), IMAGE_HEX, Const.KEY_SHA256_ECDSA_SIGNATURE_ALGORITHM);

        assertFalse(SigstoreVerifier.verifyBundle(bundle, IMAGE_DIGEST, other.getPublic()));
    }

    @Test
    void rejectsBundleWhenDigestDoesNotMatch() throws Exception {
        KeyPair kp = generateEcKeyPair();
        byte[] bundle = buildBundle(kp.getPrivate(), IMAGE_HEX, Const.KEY_SHA256_ECDSA_SIGNATURE_ALGORITHM);

        String otherDigest = "sha256:" + "0".repeat(64);
        assertFalse(SigstoreVerifier.verifyBundle(bundle, otherDigest, kp.getPublic()));
    }

    @Test
    void rejectsBundleWithTamperedPayload() throws Exception {
        KeyPair kp = generateEcKeyPair();
        byte[] payload = inTotoPayload(IMAGE_HEX).getBytes(StandardCharsets.UTF_8);
        byte[] pae = SigstoreVerifier.preAuthEncoding(Const.IN_TOTO_PAYLOAD_TYPE, payload);
        byte[] signature = sign(kp.getPrivate(), pae, Const.KEY_SHA256_ECDSA_SIGNATURE_ALGORITHM);
        byte[] tamperedPayload = (inTotoPayload(IMAGE_HEX) + " ").getBytes(StandardCharsets.UTF_8);
        byte[] bundle = bundleJson(tamperedPayload, signature).getBytes(StandardCharsets.UTF_8);
        assertFalse(SigstoreVerifier.verifyBundle(bundle, IMAGE_DIGEST, kp.getPublic()));
    }

    @Test
    void rejectsWhenNoBundlesAttached() throws Exception {
        KeyPair kp = generateEcKeyPair();
        assertFalse(SigstoreVerifier.verify(List.of(), IMAGE_DIGEST, kp.getPublic()));
    }

    @Test
    void parsesPublicKeyFromPem() throws Exception {
        KeyPair kp = generateEcKeyPair();
        PublicKey parsed = SigstoreVerifier.parsePublicKey(toPem(kp.getPublic()));
        assertNotNull(parsed);
        assertArrayEquals(kp.getPublic().getEncoded(), parsed.getEncoded());
    }

    @Test
    void loadsKeyFromKeyPathAndKeyData(@TempDir Path dir) throws Exception {
        KeyPair kp = generateEcKeyPair();
        String pem = toPem(kp.getPublic());

        Path keyFile = dir.resolve("cosign.pub");
        Files.writeString(keyFile, pem);

        // keyData is the base64-encoded content of the key file.
        String keyData = Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.UTF_8));

        PolicyRequirement.SigstoreSigned fromPath = new PolicyRequirement.SigstoreSigned(keyFile.toString(), null);
        PolicyRequirement.SigstoreSigned fromData = new PolicyRequirement.SigstoreSigned(null, keyData);
        PolicyRequirement.SigstoreSigned none = new PolicyRequirement.SigstoreSigned(null, null);

        assertNotNull(SigstoreVerifier.loadKey(fromPath));
        assertNotNull(SigstoreVerifier.loadKey(fromData));
        assertNull(SigstoreVerifier.loadKey(none));
    }

    @Test
    void loadsKeysFromKeyPathsAndKeyDatas(@TempDir Path dir) throws Exception {
        KeyPair kp1 = generateEcKeyPair();
        KeyPair kp2 = generateEcKeyPair();
        String pem1 = toPem(kp1.getPublic());
        String pem2 = toPem(kp2.getPublic());

        Path keyFile1 = dir.resolve("cosign1.pub");
        Path keyFile2 = dir.resolve("cosign2.pub");
        Files.writeString(keyFile1, pem1);
        Files.writeString(keyFile2, pem2);

        String keyData1 = Base64.getEncoder().encodeToString(pem1.getBytes(StandardCharsets.UTF_8));
        String keyData2 = Base64.getEncoder().encodeToString(pem2.getBytes(StandardCharsets.UTF_8));

        // keyPaths list
        PolicyRequirement.SigstoreSigned fromPaths = new PolicyRequirement.SigstoreSigned(
                null, null, List.of(keyFile1.toString(), keyFile2.toString()), null);
        List<java.security.PublicKey> loadedFromPaths = SigstoreVerifier.loadKeys(fromPaths);
        assertEquals(2, loadedFromPaths.size());

        // keyDatas list
        PolicyRequirement.SigstoreSigned fromDatas =
                new PolicyRequirement.SigstoreSigned(null, null, null, List.of(keyData1, keyData2));
        List<java.security.PublicKey> loadedFromDatas = SigstoreVerifier.loadKeys(fromDatas);
        assertEquals(2, loadedFromDatas.size());
    }

    @Test
    void verifyWithAnyKeyAcceptsSignatureFromAnyKeyInList() throws Exception {
        KeyPair kp1 = generateEcKeyPair();
        KeyPair kp2 = generateEcKeyPair();

        // Bundle signed by kp1
        byte[] bundle = buildBundle(kp1.getPrivate(), IMAGE_HEX, Const.KEY_SHA256_ECDSA_SIGNATURE_ALGORITHM);

        // Verification passes when kp1 is in the list (even with kp2 present)
        assertTrue(SigstoreVerifier.verifyWithAnyKey(
                List.of(bundle), IMAGE_DIGEST, List.of(kp1.getPublic(), kp2.getPublic())));

        // Verification fails when neither key matches
        KeyPair kp3 = generateEcKeyPair();
        assertFalse(SigstoreVerifier.verifyWithAnyKey(
                List.of(bundle), IMAGE_DIGEST, List.of(kp2.getPublic(), kp3.getPublic())));
    }

    @Test
    void policyVerificationPassesForSignedImageAndFailsWhenTampered(@TempDir Path dir) throws Exception {
        KeyPair kp = generateEcKeyPair();
        byte[] bundle = buildBundle(kp.getPrivate(), IMAGE_HEX, Const.KEY_SHA256_ECDSA_SIGNATURE_ALGORITHM);

        Path keyFile = dir.resolve("cosign.pub");
        Files.writeString(keyFile, toPem(kp.getPublic()));

        Path policyPath = dir.resolve("policy.json");
        // language=json
        Files.writeString(
                policyPath,
                """
                {
                  "default": [{"type": "reject"}],
                  "transports": {
                    "docker": {
                      "registry.example.com/app": [
                        {"type": "sigstoreSigned", "keyPath": "%s"}
                      ]
                    }
                  }
                }
                """
                        .formatted(keyFile.toString().replace("\\", "\\\\")));

        ContainersPolicy policy = ContainersPolicy.newPolicy(policyPath);

        // Signed image
        PolicyContext signed = new PolicyContext(
                Transport.DOCKER,
                "registry.example.com/app",
                IMAGE_DIGEST,
                "registry.example.com/app:latest",
                () -> List.of(bundle));
        assertDoesNotThrow(() -> policy.verify(signed));

        // No bundle
        PolicyContext unsigned = new PolicyContext(
                Transport.DOCKER,
                "registry.example.com/app",
                IMAGE_DIGEST,
                "registry.example.com/app:latest",
                List::of);
        assertThrows(OrasException.class, () -> policy.verify(unsigned));
    }

    @Test
    void policyVerificationFailsWhenKeyIsMissing(@TempDir Path dir) throws Exception {
        KeyPair kp = generateEcKeyPair();
        byte[] bundle = buildBundle(kp.getPrivate(), IMAGE_HEX, Const.KEY_SHA256_ECDSA_SIGNATURE_ALGORITHM);

        Path policyPath = dir.resolve("policy.json");
        // language=json
        Files.writeString(
                policyPath,
                """
                {
                  "default": [{"type": "reject"}],
                  "transports": {
                    "docker": {
                      "registry.example.com/app": [
                        {"type": "sigstoreSigned", "keyPath": "/nonexistent/cosign.pub"}
                      ]
                    }
                  }
                }
                """);

        ContainersPolicy policy = ContainersPolicy.newPolicy(policyPath);
        PolicyContext context = new PolicyContext(
                Transport.DOCKER,
                "registry.example.com/app",
                IMAGE_DIGEST,
                "registry.example.com/app:latest",
                () -> List.of(bundle));
        assertThrows(OrasException.class, () -> policy.verify(context));
    }

    private static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(Const.KEY_EC_ALGORITHM);
        kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        return kpg.generateKeyPair();
    }

    private static byte[] buildBundle(PrivateKey priv, String imageHex, String sigAlgorithm) throws Exception {
        byte[] payload = inTotoPayload(imageHex).getBytes(StandardCharsets.UTF_8);
        byte[] pae = SigstoreVerifier.preAuthEncoding(Const.IN_TOTO_PAYLOAD_TYPE, payload);
        byte[] signature = sign(priv, pae, sigAlgorithm);
        return bundleJson(payload, signature).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] sign(PrivateKey priv, byte[] content, String algorithm) throws Exception {
        Signature signer = Signature.getInstance(algorithm);
        signer.initSign(priv);
        signer.update(content);
        return signer.sign();
    }

    private static String inTotoPayload(String imageHex) {
        // language=json
        return """
                {
                  "_type": "https://in-toto.io/Statement/v1",
                  "subject": [{"digest": {"sha256": "%s"}, "annotations": {}}],
                  "predicateType": "https://sigstore.dev/cosign/sign/v1",
                  "predicate": {}
                }"""
                .formatted(imageHex);
    }

    private static String bundleJson(byte[] payload, byte[] signature) {
        Base64.Encoder b64 = Base64.getEncoder();
        // language=json
        return """
                {
                  "mediaType": "%s",
                  "dsseEnvelope": {
                    "payload": "%s",
                    "payloadType": "%s",
                    "signatures": [{"sig": "%s"}]
                  }
                }"""
                .formatted(
                        Const.SIGSTORE_BUNDLE_MEDIA_TYPE,
                        b64.encodeToString(payload),
                        Const.IN_TOTO_PAYLOAD_TYPE,
                        b64.encodeToString(signature));
    }

    private static String toPem(PublicKey key) {
        String b64 =
                Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(key.getEncoded());
        return """
                -----BEGIN PUBLIC KEY-----
                %s
                -----END PUBLIC KEY-----
                """
                .formatted(b64);
    }
}
