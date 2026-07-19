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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;
import land.oras.TestUtils;
import land.oras.exception.OrasException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;

/**
 * Unit tests for {@link ContainersPolicy} and {@link PolicyRequirement}.
 */
@Execution(ExecutionMode.SAME_THREAD)
class ContainersPolicyTest {

    @Test
    void loadAcceptAllFromFile() {
        Path path = resourcePath("policy/accept-all.json");
        ContainersPolicy policy = ContainersPolicy.newPolicy(path);

        List<PolicyRequirement> defaults = policy.getDefaultRequirements();
        assertEquals(1, defaults.size());
        assertInstanceOf(PolicyRequirement.InsecureAcceptAnything.class, defaults.get(0));
        assertTrue(policy.isAllowed(Transport.DOCKER, "docker.io/library/nginx"));
    }

    @Test
    void loadRejectAllFromFile() {
        Path path = resourcePath("policy/reject-all.json");
        ContainersPolicy policy = ContainersPolicy.newPolicy(path);

        List<PolicyRequirement> defaults = policy.getDefaultRequirements();
        assertEquals(1, defaults.size());
        assertInstanceOf(PolicyRequirement.Reject.class, defaults.get(0));
        assertFalse(policy.isAllowed(Transport.DOCKER, "docker.io/library/nginx"));
    }

    @Test
    void loadMixedPolicyFromFile() {
        Path path = resourcePath("policy/mixed.json");
        ContainersPolicy policy = ContainersPolicy.newPolicy(path);

        // Global default is reject
        assertInstanceOf(
                PolicyRequirement.Reject.class, policy.getDefaultRequirements().get(0));

        assertTrue(policy.isAllowed(Transport.DOCKER, "docker.io"));
        assertTrue(policy.isAllowed(Transport.DOCKER, "docker.io/library/ubuntu"));
        assertFalse(policy.isAllowed(Transport.DOCKER, "docker.io/library/nginx"));
        assertFalse(policy.isAllowed(Transport.DOCKER, "quay.io/someimage"));
        assertTrue(policy.isAllowed(Transport.DOCKER, "quay.io/myorg"));
        assertTrue(policy.isAllowed(Transport.DOCKER, "quay.io/myorg/app"));

        // The "docker-daemon" transport in mixed.json maps to UNKNOWN, whose "" default is
        // insecureAcceptAnything; every non-docker transport collapses to that same UNKNOWN bucket.
        assertTrue(policy.isAllowed(Transport.UNKNOWN, "anything"));
        assertTrue(policy.isAllowed(Transport.UNKNOWN, "some/image"));
    }

    @Test
    void exactScopeMatchTakesPrecedenceOverPrefix() {
        Path path = resourcePath("policy/mixed.json");
        ContainersPolicy policy = ContainersPolicy.newPolicy(path);
        List<PolicyRequirement> reqs = policy.resolveRequirements(Transport.DOCKER, "docker.io/library/nginx");
        assertEquals(1, reqs.size());
        assertInstanceOf(PolicyRequirement.Reject.class, reqs.get(0));
    }

    @Test
    void longestPrefixMatchIsSelected() {
        Path path = resourcePath("policy/mixed.json");
        ContainersPolicy policy = ContainersPolicy.newPolicy(path);
        List<PolicyRequirement> reqs = policy.resolveRequirements(Transport.DOCKER, "quay.io/myorg/app/subapp");
        assertEquals(1, reqs.size());
        assertInstanceOf(PolicyRequirement.InsecureAcceptAnything.class, reqs.get(0));
    }

    @Test
    void wildcardSubdomainMatchAcceptsSubdomain() {
        Path path = resourcePath("policy/mixed.json");
        ContainersPolicy policy = ContainersPolicy.newPolicy(path);
        assertTrue(policy.isAllowed(Transport.DOCKER, "sub.example.com/repo"));
        assertTrue(policy.isAllowed(Transport.DOCKER, "other.example.com"));
    }

    @Test
    void wildcardWithPathMatchesMoreSpecificPath() {
        Path path = resourcePath("policy/mixed.json");
        ContainersPolicy policy = ContainersPolicy.newPolicy(path);
        assertFalse(policy.isAllowed(Transport.DOCKER, "sub.example.com/restricted"));
        assertFalse(policy.isAllowed(Transport.DOCKER, "sub.example.com/restricted/deeper"));
    }

    @Test
    void wildcardDoesNotMatchParentDomain() {
        Path path = resourcePath("policy/mixed.json");
        ContainersPolicy policy = ContainersPolicy.newPolicy(path);
        assertFalse(policy.isAllowed(Transport.DOCKER, "example.com/repo"));
    }

    @Test
    void transportDefaultAppliesWhenNoScopeMatches() {
        Path path = resourcePath("policy/mixed.json");
        ContainersPolicy policy = ContainersPolicy.newPolicy(path);
        assertFalse(policy.isAllowed(Transport.DOCKER, "ghcr.io/owner/image"));
    }

    @Test
    void sigstoreSignedRequirementDeserializesCorrectly() {
        Path path = resourcePath("policy/signing.json");
        ContainersPolicy policy = ContainersPolicy.newPolicy(path);

        List<PolicyRequirement> reqs = policy.resolveRequirements(Transport.DOCKER, "registry.example.com/cosign");
        assertEquals(1, reqs.size());
        assertInstanceOf(PolicyRequirement.SigstoreSigned.class, reqs.get(0));

        // keyPath is read; a signedIdentity field, if present in the JSON, is ignored.
        PolicyRequirement.SigstoreSigned sigstore = (PolicyRequirement.SigstoreSigned) reqs.get(0);
        assertEquals("/etc/pki/containers/cosign.pub", sigstore.getKeyPath());
    }

    @Test
    void evaluatingSignedByFalseNotImplemented() {
        Path path = resourcePath("policy/signing.json");
        ContainersPolicy policy = ContainersPolicy.newPolicy(path);
        assertFalse(policy.isAllowed(Transport.DOCKER, "registry.example.com/signed"));
    }

    @Test
    void evaluatingSigstoreSignedPassesScopeGate() {
        Path path = resourcePath("policy/signing.json");
        ContainersPolicy policy = ContainersPolicy.newPolicy(path);
        assertTrue(policy.isAllowed(Transport.DOCKER, "registry.example.com/cosign"));
    }

    @Test
    void loadsUserPolicyFromHome(@TempDir Path homeDir) throws Exception {
        // language=json
        String policyJson = """
                {"default": [{"type": "insecureAcceptAnything"}]}
                """;
        writePolicyFile(homeDir, policyJson);

        TestUtils.withHome(homeDir, () -> {
            ContainersPolicy policy = ContainersPolicy.newPolicy();
            assertNotNull(policy);
            assertTrue(policy.isAllowed(Transport.DOCKER, "docker.io/library/nginx"));
        });
    }

    @Test
    @Execution(ExecutionMode.SAME_THREAD)
    void fallsBackToAcceptAllWhenNoPolicyFileFound(@TempDir Path emptyHome) throws Exception {
        // Use a home dir that has no policy.json and ensure /etc/containers/policy.json is skipped
        // by pointing both to a dir we control (emptyHome has no policy.json)
        new EnvironmentVariables()
                .set("HOME", emptyHome.toAbsolutePath().toString())
                .execute(() -> {
                    ContainersPolicy policy = ContainersPolicy.newPolicy();
                    assertNotNull(policy);
                });
    }

    @Test
    void throwsOnInvalidPolicyJson(@TempDir Path dir) throws IOException {
        Path badPath = dir.resolve("bad.json");
        Files.writeString(badPath, "{ this is not valid json }");
        assertThrows(OrasException.class, () -> ContainersPolicy.newPolicy(badPath));
    }

    @Test
    void requirementTypeNamesAreCorrect() {
        assertEquals("insecureAcceptAnything", new PolicyRequirement.InsecureAcceptAnything().getType());
        assertEquals("reject", new PolicyRequirement.Reject().getType());
        assertEquals("signedBy", new PolicyRequirement.SignedBy().getType());
        assertEquals("sigstoreSigned", new PolicyRequirement.SigstoreSigned(null, null).getType());
    }

    @Test
    void sigstoreSignedExactScopeVerifiesSignedImage(@TempDir Path dir) throws IOException {
        KeyPair kp = SigstoreTestSupport.generateKeyPair();
        ContainersPolicy policy =
                sigstorePolicy(dir, "registry.example.com/app", "keyData", SigstoreTestSupport.keyData(kp.getPublic()));

        // A correctly signed image passes.
        assertDoesNotThrow(() -> policy.verify(context(
                "registry.example.com/app",
                "registry.example.com/app:latest",
                SigstoreTestSupport.signedBundle(kp.getPrivate(), SigstoreTestSupport.IMAGE_DIGEST))));

        // An unsigned image (no bundles attached) fails closed.
        OrasException e = assertThrows(
                OrasException.class,
                () -> policy.verify(context("registry.example.com/app", "registry.example.com/app:latest")));
        assertTrue(e.getMessage().contains("sigstoreSigned"));
    }

    @Test
    void sigstoreSignedPrefixScopeAppliesToSubpaths(@TempDir Path dir) throws IOException {
        KeyPair kp = SigstoreTestSupport.generateKeyPair();
        ContainersPolicy policy = sigstorePolicy(
                dir, "registry.example.com/team", "keyData", SigstoreTestSupport.keyData(kp.getPublic()));

        // Sub-path resolves to the prefix requirement.
        List<PolicyRequirement> reqs = policy.resolveRequirements(Transport.DOCKER, "registry.example.com/team/app");
        assertEquals(1, reqs.size());
        assertInstanceOf(PolicyRequirement.SigstoreSigned.class, reqs.get(0));

        assertDoesNotThrow(() -> policy.verify(context(
                "registry.example.com/team/app",
                "registry.example.com/team/app:1.0",
                SigstoreTestSupport.signedBundle(kp.getPrivate(), SigstoreTestSupport.IMAGE_DIGEST))));
        assertThrows(
                OrasException.class,
                () -> policy.verify(context("registry.example.com/team/app", "registry.example.com/team/app:1.0")));
    }

    @Test
    void sigstoreSignedWildcardScopeAppliesToSubdomains(@TempDir Path dir) throws IOException {
        KeyPair kp = SigstoreTestSupport.generateKeyPair();
        ContainersPolicy policy =
                sigstorePolicy(dir, "*.example.com", "keyData", SigstoreTestSupport.keyData(kp.getPublic()));

        assertDoesNotThrow(() -> policy.verify(context(
                "sub.example.com/app",
                "sub.example.com/app:latest",
                SigstoreTestSupport.signedBundle(kp.getPrivate(), SigstoreTestSupport.IMAGE_DIGEST))));
        assertThrows(
                OrasException.class, () -> policy.verify(context("sub.example.com/app", "sub.example.com/app:latest")));
    }

    @Test
    void sigstoreSignedTransportDefaultApplies(@TempDir Path dir) throws IOException {
        KeyPair kp = SigstoreTestSupport.generateKeyPair();
        // Empty scope key is the transport default.
        ContainersPolicy policy = sigstorePolicy(dir, "", "keyData", SigstoreTestSupport.keyData(kp.getPublic()));

        assertDoesNotThrow(() -> policy.verify(context(
                "ghcr.io/owner/image",
                "ghcr.io/owner/image:latest",
                SigstoreTestSupport.signedBundle(kp.getPrivate(), SigstoreTestSupport.IMAGE_DIGEST))));
        assertThrows(
                OrasException.class, () -> policy.verify(context("ghcr.io/owner/image", "ghcr.io/owner/image:latest")));
    }

    @Test
    void sigstoreSignedGlobalDefaultApplies(@TempDir Path dir) throws IOException {
        KeyPair kp = SigstoreTestSupport.generateKeyPair();
        Path path = dir.resolve("policy.json");
        // language=json
        Files.writeString(
                path,
                """
                {"default": [{"type": "sigstoreSigned", "keyData": "%s"}]}
                """
                        .formatted(SigstoreTestSupport.keyData(kp.getPublic())));
        ContainersPolicy policy = ContainersPolicy.newPolicy(path);

        assertDoesNotThrow(() -> policy.verify(context(
                "anything.io/x",
                "anything.io/x:latest",
                SigstoreTestSupport.signedBundle(kp.getPrivate(), SigstoreTestSupport.IMAGE_DIGEST))));
    }

    @Test
    void sigstoreSignedRejectsSignatureFromUntrustedKey(@TempDir Path dir) throws IOException {
        KeyPair trusted = SigstoreTestSupport.generateKeyPair();
        KeyPair attacker = SigstoreTestSupport.generateKeyPair();
        ContainersPolicy policy = sigstorePolicy(
                dir, "registry.example.com/app", "keyData", SigstoreTestSupport.keyData(trusted.getPublic()));

        // Validly signed, but by a key that is not in the policy.
        assertThrows(
                OrasException.class,
                () -> policy.verify(context(
                        "registry.example.com/app",
                        "registry.example.com/app:latest",
                        SigstoreTestSupport.signedBundle(attacker.getPrivate(), SigstoreTestSupport.IMAGE_DIGEST))));
    }

    @Test
    void sigstoreSignedRejectsSignatureForDifferentDigest(@TempDir Path dir) throws IOException {
        KeyPair kp = SigstoreTestSupport.generateKeyPair();
        ContainersPolicy policy =
                sigstorePolicy(dir, "registry.example.com/app", "keyData", SigstoreTestSupport.keyData(kp.getPublic()));

        // Bundle signs a different image digest than the one being pulled.
        byte[] bundleForOtherImage = SigstoreTestSupport.signedBundle(kp.getPrivate(), "sha256:" + "1".repeat(64));
        assertThrows(
                OrasException.class,
                () -> policy.verify(
                        context("registry.example.com/app", "registry.example.com/app:latest", bundleForOtherImage)));
    }

    @Test
    void sigstoreSignedWithKeyPathFromFile(@TempDir Path dir) throws IOException {
        KeyPair kp = SigstoreTestSupport.generateKeyPair();
        Path keyFile = dir.resolve("cosign.pub");
        Files.writeString(keyFile, SigstoreTestSupport.publicKeyPem(kp.getPublic()));

        ContainersPolicy policy = sigstorePolicy(
                dir, "registry.example.com/app", "keyPath", keyFile.toString().replace("\\", "\\\\"));

        assertDoesNotThrow(() -> policy.verify(context(
                "registry.example.com/app",
                "registry.example.com/app:latest",
                SigstoreTestSupport.signedBundle(kp.getPrivate(), SigstoreTestSupport.IMAGE_DIGEST))));
    }

    @Test
    void sigstoreSignedWithKeyDataInline(@TempDir Path dir) throws IOException {
        KeyPair kp = SigstoreTestSupport.generateKeyPair();
        ContainersPolicy policy =
                sigstorePolicy(dir, "registry.example.com/app", "keyData", SigstoreTestSupport.keyData(kp.getPublic()));

        assertDoesNotThrow(() -> policy.verify(context(
                "registry.example.com/app",
                "registry.example.com/app:latest",
                SigstoreTestSupport.signedBundle(kp.getPrivate(), SigstoreTestSupport.IMAGE_DIGEST))));
    }

    @Test
    void sigstoreSignedWithKeyPathsList(@TempDir Path dir) throws IOException {
        KeyPair kp1 = SigstoreTestSupport.generateKeyPair();
        KeyPair kp2 = SigstoreTestSupport.generateKeyPair();
        Path keyFile1 = dir.resolve("cosign1.pub");
        Path keyFile2 = dir.resolve("cosign2.pub");
        Files.writeString(keyFile1, SigstoreTestSupport.publicKeyPem(kp1.getPublic()));
        Files.writeString(keyFile2, SigstoreTestSupport.publicKeyPem(kp2.getPublic()));

        Path path = dir.resolve("policy.json");
        // language=json
        Files.writeString(
                path,
                """
                {
                  "default": [{"type": "reject"}],
                  "transports": {
                    "docker": {
                      "registry.example.com/app": [{
                        "type": "sigstoreSigned",
                        "keyPaths": ["%s", "%s"]
                      }]
                    }
                  }
                }
                """
                        .formatted(
                                keyFile1.toString().replace("\\", "\\\\"),
                                keyFile2.toString().replace("\\", "\\\\")));
        ContainersPolicy policy = ContainersPolicy.newPolicy(path);

        // Accepted when signed by kp1
        assertDoesNotThrow(() -> policy.verify(context(
                "registry.example.com/app",
                "registry.example.com/app:latest",
                SigstoreTestSupport.signedBundle(kp1.getPrivate(), SigstoreTestSupport.IMAGE_DIGEST))));

        // Accepted when signed by kp2
        assertDoesNotThrow(() -> policy.verify(context(
                "registry.example.com/app",
                "registry.example.com/app:latest",
                SigstoreTestSupport.signedBundle(kp2.getPrivate(), SigstoreTestSupport.IMAGE_DIGEST))));

        // Rejected when signed by an untrusted key
        KeyPair attacker = SigstoreTestSupport.generateKeyPair();
        assertThrows(
                OrasException.class,
                () -> policy.verify(context(
                        "registry.example.com/app",
                        "registry.example.com/app:latest",
                        SigstoreTestSupport.signedBundle(attacker.getPrivate(), SigstoreTestSupport.IMAGE_DIGEST))));
    }

    @Test
    void sigstoreSignedWithKeyDatasList(@TempDir Path dir) throws IOException {
        KeyPair kp1 = SigstoreTestSupport.generateKeyPair();
        KeyPair kp2 = SigstoreTestSupport.generateKeyPair();

        Path path = dir.resolve("policy.json");
        // language=json
        Files.writeString(
                path,
                """
                {
                  "default": [{"type": "reject"}],
                  "transports": {
                    "docker": {
                      "registry.example.com/app": [{
                        "type": "sigstoreSigned",
                        "keyDatas": ["%s", "%s"]
                      }]
                    }
                  }
                }
                """
                        .formatted(
                                SigstoreTestSupport.keyData(kp1.getPublic()),
                                SigstoreTestSupport.keyData(kp2.getPublic())));
        ContainersPolicy policy = ContainersPolicy.newPolicy(path);

        // Accepted when signed by kp1
        assertDoesNotThrow(() -> policy.verify(context(
                "registry.example.com/app",
                "registry.example.com/app:latest",
                SigstoreTestSupport.signedBundle(kp1.getPrivate(), SigstoreTestSupport.IMAGE_DIGEST))));

        // Accepted when signed by kp2
        assertDoesNotThrow(() -> policy.verify(context(
                "registry.example.com/app",
                "registry.example.com/app:latest",
                SigstoreTestSupport.signedBundle(kp2.getPrivate(), SigstoreTestSupport.IMAGE_DIGEST))));

        // Rejected when signed by an untrusted key
        KeyPair attacker = SigstoreTestSupport.generateKeyPair();
        assertThrows(
                OrasException.class,
                () -> policy.verify(context(
                        "registry.example.com/app",
                        "registry.example.com/app:latest",
                        SigstoreTestSupport.signedBundle(attacker.getPrivate(), SigstoreTestSupport.IMAGE_DIGEST))));
    }

    @Test
    void sigstoreSignedKeyPathsDeserializesCorrectly(@TempDir Path dir) throws IOException {
        Path path = dir.resolve("policy.json");
        // language=json
        Files.writeString(
                path,
                """
                {
                  "default": [{"type": "reject"}],
                  "transports": {
                    "docker": {
                      "registry.example.com/app": [{
                        "type": "sigstoreSigned",
                        "keyPaths": ["/etc/pki/a.pub", "/etc/pki/b.pub"]
                      }]
                    }
                  }
                }
                """);
        ContainersPolicy policy = ContainersPolicy.newPolicy(path);
        List<PolicyRequirement> reqs = policy.resolveRequirements(Transport.DOCKER, "registry.example.com/app");
        assertEquals(1, reqs.size());
        PolicyRequirement.SigstoreSigned sigstore = (PolicyRequirement.SigstoreSigned) reqs.get(0);
        assertNull(sigstore.getKeyPath());
        assertNull(sigstore.getKeyData());
        assertNotNull(sigstore.getKeyPaths());
        assertEquals(List.of("/etc/pki/a.pub", "/etc/pki/b.pub"), sigstore.getKeyPaths());
        assertNull(sigstore.getKeyDatas());
    }

    @Test
    void signedByGpgIsDeniedBecauseNotImplemented(@TempDir Path dir) throws IOException {
        Path path = dir.resolve("policy.json");
        // language=json
        Files.writeString(
                path,
                """
                {
                  "default": [{"type": "reject"}],
                  "transports": {
                    "docker": {
                      "registry.example.com/signed": [
                        {"type": "signedBy", "keyType": "GPGKeys", "keyPath": "/etc/pki/containers/my-key.gpg"}
                      ]
                    }
                  }
                }
                """);
        ContainersPolicy policy = ContainersPolicy.newPolicy(path);
        assertThrows(
                OrasException.class,
                () -> policy.verify(context("registry.example.com/signed", "registry.example.com/signed:latest")));
    }

    @Test
    void mixedScopesResolveAndVerifyIndependently(@TempDir Path dir) throws IOException {
        KeyPair kp = SigstoreTestSupport.generateKeyPair();
        Path path = dir.resolve("policy.json");
        // language=json
        Files.writeString(
                path,
                """
                {
                  "default": [{"type": "reject"}],
                  "transports": {
                    "docker": {
                      "registry.example.com/open": [{"type": "insecureAcceptAnything"}],
                      "registry.example.com/blocked": [{"type": "reject"}],
                      "registry.example.com/secure": [{"type": "sigstoreSigned", "keyData": "%s"}]
                    }
                  }
                }
                """
                        .formatted(SigstoreTestSupport.keyData(kp.getPublic())));
        ContainersPolicy policy = ContainersPolicy.newPolicy(path);

        // Open scope: accepted without signatures.
        assertDoesNotThrow(
                () -> policy.verify(context("registry.example.com/open", "registry.example.com/open:latest")));

        // Blocked scope: always rejected.
        assertThrows(
                OrasException.class,
                () -> policy.verify(context("registry.example.com/blocked", "registry.example.com/blocked:latest")));

        // Secure scope: requires a valid signature.
        assertDoesNotThrow(() -> policy.verify(context(
                "registry.example.com/secure",
                "registry.example.com/secure:latest",
                SigstoreTestSupport.signedBundle(kp.getPrivate(), SigstoreTestSupport.IMAGE_DIGEST))));
        assertThrows(
                OrasException.class,
                () -> policy.verify(context("registry.example.com/secure", "registry.example.com/secure:latest")));

        // Unmatched scope: falls through to the global default (reject).
        assertThrows(
                OrasException.class,
                () -> policy.verify(context("registry.example.com/unknown", "registry.example.com/unknown:latest")));
    }

    /**
     * Write a policy.json with a global {@code reject} default and a single {@code sigstoreSigned}
     * requirement under {@code docker} for the given scope key.
     *
     * @param dir      the temp directory to write into.
     * @param scopeKey the transport scope key (use {@code ""} for the transport default).
     * @param keyField the key field name, e.g. {@code "keyData"} or {@code "keyPath"}.
     * @param keyValue the value of the key field.
     * @return the loaded policy.
     */
    private static ContainersPolicy sigstorePolicy(Path dir, String scopeKey, String keyField, String keyValue)
            throws IOException {
        Path path = dir.resolve("policy.json");
        // language=json
        Files.writeString(
                path,
                """
                {
                  "default": [{"type": "reject"}],
                  "transports": {
                    "docker": {
                      "%s": [{"type": "sigstoreSigned", "%s": "%s"}]
                    }
                  }
                }
                """
                        .formatted(scopeKey, keyField, keyValue));
        return ContainersPolicy.newPolicy(path);
    }

    /**
     * Build a {@link PolicyContext} for the {@code docker} transport bound to
     * {@link SigstoreTestSupport#IMAGE_DIGEST}, whose signature fetcher returns the given bundles.
     */
    private static PolicyContext context(String scope, String reference, byte[]... bundles) {
        return new PolicyContext(
                Transport.DOCKER, scope, SigstoreTestSupport.IMAGE_DIGEST, reference, () -> List.of(bundles));
    }

    private static Path resourcePath(String relative) {
        try {
            return Path.of(ContainersPolicyTest.class
                    .getClassLoader()
                    .getResource(relative)
                    .toURI());
        } catch (Exception e) {
            throw new RuntimeException("Test resource not found: " + relative, e);
        }
    }

    private static void writePolicyFile(Path homeDir, String content) throws IOException {
        Path containersDir = homeDir.resolve(".config").resolve("containers");
        Files.createDirectories(containersDir);
        Files.writeString(containersDir.resolve("policy.json"), content);
    }
}
