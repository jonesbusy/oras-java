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

package land.oras.auth;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import land.oras.ContainerRef;
import land.oras.exception.OrasException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.properties.SystemProperties;

/**
 * Test class of {@link AuthStore}.
 */
class AuthStoreTest {

    @TempDir
    private Path tempDir;

    @TempDir
    private static Path homeDir;

    @TempDir
    private static Path xdgRuntimeDir;

    private AuthStore authStore;
    private AuthStore.Config mockConfig;
    private AuthStore.Credential mockCredential;
    private static final String USERNAME = "user";
    private static final String PASSWORD = "password";

    // language=json
    public static final String SAMPLE_DOCKER_CONFIG =
            """
    {
        "auths": {
            "registry.example.com": {
                "auth": "dXNlcjpwYXNzd29yZA=="
            },
            "another.registry.com": {
                "auth": "dXNlcjpwYXNzd29yZA=="
            }
        },
        "credsStore": "unknown",
        "credHelpers": {
            "registry.other.com": "foo-binary",
            "another.other.com": "bar-binary",
            "new.other.com": "pass",
            "other.other.com": "other-binary",
            "creds.other.com": "fake",
            "error.other.com": "fake"
        }
    }
    """;

    // language=json
    public static final String SAMPLE_PODMAN_CONFIG =
            """
    {
        "auths": {
            "registry.other.com": {
                "auth": "dXNlcjpwYXNzd29yZA=="
            },
            "another.other.com": {
                "auth": "dXNlcjpwYXNzd29yZA=="
            }
        },
        "credsStore": "unknown",
        "credHelpers": {
            "registry.other.com": "foo-binary",
            "another.other.com": "bar-binary",
            "new.other.com": "pass",
            "other.other.com": "other-binary",
            "creds.other.com": "fake",
            "error.other.com": "fake"
        }
    }
    """;

    @BeforeAll
    static void init() throws Exception {

        // Write a sample Docker config file
        Files.createDirectory(homeDir.resolve(".docker"));
        Files.writeString(homeDir.resolve(".docker").resolve("config.json"), SAMPLE_DOCKER_CONFIG);

        // Write a sample Podman config file
        Files.createDirectory(xdgRuntimeDir.resolve("containers"));
        Files.writeString(xdgRuntimeDir.resolve("containers").resolve("auth.json"), SAMPLE_PODMAN_CONFIG);

        Path helper = Path.of("docker-credential-fake");
        String newPath =
                helper.toAbsolutePath().getParent() + System.getProperty("path.separator") + System.getenv("PATH");
        System.setProperty("PATH", newPath);
    }

    @BeforeEach
    void setUp() {
        // Mock Config and Credential
        mockConfig = Mockito.mock(AuthStore.Config.class);
        mockCredential = new AuthStore.Credential(USERNAME, PASSWORD);
        authStore = new AuthStore(mockConfig);
    }

    @Test
    void testShouldReadCredentialsFromCredentialHelperNullCheck() throws Exception {
        new EnvironmentVariables()
                .set("XDG_RUNTIME_DIR", "not-used")
                .remove("REGISTRY_AUTH_FILE")
                .execute(() -> {
                    new SystemProperties("user.home", homeDir.toAbsolutePath().toString()).execute(() -> {
                        assertNotNull(System.getenv("XDG_RUNTIME_DIR"));
                        AuthStore authStoreInstance = AuthStore.newStore();
                        assertNotNull(authStoreInstance);

                        // Verify
                        AuthStore.Credential credential =
                                authStoreInstance.get(ContainerRef.parse("other.other.com/foo/bar:latest"));
                        assertNull(credential);
                    });
                });
    }

    @Test
    void testShouldReadCredentialsFromCredentialStoreNullCheck() throws Exception {
        new EnvironmentVariables()
                .set("XDG_RUNTIME_DIR", "not-used")
                .remove("REGISTRY_AUTH_FILE")
                .execute(() -> {
                    new SystemProperties("user.home", homeDir.toAbsolutePath().toString()).execute(() -> {
                        assertNotNull(System.getenv("XDG_RUNTIME_DIR"));
                        AuthStore authStoreInstance = AuthStore.newStore();
                        assertNotNull(authStoreInstance);

                        // Verify
                        AuthStore.Credential credential =
                                authStoreInstance.get(ContainerRef.parse("otherfromstore.other.com/foo/bar:latest"));
                        assertNull(credential);
                    });
                });
    }

    @Test
    void testShouldReadCredentialsFromCredentialHelperFake() throws Exception {

        assumeFalse(
                System.getProperty("os.name").toLowerCase().contains("win"),
                "Skipping test: docker-credential-fake is not supported on Windows");
        assumeTrue(
                Files.exists(Path.of("/usr/bin/docker-credential-fake")),
                "Skipping test: /usr/bin/docker-credential-fake not found");

        // Prepend to PATH
        Path helper = Path.of("docker-credential-fake");
        String newPath =
                helper.toAbsolutePath().getParent() + System.getProperty("path.separator") + System.getenv("PATH");
        new EnvironmentVariables()
                .set("XDG_RUNTIME_DIR", "not-used")
                .set("PATH", newPath)
                .remove("REGISTRY_AUTH_FILE")
                .execute(() -> {
                    new SystemProperties("user.home", homeDir.toAbsolutePath().toString()).execute(() -> {
                        assertNotNull(System.getenv("XDG_RUNTIME_DIR"));
                        AuthStore authStoreInstance = AuthStore.newStore();
                        assertNotNull(authStoreInstance);

                        // Verify
                        AuthStore.Credential credential =
                                authStoreInstance.get(ContainerRef.parse("creds.other.com/foo/bar:latest"));
                        assertNotNull(credential);
                    });
                });
    }

    @Test
    void testShouldReadCredentialsFromCredentialHelperHandleNonZeroReturnCode() throws Exception {

        assumeFalse(
                System.getProperty("os.name").toLowerCase().contains("win"),
                "Skipping test: docker-credential-fake is not supported on Windows");
        assumeTrue(
                Files.exists(Path.of("/usr/bin/docker-credential-fake")),
                "Skipping test: /usr/bin/docker-credential-fake not found");

        // Prepend to PATH
        Path helper = Path.of("docker-credential-fake");
        String newPath =
                helper.toAbsolutePath().getParent() + System.getProperty("path.separator") + System.getenv("PATH");
        new EnvironmentVariables()
                .set("XDG_RUNTIME_DIR", "not-used")
                .set("PATH", newPath)
                .remove("REGISTRY_AUTH_FILE")
                .execute(() -> {
                    new SystemProperties("user.home", homeDir.toAbsolutePath().toString()).execute(() -> {
                        assertNotNull(System.getenv("XDG_RUNTIME_DIR"));
                        AuthStore authStoreInstance = AuthStore.newStore();
                        assertNotNull(authStoreInstance);

                        // Verify
                        AuthStore.Credential credential =
                                authStoreInstance.get(ContainerRef.parse("error.other.com/foo/bar:latest"));
                        assertNull(credential);
                    });
                });
    }

    @Test
    void testShouldReadCredentialsFromDockerConfig() throws Exception {
        new EnvironmentVariables()
                .set("XDG_RUNTIME_DIR", "not-used")
                .remove("REGISTRY_AUTH_FILE")
                .execute(() -> {
                    new SystemProperties("user.home", homeDir.toAbsolutePath().toString()).execute(() -> {
                        assertNotNull(System.getenv("XDG_RUNTIME_DIR"));
                        AuthStore authStoreInstance = AuthStore.newStore();
                        assertNotNull(authStoreInstance);

                        // Verify
                        AuthStore.Credential credential =
                                authStoreInstance.get(ContainerRef.parse("registry.example.com/foo/bar:latest"));
                        assertNotNull(credential);
                        assertEquals(USERNAME, credential.username());

                        // Null
                        assertNull(authStoreInstance.get(ContainerRef.parse("unknown.registry.com/foo/bar:latest")));

                        String binary = authStoreInstance.getCredentialHelperBinary(
                                ContainerRef.parse("registry.other.com/foo/bar:latest"));
                        assertNotNull(binary);
                        assertEquals("docker-credential-foo-binary", binary);

                        assertNull(authStoreInstance.getCredentialHelperBinary(
                                ContainerRef.parse("unknown.registry.com/foo/bar:latest")));
                    });
                });
    }

    @Test
    void testShouldReadCredentialsFromPodManConfig() throws Exception {
        new EnvironmentVariables()
                .set("XDG_RUNTIME_DIR", xdgRuntimeDir.toAbsolutePath().toString())
                .remove("REGISTRY_AUTH_FILE")
                .execute(() -> {
                    new SystemProperties("user.home", "not-used").execute(() -> {
                        assertNotNull(System.getenv("XDG_RUNTIME_DIR"));
                        assertEquals(xdgRuntimeDir.toAbsolutePath().toString(), System.getenv("XDG_RUNTIME_DIR"));
                        AuthStore authStoreInstance = AuthStore.newStore();
                        assertNotNull(authStoreInstance);

                        // Verify
                        AuthStore.Credential credential =
                                authStoreInstance.get(ContainerRef.parse("registry.other.com/foo/bar:latest"));
                        assertNotNull(credential);
                        assertEquals(USERNAME, credential.username());

                        String binary = authStoreInstance.getCredentialHelperBinary(
                                ContainerRef.parse("registry.other.com/foo/bar:latest"));
                        assertNotNull(binary);
                        assertEquals("docker-credential-foo-binary", binary);

                        assertNull(authStoreInstance.getCredentialHelperBinary(
                                ContainerRef.parse("unknown.registry.com/foo/bar:latest")));
                    });
                });
    }

    // language=json
    public static final String SAMPLE_HIERARCHICAL_CONFIG =
            """
    {
        "auths": {
            "my-registry.local/namespace/user/image": {
                "auth": "dXNlcjE6cGFzczE="
            },
            "my-registry.local/namespace": {
                "auth": "dXNlcjM6cGFzczM="
            },
            "my-registry.local": {
                "auth": "dXNlcjI6cGFzczI="
            }
        }
    }
    """;

    @Test
    void testHierarchicalCredentialLookupMostSpecific() throws Exception {
        Path configFile = tempDir.resolve("hierarchical-config.json");
        Files.writeString(configFile, SAMPLE_HIERARCHICAL_CONFIG);
        AuthStore store = AuthStore.newStore(List.of(configFile));

        // Most specific key: my-registry.local/namespace/user/image
        AuthStore.Credential credential =
                store.get(ContainerRef.parse("my-registry.local/namespace/user/image:latest"));
        assertNotNull(credential);
        assertEquals("user1", credential.username());
        assertEquals("pass1", credential.password());
    }

    @Test
    void testHierarchicalCredentialLookupNamespaceOnly() throws Exception {
        Path configFile = tempDir.resolve("hierarchical-config.json");
        Files.writeString(configFile, SAMPLE_HIERARCHICAL_CONFIG);
        AuthStore store = AuthStore.newStore(List.of(configFile));

        // Credential stored at namespace level: my-registry.local/namespace
        // Image under that namespace but not exact-matched should fall back to namespace credential
        AuthStore.Credential credential =
                store.get(ContainerRef.parse("my-registry.local/namespace/other-image:latest"));
        assertNotNull(credential);
        assertEquals("user3", credential.username());
        assertEquals("pass3", credential.password());
    }

    @Test
    void testHierarchicalCredentialLookupFallsBackToRegistry() throws Exception {
        Path configFile = tempDir.resolve("hierarchical-config.json");
        Files.writeString(configFile, SAMPLE_HIERARCHICAL_CONFIG);
        AuthStore store = AuthStore.newStore(List.of(configFile));

        // Different image under the same registry falls back to registry-level credential
        AuthStore.Credential credential = store.get(ContainerRef.parse("my-registry.local/other/repo:latest"));
        assertNotNull(credential);
        assertEquals("user2", credential.username());
        assertEquals("pass2", credential.password());
    }

    @Test
    void testHierarchicalCredentialLookupRegistryOnly() throws Exception {
        Path configFile = tempDir.resolve("hierarchical-config.json");
        Files.writeString(configFile, SAMPLE_HIERARCHICAL_CONFIG);
        AuthStore store = AuthStore.newStore(List.of(configFile));

        // Image without namespace falls back to registry-level credential
        AuthStore.Credential credential = store.get(ContainerRef.parse("my-registry.local/image:latest"));
        assertNotNull(credential);
        assertEquals("user2", credential.username());
        assertEquals("pass2", credential.password());
    }

    @Test
    void testHierarchicalCredentialLookupNoMatch() throws Exception {
        Path configFile = tempDir.resolve("hierarchical-config.json");
        Files.writeString(configFile, SAMPLE_HIERARCHICAL_CONFIG);
        AuthStore store = AuthStore.newStore(List.of(configFile));

        // Unknown registry returns null
        AuthStore.Credential credential = store.get(ContainerRef.parse("unknown-registry.local/foo/bar:latest"));
        assertNull(credential);
    }

    @Test
    void testWithoutXdgRuntimeDir() throws Exception {
        new EnvironmentVariables()
                .remove("XDG_RUNTIME_DIR")
                .remove("REGISTRY_AUTH_FILE")
                .execute(() -> {
                    assertNull(System.getenv("XDG_RUNTIME_DIR"));
                    AuthStore authStoreInstance = AuthStore.newStore();
                    assertNotNull(authStoreInstance);
                });
    }

    @Test
    void testRegistryAuthFileIsUsedWhenSet() throws Exception {
        Path authFile = tempDir.resolve("custom-auth.json");
        Files.writeString(authFile, SAMPLE_DOCKER_CONFIG);

        new EnvironmentVariables()
                .set("REGISTRY_AUTH_FILE", authFile.toAbsolutePath().toString())
                .remove("XDG_RUNTIME_DIR")
                .execute(() -> {
                    new SystemProperties("user.home", homeDir.toAbsolutePath().toString()).execute(() -> {
                        AuthStore authStoreInstance = AuthStore.newStore();
                        assertNotNull(authStoreInstance);

                        AuthStore.Credential credential =
                                authStoreInstance.get(ContainerRef.parse("registry.example.com/foo/bar:latest"));
                        assertNotNull(credential);
                        assertEquals(USERNAME, credential.username());
                    });
                });
    }

    @Test
    void testRegistryAuthFileTakesPrecedenceOverDefaults() throws Exception {
        // language=json
        String customConfig =
                """
        {
            "auths": {
                "custom.registry.com": {
                    "auth": "dXNlcjpwYXNzd29yZA=="
                }
            }
        }
        """;
        Path authFile = tempDir.resolve("custom-auth.json");
        Files.writeString(authFile, customConfig);

        new EnvironmentVariables()
                .set("REGISTRY_AUTH_FILE", authFile.toAbsolutePath().toString())
                .set("XDG_RUNTIME_DIR", xdgRuntimeDir.toAbsolutePath().toString())
                .execute(() -> {
                    new SystemProperties("user.home", homeDir.toAbsolutePath().toString()).execute(() -> {
                        AuthStore authStoreInstance = AuthStore.newStore();

                        // Custom registry from REGISTRY_AUTH_FILE must be found
                        AuthStore.Credential custom =
                                authStoreInstance.get(ContainerRef.parse("custom.registry.com/foo/bar:latest"));
                        assertNotNull(custom);
                        assertEquals(USERNAME, custom.username());

                        // Default docker/podman registries must NOT be visible (REGISTRY_AUTH_FILE is exclusive)
                        assertNull(authStoreInstance.get(ContainerRef.parse("registry.example.com/foo/bar:latest")));
                        assertNull(authStoreInstance.get(ContainerRef.parse("registry.other.com/foo/bar:latest")));
                    });
                });
    }

    @Test
    void testGetCredential_success() throws Exception {

        ContainerRef ref = ContainerRef.parse("localhost:5000/myrepo/myimage:latest");

        // Mock the behavior of getting credentials
        Mockito.when(mockConfig.getCredential(ref)).thenReturn(mockCredential);

        AuthStore.Credential credential = authStore.get(ref);

        assertNotNull(credential);
        assertEquals(USERNAME, credential.username());
        assertEquals(PASSWORD, credential.password());
    }

    @Test
    void testConfigLoad_success() throws Exception {
        // Create a temporary JSON file for testing
        ContainerRef containerRef =
                ContainerRef.parse("docker.io/library/foo/hello-world:latest@sha256:1234567890abcdef");

        AuthStore.ConfigFile configFile =
                AuthStore.ConfigFile.fromCredential(new AuthStore.Credential("admin", "password123"));

        // Load the configuration from the temporary file
        AuthStore.Config.load(List.of(configFile));

        assertEquals("docker.io", containerRef.getRegistry());
        assertEquals("library/foo", containerRef.getNamespace());
        assertEquals("hello-world", containerRef.getRepository());
        assertEquals("latest", containerRef.getTag());
        assertEquals("sha256:1234567890abcdef", containerRef.getDigest());

        // Clean up by deleting the temporary file
        Files.delete(tempDir);
    }

    @Test
    void testPasswordContainingColonIsPreserved() throws Exception {
        String user = "user";
        String password = "p@ss:with:colons";
        String auth = java.util.Base64.getEncoder()
                .encodeToString((user + ":" + password).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        // language=json
        String config =
                """
                {
                    "auths": {
                        "colon.registry.com": { "auth": "%s" }
                    }
                }
                """
                        .formatted(auth);
        Path configFile = tempDir.resolve("colon-config.json");
        Files.writeString(configFile, config);

        AuthStore store = AuthStore.newStore(List.of(configFile));
        AuthStore.Credential credential = store.get(ContainerRef.parse("colon.registry.com/foo/bar:latest"));

        assertNotNull(credential);
        assertEquals(user, credential.username());
        assertEquals(password, credential.password());
    }

    @Test
    void testMalformedEntryIsSkippedWithoutDroppingOtherCredentials() throws Exception {
        String malformed = java.util.Base64.getEncoder()
                .encodeToString("no-colon-here".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String valid = java.util.Base64.getEncoder()
                .encodeToString("user:password".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        // language=json
        String config =
                """
                {
                    "auths": {
                        "bad.registry.com": { "auth": "%s" },
                        "good.registry.com": { "auth": "%s" }
                    }
                }
                """
                        .formatted(malformed, valid);
        Path configFile = tempDir.resolve("malformed-config.json");
        Files.writeString(configFile, config);

        AuthStore store = AuthStore.newStore(List.of(configFile));
        assertNull(store.get(ContainerRef.parse("bad.registry.com/foo/bar:latest")));
        AuthStore.Credential credential = store.get(ContainerRef.parse("good.registry.com/foo/bar:latest"));
        assertNotNull(credential);
        assertEquals("user", credential.username());
        assertEquals("password", credential.password());
    }

    @Test
    void testEmptyPasswordIsPreserved() throws Exception {
        String auth =
                java.util.Base64.getEncoder().encodeToString("user:".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        // language=json
        String config =
                """
                {
                    "auths": {
                        "empty.registry.com": { "auth": "%s" }
                    }
                }
                """
                        .formatted(auth);
        Path configFile = tempDir.resolve("empty-pass-config.json");
        Files.writeString(configFile, config);

        AuthStore store = AuthStore.newStore(List.of(configFile));
        AuthStore.Credential credential = store.get(ContainerRef.parse("empty.registry.com/foo/bar:latest"));

        assertNotNull(credential);
        assertEquals("user", credential.username());
        assertEquals("", credential.password());
    }

    @Test
    void testPasswordWithArbitraryCharactersIsPreserved() throws Exception {
        String user = "user";
        String password = "p:ä ss\"w0rd\\:with=🔒:tail";
        String auth = java.util.Base64.getEncoder()
                .encodeToString((user + ":" + password).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        // language=json
        String config =
                """
                {
                    "auths": {
                        "any.registry.com": { "auth": "%s" }
                    }
                }
                """
                        .formatted(auth);
        Path configFile = tempDir.resolve("any-char-config.json");
        Files.writeString(configFile, config);

        AuthStore store = AuthStore.newStore(List.of(configFile));
        AuthStore.Credential credential = store.get(ContainerRef.parse("any.registry.com/foo/bar:latest"));

        assertNotNull(credential);
        assertEquals(user, credential.username());
        assertEquals(password, credential.password());
    }

    @Test
    void shouldRejectCredentialHelperThatEscapesPrefix() throws Exception {
        String maliciousSuffix = "../../../../../../tmp/pwn";
        // language=json
        String config =
                """
                {
                    "auths": {},
                    "credHelpers": { "evil.registry.com": "%s" }
                }
                """
                        .formatted(maliciousSuffix);
        Path configFile = tempDir.resolve("evil-helper-config.json");
        Files.writeString(configFile, config);

        AuthStore store = AuthStore.newStore(List.of(configFile));

        ContainerRef ref = ContainerRef.parse("evil.registry.com/foo/bar:latest");
        OrasException ex = assertThrows(OrasException.class, () -> store.getCredentialHelperBinary(ref));
        assertTrue(ex.getMessage().contains("Invalid credential helper name"), "Unexpected: " + ex.getMessage());
    }

    @Test
    void shouldReturnValidCredentialHelperBinary() throws Exception {
        // language=json
        String config =
                """
                {
                    "auths": {},
                    "credHelpers": { "good.registry.com": "ecr-login" }
                }
                """;
        Path configFile = tempDir.resolve("good-helper-config.json");
        Files.writeString(configFile, config);

        AuthStore store = AuthStore.newStore(List.of(configFile));
        String binary = store.getCredentialHelperBinary(ContainerRef.parse("good.registry.com/foo/bar:latest"));
        assertEquals("docker-credential-ecr-login", binary);
    }

    @Test
    void credentialHelperBinaryNameRejectsPrefixEscapes() {
        // Several bad path
        for (String bad : List.of(
                "../../../../tmp/evil", "/bin/sh", "a/b", "a\\b", "..", "foo bar", "foo;rm -rf /", "foo$(id)", "")) {
            OrasException ex = assertThrows(
                    OrasException.class,
                    () -> AuthStore.credentialHelperBinaryName(bad),
                    "Expected rejection for: '" + bad + "'");
            assertTrue(ex.getMessage().contains("Invalid credential helper name"), "Unexpected: " + ex.getMessage());
        }
    }

    @Test
    void credentialHelperBinaryNameAcceptsBareHelperNames() {
        // Real-world helper names must keep working
        assertEquals("docker-credential-osxkeychain", AuthStore.credentialHelperBinaryName("osxkeychain"));
        assertEquals("docker-credential-ecr-login", AuthStore.credentialHelperBinaryName("ecr-login"));
        assertEquals("docker-credential-secretservice", AuthStore.credentialHelperBinaryName("secretservice"));
        assertEquals("docker-credential-pass", AuthStore.credentialHelperBinaryName("pass"));
        assertEquals("docker-credential-wincred", AuthStore.credentialHelperBinaryName("wincred"));
    }
}
