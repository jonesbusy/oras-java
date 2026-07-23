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

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import land.oras.auth.AuthStore;
import land.oras.auth.AuthStoreAuthenticationProvider;
import land.oras.auth.BearerTokenProvider;
import land.oras.auth.HttpClient;
import land.oras.auth.NoAuthProvider;
import land.oras.auth.Scopes;
import land.oras.auth.UsernamePasswordProvider;
import land.oras.exception.OrasException;
import land.oras.utils.Const;
import land.oras.utils.JsonUtils;
import land.oras.utils.SupportedAlgorithm;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

@WireMockTest
@Execution(ExecutionMode.SAME_THREAD)
class RegistryWireMockTest {

    private final UsernamePasswordProvider authProvider = new UsernamePasswordProvider("myuser", "mypass");

    @TempDir
    private Path configDir;

    @TempDir
    private static Path homeDir1;

    @TempDir
    private static Path homeDir2;

    @TempDir
    private static Path homeDir3;

    @TempDir
    private static Path homeDir4;

    @Test
    void shouldPassBearerTokenWithExternalRequestedToken(WireMockRuntimeInfo wmRuntimeInfo) {
        Registry registry = Registry.Builder.builder()
                .insecure()
                .withAuthToken("insecure-token")
                .build();

        // Ensure WireMock accept only our token
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(WireMock.get(WireMock.urlEqualTo("/v2/library/artifact-text/tags/list"))
                .withHeader("Authorization", equalTo("Bearer insecure-token"))
                .willReturn(WireMock.okJson(JsonUtils.toJson(new Tags("artifact-text", List.of("latest", "0.1.1"))))));
        wireMock.register(WireMock.get(WireMock.urlEqualTo("/v2/library/artifact-text/tags/list"))
                .withHeader("Authorization", equalTo("Bearer invalid-token"))
                .willReturn(WireMock.unauthorized()));

        registry.getTags(ContainerRef.parse("%s/library/artifact-text"
                .formatted(wmRuntimeInfo.getHttpBaseUrl().replace("http://", ""))));

        // Ensure it fail with invalid token
        final Registry newRegistry = registry.withAuthToken("invalid-token");
        OrasException e = assertThrows(
                OrasException.class,
                () -> newRegistry.getTags(ContainerRef.parse("%s/library/artifact-text"
                        .formatted(wmRuntimeInfo.getHttpBaseUrl().replace("http://", "")))));
        assertEquals(401, e.getStatusCode());
    }

    @Test
    void shouldFailToGetManifestOn403(WireMockRuntimeInfo wmRuntimeInfo) {

        // Return data from wiremock
        WireMock wireMock = wmRuntimeInfo.getWireMock();

        // Return 403 on getting manifest
        wireMock.register(WireMock.head(WireMock.urlEqualTo("/v2/library/some-artifact/manifests/latest"))
                .willReturn(WireMock.forbidden().withBody("Forbidden")));

        // Insecure registry
        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        ContainerRef containerRef =
                ContainerRef.parse("localhost:%d/library/some-artifact:latest".formatted(wmRuntimeInfo.getHttpPort()));
        OrasException exception = assertThrows(OrasException.class, () -> registry.getManifest(containerRef));
        assertEquals(403, exception.getStatusCode());
    }

    @Test
    void shouldRedirectWhenDownloadingBlob(WireMockRuntimeInfo wmRuntimeInfo) {

        String digest = SupportedAlgorithm.SHA256.digest("blob-data".getBytes());

        // Return data from wiremock
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(WireMock.any(WireMock.urlEqualTo("/v2/library/artifact-text/blobs/%s".formatted(digest)))
                .willReturn(WireMock.temporaryRedirect("http://localhost:%d/v2/library/artifact-text/blobs/sha256:other"
                        .formatted(wmRuntimeInfo.getHttpPort()))));

        // Return blob on new location
        wireMock.register(head(WireMock.urlEqualTo("/v2/library/artifact-text/blobs/%s".formatted(digest)))
                .willReturn(WireMock.ok()));
        wireMock.register(WireMock.get(WireMock.urlEqualTo("/v2/library/artifact-text/blobs/sha256:other"))
                .willReturn(
                        WireMock.ok().withBody("blob-data").withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, digest)));

        // Insecure registry
        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        ContainerRef containerRef =
                ContainerRef.parse("localhost:%d/library/artifact-text".formatted(wmRuntimeInfo.getHttpPort()));
        byte[] blob = registry.getBlob(containerRef.withDigest(digest));
        assertEquals("blob-data", new String(blob));
    }

    @Test
    void mountBlobShouldReturnFalseOn202(WireMockRuntimeInfo wmRuntimeInfo) throws IOException {

        // Return data from wiremock
        WireMock wireMock = wmRuntimeInfo.getWireMock();

        // Return location without domain when pushing blob
        wireMock.register(WireMock.post(WireMock.urlPathMatching("/.*"))
                .willReturn(WireMock.status(202).withHeader("Location", "/foobar")));

        // Push is on foobar
        wireMock.register(WireMock.put(WireMock.urlPathMatching("/foobar.*")).willReturn(WireMock.status(201)));

        // Insecure registry
        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        ContainerRef containerRef = ContainerRef.parse(
                "%s/test@sha512:12345".formatted(wmRuntimeInfo.getHttpBaseUrl().replace("http://", "")));
        assertFalse(registry.mountBlob(containerRef, containerRef), "Mount blob should return false");
    }

    @Test
    void shouldRedirectWhenPushingBlob(WireMockRuntimeInfo wmRuntimeInfo) throws IOException {

        // Return data from wiremock
        WireMock wireMock = wmRuntimeInfo.getWireMock();

        // Return location without domain when pushing blob
        wireMock.register(head(WireMock.urlPathMatching("/v2/library/artifact-redirect/blobs/.*"))
                .willReturn(WireMock.status(404)));
        wireMock.register(WireMock.post(WireMock.urlPathMatching("/v2/library/artifact-redirect/blobs/uploads/.*"))
                .willReturn(WireMock.status(202).withHeader("Location", "/foobar")));

        // Push is on foobar
        wireMock.register(WireMock.put(WireMock.urlPathMatching("/foobar.*")).willReturn(WireMock.status(201)));

        // Insecure registry
        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        ContainerRef containerRef = ContainerRef.parse(
                "localhost:%d/library/artifact-redirect@sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
                        .formatted(wmRuntimeInfo.getHttpPort()));
        registry.pushBlob(containerRef, "hello".getBytes());

        // Via file
        Path testFile = configDir.resolve("test-data.temp");
        Files.writeString(testFile, "Test Content");
        registry.pushBlob(containerRef, testFile);
    }

    @Test
    void shouldNotSendAuthHeaderOnRedirectToDifferentDomain(WireMockRuntimeInfo wmRuntimeInfo) {
        String digest = SupportedAlgorithm.SHA256.digest("blob-data".getBytes());

        // Setup second WireMock instance on a different port
        WireMockServer redirectTarget =
                new WireMockServer(WireMockConfiguration.options().dynamicPort());
        redirectTarget.start();

        try {
            String redirectUrl = "http://localhost:%d/v2/other/blobs/sha256:other".formatted(redirectTarget.port());

            WireMock mainMock = wmRuntimeInfo.getWireMock();

            // Main mock responds with redirect to different domain
            mainMock.register(WireMock.any(WireMock.urlEqualTo("/v2/library/artifact/blobs/%s".formatted(digest)))
                    .willReturn(WireMock.temporaryRedirect(redirectUrl)));

            // Secondary server returns blob, we inspect headers here
            redirectTarget.stubFor(WireMock.get(WireMock.urlEqualTo("/v2/other/blobs/sha256:other"))
                    .willReturn(WireMock.ok()
                            .withBody("blob-data")
                            .withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, digest)));

            redirectTarget.stubFor(WireMock.head(WireMock.urlEqualTo("/v2/other/blobs/sha256:other"))
                    .willReturn(WireMock.ok()));

            // Registry setup with auth that would inject an Authorization header
            Registry registry = Registry.Builder.builder()
                    .withAuthProvider(authProvider)
                    .withInsecure(true)
                    .build();

            ContainerRef containerRef =
                    ContainerRef.parse("localhost:%d/library/artifact".formatted(wmRuntimeInfo.getHttpPort()));
            byte[] blob = registry.getBlob(containerRef.withDigest(digest));

            assertEquals("blob-data", new String(blob));

            // Assert Authorization header was not sent to the redirect target
            redirectTarget.verify(
                    1,
                    WireMock.getRequestedFor(WireMock.urlEqualTo("/v2/other/blobs/sha256:other"))
                            .withoutHeader("Authorization"));
        } finally {
            redirectTarget.stop();
        }
    }

    @Test
    void shouldNotForwardParentCredentialsToInsecureMirror(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {

        String mirrorHost = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");

        // The "original" registry (localhost:59998) is down and has an insecure mirror pointing at the
        // WireMock server. The parent registry is configured with static basic-auth credentials — those
        // credentials must NOT be forwarded to the mirror over plaintext HTTP.
        // language=toml
        String config =
                """
                [[registry]]
                prefix = "localhost:59998"
                location = "localhost:59998"

                [[registry.mirror]]
                location = "%s"
                insecure = true
                """
                        .formatted(mirrorHost);
        TestUtils.createRegistriesConfFile(homeDir4, config);

        // language=json
        String manifestJson =
                """
                {"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",\
                "config":{"mediaType":"application/vnd.oci.empty.v1+json",\
                "digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},\
                "layers":[]}""";

        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String manifestPath = "/v2/library/cred-mirror/manifests/v1";
        wireMock.register(WireMock.head(WireMock.urlEqualTo(manifestPath))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader(Const.CONTENT_TYPE_HEADER, Const.DEFAULT_MANIFEST_MEDIA_TYPE)));
        wireMock.register(WireMock.get(WireMock.urlEqualTo(manifestPath))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader(Const.CONTENT_TYPE_HEADER, Const.DEFAULT_MANIFEST_MEDIA_TYPE)
                        .withBody(manifestJson)));

        TestUtils.withHome(homeDir4, () -> {
            Registry registry =
                    Registry.Builder.builder().withAuthProvider(authProvider).build();
            ContainerRef ref = ContainerRef.parse("localhost:59998/library/cred-mirror:v1");
            Manifest manifest = registry.getManifest(ref);
            assertNotNull(manifest, "Manifest should be fetched via the mirror");
        });

        // The mirror must have been contacted without the parent registry's Authorization header.
        wireMock.verifyThat(
                WireMock.getRequestedFor(WireMock.urlEqualTo(manifestPath)).withoutHeader(Const.AUTHORIZATION_HEADER));
        wireMock.verifyThat(
                WireMock.headRequestedFor(WireMock.urlEqualTo(manifestPath)).withoutHeader(Const.AUTHORIZATION_HEADER));
    }

    @Test
    void shouldListTags(WireMockRuntimeInfo wmRuntimeInfo) {

        // Return data from wiremock
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(WireMock.get(WireMock.urlEqualTo("/v2/library/artifact-text/tags/list"))
                .willReturn(WireMock.okJson(JsonUtils.toJson(new Tags("artifact-text", List.of("latest", "0.1.1"))))));

        // Insecure registry
        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        // Test
        List<String> tags = registry.getTags(ContainerRef.parse("%s/library/artifact-text"
                        .formatted(wmRuntimeInfo.getHttpBaseUrl().replace("http://", ""))))
                .tags();

        // Assert
        assertEquals(2, tags.size());
        assertEquals("latest", tags.get(0));
        assertEquals("0.1.1", tags.get(1));
    }

    @Test
    void shouldListTagsWithLimit(WireMockRuntimeInfo wmRuntimeInfo) {

        // Return data from wiremock
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(WireMock.get(WireMock.urlEqualTo("/v2/library/artifact-text/tags/list?n=1"))
                .willReturn(WireMock.okJson(JsonUtils.toJson(new Tags("artifact-text", List.of("latest"))))));

        // Insecure registry
        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        // Test
        List<String> tags = registry.getTags(
                        ContainerRef.parse("%s/library/artifact-text"
                                .formatted(wmRuntimeInfo.getHttpBaseUrl().replace("http://", ""))),
                        1,
                        null)
                .tags();

        // Assert
        assertEquals(1, tags.size());
        assertEquals("latest", tags.get(0));
    }

    @Test
    void shouldListTagsWithConfig(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {

        String registryAsString = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");

        // language=toml
        String config =
                """
            [[registry]]
            location = "%s"
            insecure = true
            """
                        .formatted(registryAsString);
        TestUtils.createRegistriesConfFile(homeDir1, config);

        // Return data from wiremock
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(WireMock.get(WireMock.urlEqualTo("/v2/library/artifact-text-with-confg/tags/list"))
                .willReturn(WireMock.okJson(JsonUtils.toJson(new Tags("artifact-text", List.of("latest", "0.1.1"))))));

        TestUtils.withHome(homeDir1, () -> {
            // Don't see insecure flag
            Registry registry =
                    Registry.Builder.builder().withAuthProvider(authProvider).build();
            List<String> tags = registry.getTags(
                            ContainerRef.parse("%s/library/artifact-text-with-confg".formatted(registryAsString)))
                    .tags();
            assertEquals(2, tags.size());
            assertEquals("latest", tags.get(0));
            assertEquals("0.1.1", tags.get(1));

            // With limit
            tags = registry.getTags(
                            ContainerRef.parse("%s/library/artifact-text-with-confg".formatted(registryAsString)),
                            1,
                            null)
                    .tags();
            assertEquals(2, tags.size());
            assertEquals("latest", tags.get(0));
            assertEquals("0.1.1", tags.get(1));
        });
    }

    @Test
    void shouldListRepositories(WireMockRuntimeInfo wmRuntimeInfo) {

        // Return data from wiremock
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(WireMock.get(WireMock.urlEqualTo("/v2/_catalog"))
                .willReturn(
                        WireMock.okJson(JsonUtils.toJson(new Repositories(List.of("foo", "bar", "library/alpine"))))));

        // Insecure registry
        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .withRegistry(wmRuntimeInfo.getHttpBaseUrl().replace("http://", ""))
                .build();

        // Test
        List<String> repositories = registry.getRepositories().repositories();

        // Assert
        assertEquals(3, repositories.size());
        assertEquals("foo", repositories.get(0));
        assertEquals("bar", repositories.get(1));
        assertEquals("library/alpine", repositories.get(2));
    }

    @Test
    void shouldListRepositoryWithLocationConfig(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {

        String registryAsString = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");

        // language=toml
        String config =
                """
            [[registry]]
            location = "%s"
            insecure = true
            """
                        .formatted(registryAsString);
        TestUtils.createRegistriesConfFile(homeDir2, config);

        // Return data from wiremock
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(WireMock.get(WireMock.urlEqualTo("/v2/_catalog"))
                .willReturn(
                        WireMock.okJson(JsonUtils.toJson(new Repositories(List.of("foo", "bar", "library/alpine"))))));

        TestUtils.withHome(homeDir2, () -> {
            // Don't see insecure flag
            Registry registry = Registry.Builder.builder()
                    .withRegistry(registryAsString)
                    .withAuthProvider(authProvider)
                    .build();
            List<String> repositories = registry.getRepositories().repositories();
            assertEquals(3, repositories.size());
            assertEquals("foo", repositories.get(0));
            assertEquals("bar", repositories.get(1));
            assertEquals("library/alpine", repositories.get(2));
        });
    }

    @Test
    void shouldListRepositoryWithPrefixConfig(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {

        String registryAsString = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");

        // language=toml
        String config =
                """
            [[registry]]
            prefix = "%s"
            insecure = true
            """
                        .formatted(registryAsString);
        TestUtils.createRegistriesConfFile(homeDir3, config);

        // Return data from wiremock
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(WireMock.get(WireMock.urlEqualTo("/v2/_catalog"))
                .willReturn(
                        WireMock.okJson(JsonUtils.toJson(new Repositories(List.of("foo", "bar", "library/alpine"))))));

        TestUtils.withHome(homeDir3, () -> {
            // Don't see insecure flag
            Registry registry = Registry.Builder.builder()
                    .withRegistry(registryAsString)
                    .withAuthProvider(authProvider)
                    .build();
            List<String> repositories = registry.getRepositories().repositories();
            assertEquals(3, repositories.size());
            assertEquals("foo", repositories.get(0));
            assertEquals("bar", repositories.get(1));
            assertEquals("library/alpine", repositories.get(2));
        });
    }

    @Test
    void shouldListTagsWithFileStoreAuth(WireMockRuntimeInfo wmRuntimeInfo) throws IOException {

        // Auth file for current registry
        String authFile =
                """
                {
                        "auths": {
                                "localhost:%d": {
                                        "auth": "bXl1c2VyOm15cGFzcw=="
                                }
                        }
                }
                """
                        .formatted(wmRuntimeInfo.getHttpPort());

        Files.writeString(configDir.resolve("config.json"), authFile, StandardCharsets.UTF_8);

        AuthStoreAuthenticationProvider authProvider =
                new AuthStoreAuthenticationProvider(AuthStore.newStore(List.of(configDir.resolve("config.json"))));

        // Return data from wiremock
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(WireMock.get(WireMock.urlEqualTo("/v2/library/artifact-text-store/tags/list"))
                .willReturn(WireMock.okJson(
                        JsonUtils.toJson(new Tags("artifact-text-store", List.of("latest", "0.1.1"))))));

        // Insecure registry
        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        // Test
        List<String> tags = registry.getTags(ContainerRef.parse("%s/library/artifact-text-store"
                        .formatted(wmRuntimeInfo.getHttpBaseUrl().replace("http://", ""))))
                .tags();

        // Assert
        assertEquals(2, tags.size());
        assertEquals("latest", tags.get(0));
        assertEquals("0.1.1", tags.get(1));
    }

    // Errors from registry
    @Test
    void shouldHandle500Error(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");

        // Register the wiremock
        wireMock.register(WireMock.get(WireMock.urlEqualTo("/v2/library/error-artifact/tags/list"))
                .willReturn(WireMock.serverError().withBody("Internal Server Error")));
        wireMock.register(head(WireMock.urlEqualTo("/v2/library/error-artifact/blobs/sha256:1234"))
                .willReturn(WireMock.serverError().withBody("Internal Server Error")));
        Registry registry = Registry.Builder.builder().withInsecure(true).build();

        // Now we should have a reference to container
        ContainerRef ref = ContainerRef.parse("%s/library/error-artifact".formatted(registryUrl));

        OrasException exception = assertThrows(OrasException.class, () -> registry.getTags(ref));
        assertEquals(500, exception.getStatusCode());

        ContainerRef ref2 = ContainerRef.parse("%s/library/error-artifact@sha256:1234".formatted(registryUrl));
        OrasException exception2 = assertThrows(OrasException.class, () -> registry.fetchBlobDescriptor(ref2));
        assertEquals(500, exception2.getStatusCode());
    }

    // Timeout with similar structure as previous test and request 408 with different artifact name
    @Test
    void shouldHandleTimeout(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");

        // Using here a unique container reference to avoid conflicts when running in parallel
        ContainerRef ref = ContainerRef.parse("%s/library/timeout-artifact".formatted(registryUrl));

        // We Set up the stub for the timeout scenario
        wireMock.register(WireMock.get(WireMock.urlEqualTo("/v2/library/timeout-artifact/tags/list"))
                .willReturn(WireMock.aResponse().withStatus(408).withBody("Request timed out")));

        Registry registry = Registry.Builder.builder().withInsecure(true).build();

        OrasException exception = assertThrows(OrasException.class, () -> registry.getTags(ref));
        assertEquals(408, exception.getStatusCode());
    }

    @Test
    void shouldRetryBlobUpload(WireMockRuntimeInfo wmRuntimeInfo) throws IOException {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");
        String uploadPath = "/v2/library/artifact-text/blobs/uploads/";

        // HEAD: blob does not exist yet
        wireMock.register(WireMock.head(WireMock.urlPathMatching("/v2/library/artifact-text/blobs/.*"))
                .willReturn(WireMock.status(404)));

        // POST: first attempt fails with 500; second succeeds with 202 + Location
        wireMock.register(WireMock.post(WireMock.urlPathMatching(uploadPath + ".*"))
                .inScenario("upload retry scenario")
                .whenScenarioStateIs(Scenario.STARTED)
                .willReturn(WireMock.serverError())
                .willSetStateTo("retry"));

        wireMock.register(WireMock.post(WireMock.urlPathMatching(uploadPath + ".*"))
                .inScenario("upload retry scenario")
                .whenScenarioStateIs("retry")
                .willReturn(WireMock.aResponse().withStatus(202).withHeader("Location", uploadPath + "12345")));

        wireMock.register(
                WireMock.put(WireMock.urlPathMatching(uploadPath + "12345.*")).willReturn(WireMock.created()));

        Registry registry =
                Registry.Builder.builder().withInsecure(true).withRetryDelay(0).build();
        ContainerRef ref = ContainerRef.parse("%s/library/artifact-text".formatted(registryUrl));

        Path testFile = configDir.resolve("test-data.temp");
        Files.writeString(testFile, "Test Content");

        try (InputStream inputStream = Files.newInputStream(testFile)) {
            Layer layer = registry.pushBlob(ref, inputStream);
            assertNotNull(layer);
            assertNotNull(layer.getDigest());
        }
    }

    @Test
    void shouldGetToken(WireMockRuntimeInfo wmRuntimeInfo) {
        byte[] blob = tokenScenario(wmRuntimeInfo, "get-token", "token", null);
        assertEquals("blob-data", new String(blob));
    }

    @Test
    void shouldGetAuthToken(WireMockRuntimeInfo wmRuntimeInfo) {
        byte[] blob = tokenScenario(wmRuntimeInfo, "get-auth-token", null, "access-token");
        assertEquals("blob-data", new String(blob));
        blob = tokenScenario(wmRuntimeInfo, "get-auth-token", null, "access-token");
        assertEquals("blob-data", new String(blob));
        blob = tokenScenario(wmRuntimeInfo, "get-auth-token", null, "access-token");
        assertEquals("blob-data", new String(blob));

        // Ensure only one request on token endpoint du to caching
        WireMock.verify(
                1,
                WireMock.getRequestedFor(
                        WireMock.urlEqualTo("/token?scope=repository:library/get-auth-token:pull&service=localhost")));
    }

    @Test
    void shouldRefreshExpiredToken(WireMockRuntimeInfo wmRuntimeInfo) {

        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        Metrics.addRegistry(meterRegistry);

        String digest = SupportedAlgorithm.SHA256.digest("blob-data".getBytes());

        // Return data from wiremock
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(WireMock.any(WireMock.urlEqualTo("/v2/library/refresh-token/blobs/%s".formatted(digest)))
                .inScenario("get token")
                .willReturn(WireMock.forbidden()
                        .withHeader(
                                Const.WWW_AUTHENTICATE_HEADER,
                                "Bearer realm=\"http://localhost:%d/token\",service=\"localhost\",scope=\"repository:library/refresh-token:pull\""
                                        .formatted(wmRuntimeInfo.getHttpPort()))));

        // Return token
        wireMock.register(WireMock.any(
                        WireMock.urlEqualTo("/token?scope=repository:library/refresh-token:pull&service=localhost"))
                .inScenario("get token")
                .willSetStateTo("get")
                .willReturn(WireMock.okJson(JsonUtils.toJson(
                        new HttpClient.TokenResponse("fake-token", "access-token", null, 300, ZonedDateTime.now())))));

        // On the second call we return ok
        wireMock.register(WireMock.any(WireMock.urlEqualTo("/v2/library/refresh-token/blobs/%s".formatted(digest)))
                .inScenario("get token")
                .whenScenarioStateIs("get")
                .willReturn(
                        WireMock.ok().withBody("blob-data").withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, digest)));

        // Insecure registry with a custom meter registry to track metrics
        Registry registry = Registry.Builder.builder()
                .withAuthProvider(new BearerTokenProvider()) // Already bearer token
                .withInsecure(true)
                .build();

        ContainerRef containerRef =
                ContainerRef.parse("localhost:%d/library/refresh-token".formatted(wmRuntimeInfo.getHttpPort()));
        byte[] blob = registry.getBlob(containerRef.withDigest(digest));
        assertEquals("blob-data", new String(blob));

        // Verify that exactly one token refresh was performed
        assertEquals(
                1.0,
                meterRegistry
                        .counter(
                                Const.METRIC_TOKEN_REFRESH,
                                Const.METRIC_TAG_SERVICE,
                                "localhost",
                                Const.METRIC_TAG_REALM,
                                "http://localhost:%d/token".formatted(wmRuntimeInfo.getHttpPort()))
                        .count(),
                "Token refresh counter should be 1 after one token refresh");
        assertEquals(
                1.0,
                meterRegistry.find(Const.METRIC_TOKEN_REFRESH).counters().stream()
                        .mapToDouble(Counter::count)
                        .sum());
        TestUtils.dumpMetrics(meterRegistry);
        TestUtils.dumpMetrics(Metrics.globalRegistry);
    }

    @Test
    void shouldExecutePatchRequestWithHeaders(WireMockRuntimeInfo wMockRuntimeInfo) {
        WireMock wireMock = wMockRuntimeInfo.getWireMock();
        String registryUrl = wMockRuntimeInfo.getHttpBaseUrl().replace("http://", "");
        HttpClient client = HttpClient.Builder.builder().withSkipTlsVerify(true).build();

        // Setup Mock to craete a PATCH request with Headers
        wireMock.register(patch(urlEqualTo("/v2/test/blobs/uploads/session1"))
                .withHeader(Const.CONTENT_TYPE_HEADER, equalTo(Const.APPLICATION_OCTET_STREAM_HEADER_VALUE))
                .withHeader(Const.CONTENT_RANGE_HEADER, equalTo("0-1023"))
                .willReturn(aResponse()
                        .withStatus(202)
                        .withHeader(Const.LOCATION_HEADER, "/v2/test/blobs/uploads/session2")
                        .withHeader(Const.RANGE_HEADER, "0-1023")
                        .withHeader(Const.OCI_CHUNK_MIN_LENGTH_HEADER, "4096")));

        // Create sample data with headers
        byte[] data = "test patch".getBytes();
        Map<String, String> headers = new HashMap<>();
        headers.put(Const.CONTENT_TYPE_HEADER, Const.APPLICATION_OCTET_STREAM_HEADER_VALUE);
        headers.put(Const.CONTENT_RANGE_HEADER, "0-1023");

        // Execute Patch
        URI uri = URI.create("http://" + registryUrl + "/v2/test/blobs/uploads/session1");
        HttpClient.ResponseWrapper<String> response =
                client.patch(uri, data, headers, Scopes.of(ContainerRef.parse("foo")), new NoAuthProvider());

        // Verify response uses all our constants
        assertEquals(202, response.statusCode());
        assertEquals("/v2/test/blobs/uploads/session2", response.headers().get(Const.LOCATION_HEADER.toLowerCase()));
        assertEquals("0-1023", response.headers().get(Const.RANGE_HEADER.toLowerCase()));
        assertEquals("4096", response.headers().get(Const.OCI_CHUNK_MIN_LENGTH_HEADER.toLowerCase()));

        // Verify the PATCH request was made with correct headers
        wireMock.verifyThat(patchRequestedFor(urlEqualTo("/v2/test/blobs/uploads/session1"))
                .withHeader(Const.CONTENT_TYPE_HEADER, equalTo(Const.APPLICATION_OCTET_STREAM_HEADER_VALUE))
                .withHeader(Const.CONTENT_RANGE_HEADER, equalTo("0-1023")));
    }

    @Test
    void shouldHandleRateLimitingResponse(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");

        // Setup WireMock to return 429 Too Many Requests
        wireMock.register(get(urlEqualTo("/v2/library/rate-limited/tags/list"))
                .willReturn(aResponse()
                        .withStatus(429)
                        .withHeader("Retry-After", "5")
                        .withBody("Rate limit exceeded")));

        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        ContainerRef ref = ContainerRef.parse("%s/library/rate-limited".formatted(registryUrl));

        // Verify that a 429 status code is thrown as an OrasException
        OrasException exception = assertThrows(OrasException.class, () -> registry.getTags(ref));
        assertEquals(429, exception.getStatusCode());
        assertEquals("Response code: 429", exception.getMessage());
    }

    @Test
    void shouldFollowRedirectOnBlobFetch(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");
        String digest = SupportedAlgorithm.SHA256.digest("blob-data".getBytes());

        // Setup WireMock to redirect to a new location
        String redirectUrl = "http://%s/v2/library/redirect-blob/blobs/redirected/%s".formatted(registryUrl, digest);
        wireMock.register(get(urlEqualTo("/v2/library/redirect-blob/blobs/%s".formatted(digest)))
                .willReturn(aResponse().withStatus(307).withHeader("Location", redirectUrl)));

        // Setup WireMock to serve blob at redirected location
        wireMock.register(get(urlEqualTo("/v2/library/redirect-blob/blobs/redirected/%s".formatted(digest)))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, digest)
                        .withBody("blob-data")));

        // Setup HEAD request for validation
        wireMock.register(head(urlEqualTo("/v2/library/redirect-blob/blobs/%s".formatted(digest)))
                .willReturn(aResponse().withStatus(200)));

        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        ContainerRef containerRef = ContainerRef.parse("%s/library/redirect-blob".formatted(registryUrl));
        byte[] blob = registry.getBlob(containerRef.withDigest(digest));
        assertEquals("blob-data", new String(blob));
    }

    @Test
    void shouldComputeSizeWhenGettingDescriptorIfNull(WireMockRuntimeInfo wmRuntimeInfo) {

        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");
        wireMock.register(any(urlEqualTo("/v2/library/null-size/manifests/latest"))
                .willReturn(
                        aResponse().withStatus(200).withBody("{}") // Empty JSON, no test on index
                        ));

        // Test
        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();
        ContainerRef containerRef = ContainerRef.parse("%s/library/null-size".formatted(registryUrl));

        Descriptor descriptor = registry.getDescriptor(containerRef);
        assertNotNull(descriptor, "Descriptor should not be null");
        assertEquals(2, descriptor.getSize(), "Size should be 0 when not provided by registry");
    }

    @Test
    void shouldGetSizeFromHeaderWhenGettingDescriptor(WireMockRuntimeInfo wmRuntimeInfo) {

        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");
        wireMock.register(any(urlEqualTo("/v2/library/header-size-size/manifests/latest"))
                .willReturn(
                        aResponse()
                                .withStatus(200)
                                .withHeader("Content-Length", "42")
                                .withBody("{}") // Empty JSON, no test on index
                        ));

        // Test
        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();
        ContainerRef containerRef = ContainerRef.parse("%s/library/header-size-size".formatted(registryUrl));

        Descriptor descriptor = registry.getDescriptor(containerRef);
        assertNotNull(descriptor, "Descriptor should not be null");
        assertEquals(42, descriptor.getSize(), "Size should be 0 when not provided by registry");
    }

    @Test
    void shouldValidateDockerContentDigestForUnknownAlgorithm(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");
        String digest = SupportedAlgorithm.SHA256.digest("blob-data".getBytes());
        wireMock.register(any(urlEqualTo("/v2/library/validate-digest/blobs/%s".formatted(digest)))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("blob-data")
                        .withHeader("Docker-Content-Digest", "fake:12345")));

        // Test
        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();
        ContainerRef containerRef = ContainerRef.parse("%s/library/validate-digest".formatted(registryUrl));
        OrasException e = assertThrows(
                OrasException.class,
                () -> registry.getBlob(containerRef.withDigest(digest)),
                "Expected OrasException to be thrown");
        assertEquals("Unsupported digest: fake:12345", e.getMessage());
    }

    @Test
    void shouldValidateDockerContentDigestMismatch(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");
        String digest = SupportedAlgorithm.SHA256.digest("blob-data".getBytes());
        wireMock.register(any(urlEqualTo("/v2/library/validate-digest/blobs/%s".formatted(digest)))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("blob-data")
                        .withHeader("Docker-Content-Digest", "sha256:12345")));

        // Test
        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();
        ContainerRef containerRef = ContainerRef.parse("%s/library/validate-digest".formatted(registryUrl));
        OrasException e = assertThrows(
                OrasException.class,
                () -> registry.getBlob(containerRef.withDigest(digest)),
                "Expected OrasException to be thrown");
        assertEquals(
                "Digest mismatch: sha256:12345 != sha256:c2752ad96ee652e4d37fd3852de632c50f193490d132f27a1794c986e1f112ef",
                e.getMessage());
    }

    @Test
    void shouldNotValidateDockerContentDigestWhenProbingDescriptor(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");
        wireMock.register(head(urlEqualTo("/v2/library/validate-digest/manifests/latest"))
                .willReturn(aResponse().withStatus(200).withBody("blob-data")));

        // Test
        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();
        ContainerRef containerRef = ContainerRef.parse("%s/library/validate-digest".formatted(registryUrl));
        Descriptor descriptor = registry.probeDescriptor(containerRef);
        assertNotNull(descriptor, "Descriptor should not be null");
    }

    @Test
    void shouldFollowRedirectAfterRequestingToken(WireMockRuntimeInfo wmRuntimeInfo) {

        String digest = SupportedAlgorithm.SHA256.digest("blob-data".getBytes());

        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");

        // Redirect to a fake other storage
        String redirectUrl = "http://%s/storage/%s".formatted(registryUrl, digest);

        WireMock wireMock = wmRuntimeInfo.getWireMock();

        // First we need to authenticate
        wireMock.register(WireMock.any(WireMock.urlEqualTo("/v2/library/get-first-token/blobs/%s".formatted(digest)))
                .inScenario("redirect after token")
                .willSetStateTo("auth requested")
                .willReturn(WireMock.unauthorized()
                        .withHeader(
                                Const.WWW_AUTHENTICATE_HEADER,
                                "Bearer realm=\"http://localhost:%d/token\",service=\"localhost\",scope=\"repository:library/get-first-token:pull\""
                                        .formatted(wmRuntimeInfo.getHttpPort()))));

        // Token is returned
        wireMock.register(WireMock.any(
                        WireMock.urlEqualTo("/token?scope=repository:library/get-first-token:pull&service=localhost"))
                .inScenario("redirect after token")
                .whenScenarioStateIs("auth requested")
                .willSetStateTo("got token")
                .willReturn(WireMock.okJson(JsonUtils.toJson(
                        new HttpClient.TokenResponse("fake-token", "access-token", null, 300, ZonedDateTime.now())))));

        // After getting token we get a redirect
        wireMock.register(WireMock.any(WireMock.urlEqualTo("/v2/library/get-first-token/blobs/%s".formatted(digest)))
                .inScenario("redirect after token")
                .whenScenarioStateIs("got token")
                .willSetStateTo("redirect")
                .willReturn(WireMock.temporaryRedirect(redirectUrl)));

        // We finally get the blob
        wireMock.register(WireMock.any(WireMock.urlEqualTo("/storage/%s".formatted(digest)))
                .inScenario("redirect after token")
                .whenScenarioStateIs("redirect")
                .willSetStateTo("done")
                .willReturn(WireMock.ok("blob-data").withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, digest)));

        // Test
        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();
        ContainerRef containerRef =
                ContainerRef.parse("localhost:%d/library/get-first-token".formatted(wmRuntimeInfo.getHttpPort()));
        byte[] blob = registry.getBlob(containerRef.withDigest(digest));
        assertEquals("blob-data", new String(blob));
    }

    @Test
    void shouldHandleConcurrentBlobPushes(WireMockRuntimeInfo wmRuntimeInfo) throws IOException, InterruptedException {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");
        String digest = SupportedAlgorithm.SHA256.digest("concurrent-data".getBytes());

        // Setup WireMock for blob push
        wireMock.register(head(urlPathMatching("/v2/library/concurrent-blob/blobs/.*"))
                .willReturn(aResponse().withStatus(404)));
        wireMock.register(post(urlPathMatching("/v2/library/concurrent-blob/blobs/uploads/.*"))
                .willReturn(aResponse().withStatus(202).withHeader("Location", "/upload")));
        wireMock.register(
                put(urlPathMatching("/upload.*")).willReturn(aResponse().withStatus(201)));

        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        ContainerRef containerRef = ContainerRef.parse("%s/library/concurrent-blob@%s".formatted(registryUrl, digest));

        // Create a temporary file for pushing
        Path testFile = configDir.resolve("concurrent-data.temp");
        Files.writeString(testFile, "concurrent-data");

        // Execute concurrent blob pushes
        ExecutorService executor = Executors.newFixedThreadPool(3);
        for (int i = 0; i < 3; i++) {
            executor.submit(() -> {
                try {
                    registry.pushBlob(containerRef, testFile);
                } catch (OrasException e) {
                    throw new RuntimeException(e);
                }
            });
        }

        executor.shutdown();
        boolean completed = executor.awaitTermination(10, TimeUnit.SECONDS);
        assertEquals(true, completed, "Concurrent blob pushes did not complete within timeout");
    }

    @Test
    void shouldHandleNetworkConnectivityLoss(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");

        // Setup WireMock to simulate a connection reset
        wireMock.register(get(urlEqualTo("/v2/library/network-loss/tags/list"))
                .willReturn(aResponse().withStatus(503).withBody("Service Unavailable")));

        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        ContainerRef ref = ContainerRef.parse("%s/library/network-loss".formatted(registryUrl));

        // Verify that a network connectivity loss results in an OrasException
        OrasException exception = assertThrows(OrasException.class, () -> registry.getTags(ref));
        assertEquals("Response code: 503", exception.getMessage());
    }

    @Test
    void shouldHandleCorruptedResponse(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");
        String digest = SupportedAlgorithm.SHA256.digest("blob-data".getBytes());

        // Setup WireMock to return a corrupted blob response
        wireMock.register(head(urlEqualTo("/v2/library/corrupted-blob/blobs/%s".formatted(digest)))
                .willReturn(aResponse().withStatus(200)));
        wireMock.register(get(urlEqualTo("/v2/library/corrupted-blob/blobs/%s".formatted(digest)))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, digest)
                        .withBody("corrupted-data")));

        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        ContainerRef containerRef = ContainerRef.parse("%s/library/corrupted-blob".formatted(registryUrl));

        // Expect digest mismatch exception
        OrasException exception =
                assertThrows(OrasException.class, () -> registry.getBlob(containerRef.withDigest(digest)));
        assertEquals(
                "Digest mismatch: sha256:c2752ad96ee652e4d37fd3852de632c50f193490d132f27a1794c986e1f112ef != sha256:2be4e14a6587ab9b637afb553f0654c70e80fa14bd0b8fbf9fa09079f55a2ace",
                exception.getMessage());
    }

    private byte[] tokenScenario(
            WireMockRuntimeInfo wmRuntimeInfo, String registryName, String token, String accessToken) {
        String digest = SupportedAlgorithm.SHA256.digest("blob-data".getBytes());

        // Return data from wiremock
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(WireMock.any(WireMock.urlEqualTo("/v2/library/%s/blobs/%s".formatted(registryName, digest)))
                .inScenario(registryName)
                .willReturn(WireMock.unauthorized()
                        .withHeader(
                                Const.WWW_AUTHENTICATE_HEADER,
                                "Bearer realm=\"http://localhost:%d/token\",service=\"localhost\",scope=\"repository:library/%s:pull\""
                                        .formatted(wmRuntimeInfo.getHttpPort(), registryName))));

        // Return token
        wireMock.register(WireMock.any(WireMock.urlEqualTo(
                        "/token?scope=repository:library/%s:pull&service=localhost".formatted(registryName)))
                .inScenario(registryName)
                .willSetStateTo("get")
                .willReturn(WireMock.okJson(JsonUtils.toJson(
                        new HttpClient.TokenResponse(token, accessToken, null, 300, ZonedDateTime.now())))));

        // On the second call we return ok
        wireMock.register(WireMock.any(WireMock.urlEqualTo("/v2/library/%s/blobs/%s".formatted(registryName, digest)))
                .inScenario(registryName)
                .whenScenarioStateIs("get")
                .willReturn(
                        WireMock.ok().withBody("blob-data").withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, digest)));

        // Insecure registry
        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        ContainerRef containerRef =
                ContainerRef.parse("localhost:%d/library/%s".formatted(wmRuntimeInfo.getHttpPort(), registryName));
        return registry.getBlob(containerRef.withDigest(digest));
    }

    @Test
    void pullArtifactShouldRejectInvalidTitleAnnotation(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");

        // Craft a blob and build a manifest whose layer title contains a invalid sequence
        byte[] blobContent = "malicious content".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String blobDigest = SupportedAlgorithm.SHA256.digest(blobContent);

        Layer maliciousLayer = Layer.fromDigest(blobDigest, blobContent.length)
                .withAnnotations(Map.of(Const.ANNOTATION_TITLE, "../traversed-file.txt"));

        Manifest manifest = Manifest.empty().withLayers(List.of(maliciousLayer));
        String manifestJson = JsonUtils.toJson(manifest);
        String manifestDigest =
                SupportedAlgorithm.SHA256.digest(manifestJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        // Stub HEAD manifest
        wireMock.register(head(urlEqualTo("/v2/library/malicious-artifact/manifests/latest"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader(Const.CONTENT_TYPE_HEADER, Const.DEFAULT_MANIFEST_MEDIA_TYPE)
                        .withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, manifestDigest)));

        // Stub GET manifest
        wireMock.register(get(urlEqualTo("/v2/library/malicious-artifact/manifests/latest"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader(Const.CONTENT_TYPE_HEADER, Const.DEFAULT_MANIFEST_MEDIA_TYPE)
                        .withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, manifestDigest)
                        .withBody(manifestJson)));

        // Stub GET blob
        wireMock.register(get(urlEqualTo("/v2/library/malicious-artifact/blobs/%s".formatted(blobDigest)))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(blobContent)
                        .withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, blobDigest)));

        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        ContainerRef containerRef = ContainerRef.parse("%s/library/malicious-artifact:latest".formatted(registryUrl));

        Path outputDir = configDir.resolve("pull-output");
        Files.createDirectories(outputDir);

        // Check exception
        Throwable cause = assertThrows(
                Exception.class,
                () -> registry.pullArtifact(containerRef, outputDir, true),
                "Expected an exception for title annotation");
        while (cause.getCause() != null && !(cause instanceof OrasException)) {
            cause = cause.getCause();
        }
        assertInstanceOf(
                OrasException.class,
                cause,
                "Root cause should be OrasException but was: "
                        + cause.getClass().getName());
        assertTrue(
                cause.getMessage().contains("is not withing folder"),
                "Exception message should mention is not withing folder but was: " + cause.getMessage());

        // The file must NOT have been written outside the output directory
        assertFalse(
                Files.exists(outputDir.getParent().resolve("traversed-file.txt")),
                "Blob must not be written outside the output directory");
    }

    @Test
    void shouldRetryOn429WithRetryAfterHeader(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");

        // First call: 429 with Retry-After: 0 (immediate retry in tests)
        wireMock.register(get(urlEqualTo("/v2/library/rate-limited-retry/tags/list"))
                .inScenario("rate-limit-retry")
                .whenScenarioStateIs(Scenario.STARTED)
                .willReturn(aResponse()
                        .withStatus(429)
                        .withHeader("Retry-After", "0")
                        .withBody("Rate limited"))
                .willSetStateTo("retry"));

        // Second call: success
        wireMock.register(get(urlEqualTo("/v2/library/rate-limited-retry/tags/list"))
                .inScenario("rate-limit-retry")
                .whenScenarioStateIs("retry")
                .willReturn(okJson(JsonUtils.toJson(new Tags("rate-limited-retry", List.of("latest"))))));

        Registry registry = Registry.Builder.builder()
                .withInsecure(true)
                .withRetryDelay(0)
                .withMaxRetries(2)
                .build();

        ContainerRef ref = ContainerRef.parse("%s/library/rate-limited-retry".formatted(registryUrl));
        Tags tags = registry.getTags(ref);
        assertEquals(List.of("latest"), tags.tags());

        // Verify the server was called exactly twice (one failure + one retry)
        WireMock.verify(2, getRequestedFor(urlEqualTo("/v2/library/rate-limited-retry/tags/list")));
    }

    @Test
    void shouldRetryOn429WithExponentialBackoff(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");

        // Two 429 responses without Retry-After, then success
        wireMock.register(get(urlEqualTo("/v2/library/rate-limited-backoff/tags/list"))
                .inScenario("backoff-retry")
                .whenScenarioStateIs(Scenario.STARTED)
                .willReturn(aResponse().withStatus(429).withBody("Rate limited"))
                .willSetStateTo("retry-1"));

        wireMock.register(get(urlEqualTo("/v2/library/rate-limited-backoff/tags/list"))
                .inScenario("backoff-retry")
                .whenScenarioStateIs("retry-1")
                .willReturn(aResponse().withStatus(429).withBody("Rate limited"))
                .willSetStateTo("retry-2"));

        wireMock.register(get(urlEqualTo("/v2/library/rate-limited-backoff/tags/list"))
                .inScenario("backoff-retry")
                .whenScenarioStateIs("retry-2")
                .willReturn(okJson(JsonUtils.toJson(new Tags("rate-limited-backoff", List.of("v1"))))));

        Registry registry = Registry.Builder.builder()
                .withInsecure(true)
                .withRetryDelay(0)
                .withMaxRetries(3)
                .build();

        ContainerRef ref = ContainerRef.parse("%s/library/rate-limited-backoff".formatted(registryUrl));
        Tags tags = registry.getTags(ref);
        assertEquals(List.of("v1"), tags.tags());

        WireMock.verify(3, getRequestedFor(urlEqualTo("/v2/library/rate-limited-backoff/tags/list")));
    }

    @Test
    void shouldRetryOnNetworkError(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");

        // First call: connection reset (IOException); second: success
        wireMock.register(get(urlEqualTo("/v2/library/network-error-retry/tags/list"))
                .inScenario("network-error-retry")
                .whenScenarioStateIs(Scenario.STARTED)
                .willReturn(aResponse().withFault(com.github.tomakehurst.wiremock.http.Fault.CONNECTION_RESET_BY_PEER))
                .willSetStateTo("retry"));

        wireMock.register(get(urlEqualTo("/v2/library/network-error-retry/tags/list"))
                .inScenario("network-error-retry")
                .whenScenarioStateIs("retry")
                .willReturn(okJson(JsonUtils.toJson(new Tags("network-error-retry", List.of("latest"))))));

        Registry registry = Registry.Builder.builder()
                .withInsecure(true)
                .withRetryDelay(0)
                .withMaxRetries(2)
                .build();

        ContainerRef ref = ContainerRef.parse("%s/library/network-error-retry".formatted(registryUrl));
        Tags tags = registry.getTags(ref);
        assertEquals(List.of("latest"), tags.tags());

        WireMock.verify(2, getRequestedFor(urlEqualTo("/v2/library/network-error-retry/tags/list")));
    }

    @Test
    void shouldNotRetryOnClientError(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");

        wireMock.register(get(urlEqualTo("/v2/library/not-found/tags/list"))
                .willReturn(aResponse().withStatus(404).withBody("Not found")));

        Registry registry = Registry.Builder.builder()
                .withInsecure(true)
                .withRetryDelay(0)
                .withMaxRetries(3)
                .build();

        ContainerRef ref = ContainerRef.parse("%s/library/not-found".formatted(registryUrl));
        OrasException exception = assertThrows(OrasException.class, () -> registry.getTags(ref));
        assertEquals(404, exception.getStatusCode());

        // Must be called exactly once — no retry on 4xx
        WireMock.verify(1, getRequestedFor(urlEqualTo("/v2/library/not-found/tags/list")));
    }

    @Test
    void shouldExhaustRetriesAndThrow(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");

        // Always return 500
        wireMock.register(get(urlEqualTo("/v2/library/always-fails/tags/list"))
                .willReturn(aResponse().withStatus(500).withBody("Server error")));

        Registry registry = Registry.Builder.builder()
                .withInsecure(true)
                .withRetryDelay(0)
                .withMaxRetries(3)
                .build();

        ContainerRef ref = ContainerRef.parse("%s/library/always-fails".formatted(registryUrl));
        assertThrows(OrasException.class, () -> registry.getTags(ref));

        // 3 attempts total (initial + 2 retries)
        WireMock.verify(3, getRequestedFor(urlEqualTo("/v2/library/always-fails/tags/list")));
    }

    @Test
    void shouldNotRetryTokenRefreshRequest(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");
        String digest = SupportedAlgorithm.SHA256.digest("blob-data".getBytes());

        // Registry returns 401 to trigger token refresh
        wireMock.register(get(urlPathEqualTo("/v2/library/no-retry-token/blobs/%s".formatted(digest)))
                .willReturn(forbidden()
                        .withHeader(
                                Const.WWW_AUTHENTICATE_HEADER,
                                "Bearer realm=\"http://localhost:%d/token\",service=\"localhost\",scope=\"repository:library/no-retry-token:pull\""
                                        .formatted(wmRuntimeInfo.getHttpPort()))));

        // Token endpoint always fails with 500
        wireMock.register(get(urlPathEqualTo("/token"))
                .willReturn(aResponse().withStatus(500).withBody("Token service unavailable")));

        Registry registry = Registry.Builder.builder()
                .withInsecure(true)
                .withRetryDelay(0)
                .withMaxRetries(3)
                .build();

        ContainerRef ref =
                ContainerRef.parse("localhost:%d/library/no-retry-token".formatted(wmRuntimeInfo.getHttpPort()));
        assertThrows(OrasException.class, () -> registry.getBlob(ref.withDigest(digest)));

        // Token endpoint must be called exactly once — no retry on token refresh
        WireMock.verify(1, getRequestedFor(urlPathEqualTo("/token")));
    }

    @Test
    void shouldFailChunkedUploadWhenInitiationReturnsNon202(WireMockRuntimeInfo wmRuntimeInfo) throws IOException {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String registryUrl = wmRuntimeInfo.getHttpBaseUrl().replace("http://", "");

        // The POST that opens a chunked-upload session returns 500 instead of 202.
        wireMock.register(post(urlPathMatching("/v2/library/chunked-init-error/blobs/uploads/"))
                .willReturn(aResponse().withStatus(500).withBody("Internal Server Error")));

        // HEAD for the prior-existence check returns 404 (blob does not exist yet).
        wireMock.register(head(urlPathMatching("/v2/library/chunked-init-error/blobs/.*"))
                .willReturn(aResponse().withStatus(404)));

        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        byte[] content = "hello".getBytes(StandardCharsets.UTF_8);
        String digest = SupportedAlgorithm.SHA256.digest(content);

        // Path overload
        Path blobFile = configDir.resolve("chunked-init-error.txt");
        Files.write(blobFile, content);
        ContainerRef refPath = ContainerRef.parse("%s/library/chunked-init-error".formatted(registryUrl));

        OrasException exPath = assertThrows(OrasException.class, () -> registry.pushBlobChunked(refPath, blobFile, 4L));
        assertEquals(
                "Failed to initiate chunked blob upload: status 500",
                exPath.getMessage(),
                "Exception message should include the unexpected status code");

        // InputStream overload
        ContainerRef refStream = ContainerRef.parse("%s/library/chunked-init-error".formatted(registryUrl))
                .withDigest(digest);

        OrasException exStream = assertThrows(
                OrasException.class,
                () -> registry.pushBlobChunked(
                        refStream, new java.io.ByteArrayInputStream(content), content.length, 4L));
        assertEquals(
                "Failed to initiate chunked blob upload: status 500",
                exStream.getMessage(),
                "Exception message should include the unexpected status code");
    }

    @Test
    void shouldFailCopyWhenIndexNestingExceedsMaxDepth(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String repo = "library/deep-chain";

        // A malicious source serves an unbounded chain of nested indexes
        int levels = 40;
        String[] digests = new String[levels + 2];
        digests[levels + 1] = SupportedAlgorithm.SHA256.digest("deep-chain-leaf".getBytes(StandardCharsets.UTF_8));
        for (int i = levels; i >= 0; i--) {
            digests[i] = SupportedAlgorithm.SHA256.digest(
                    nestedIndexJson(digests[i + 1]).getBytes(StandardCharsets.UTF_8));
        }

        // Deeper levels
        stubNestedSourceIndex(wireMock, repo, "chain", digests[0], digests[1]);
        for (int i = 1; i <= levels; i++) {
            stubNestedSourceIndex(wireMock, repo, digests[i], digests[i], digests[i + 1]);
        }

        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        ContainerRef source = ContainerRef.parse("localhost:%d/%s:chain".formatted(wmRuntimeInfo.getHttpPort(), repo));
        ContainerRef target = ContainerRef.parse(
                "localhost:%d/library/deep-chain-target:copy".formatted(wmRuntimeInfo.getHttpPort()));

        OrasException e = assertThrows(
                OrasException.class,
                () -> CopyUtils.copy(registry, source, registry, target, CopyUtils.CopyOptions.deep()));
        assertTrue(
                e.getMessage().contains("recursion depth"),
                "Expected a recursion depth error but got: " + e.getMessage());
    }

    @Test
    void shouldCopyWithoutLoopingOnCyclicIndexGraph(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String srcRepo = "library/cyclic-src";
        String dstRepo = "library/cyclic-dst";

        // A malicious source serves a self-referential index
        String digestA = SupportedAlgorithm.SHA256.digest("cyclic-self".getBytes(StandardCharsets.UTF_8));

        // Reference itself
        stubNestedSourceIndex(wireMock, srcRepo, "self", digestA, digestA);
        wireMock.register(WireMock.head(WireMock.urlEqualTo("/v2/%s/manifests/%s".formatted(srcRepo, digestA)))
                .willReturn(WireMock.ok()
                        .withHeader(Const.CONTENT_TYPE_HEADER, Const.DEFAULT_INDEX_MEDIA_TYPE)
                        .withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, digestA)));

        // Generic target: accept any manifest push and return an empty index on the follow-up read.
        String emptyIndex =
                """
                {
                  "schemaVersion": 2,
                  "mediaType": "%s",
                  "manifests": []
                }"""
                        .formatted(Const.DEFAULT_INDEX_MEDIA_TYPE);
        wireMock.register(WireMock.put(WireMock.urlMatching("/v2/%s/manifests/.*".formatted(dstRepo)))
                .willReturn(WireMock.created().withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, digestA)));
        wireMock.register(WireMock.head(WireMock.urlMatching("/v2/%s/manifests/.*".formatted(dstRepo)))
                .willReturn(WireMock.ok()
                        .withHeader(Const.CONTENT_TYPE_HEADER, Const.DEFAULT_INDEX_MEDIA_TYPE)
                        .withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, digestA)));
        wireMock.register(WireMock.get(WireMock.urlMatching("/v2/%s/manifests/.*".formatted(dstRepo)))
                .willReturn(WireMock.ok()
                        .withHeader(Const.CONTENT_TYPE_HEADER, Const.DEFAULT_INDEX_MEDIA_TYPE)
                        .withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, digestA)
                        .withBody(emptyIndex)));

        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        ContainerRef source =
                ContainerRef.parse("localhost:%d/%s:self".formatted(wmRuntimeInfo.getHttpPort(), srcRepo));
        ContainerRef target =
                ContainerRef.parse("localhost:%d/%s:copy".formatted(wmRuntimeInfo.getHttpPort(), dstRepo));

        // Terminates rather than looping / overflowing.
        CopyUtils.copy(registry, source, registry, target, CopyUtils.CopyOptions.deep());

        // The cycle guard returned before getIndex
        wireMock.verifyThat(
                0, WireMock.getRequestedFor(WireMock.urlEqualTo("/v2/%s/manifests/%s".formatted(srcRepo, digestA))));
        wireMock.verifyThat(
                WireMock.headRequestedFor(WireMock.urlEqualTo("/v2/%s/manifests/%s".formatted(srcRepo, digestA))));
    }

    /**
     * Build the JSON of an index whose single entry is another index (the child).
     */
    private static String nestedIndexJson(String childDigest) {
        return """
                {
                  "schemaVersion": 2,
                  "mediaType": "%s",
                  "manifests": [
                    {
                      "mediaType": "%s",
                      "digest": "%s",
                      "size": 100
                    }
                  ]
                }"""
                .formatted(Const.DEFAULT_INDEX_MEDIA_TYPE, Const.DEFAULT_INDEX_MEDIA_TYPE, childDigest);
    }

    /**
     * Stub HEAD + GET on a source index that references a single nested (child) index.
     */
    private static void stubNestedSourceIndex(
            WireMock wireMock, String repo, String ref, String selfDigest, String childDigest) {
        String url = "/v2/%s/manifests/%s".formatted(repo, ref);
        wireMock.register(WireMock.head(WireMock.urlEqualTo(url))
                .willReturn(WireMock.ok()
                        .withHeader(Const.CONTENT_TYPE_HEADER, Const.DEFAULT_INDEX_MEDIA_TYPE)
                        .withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, selfDigest)));
        wireMock.register(WireMock.get(WireMock.urlEqualTo(url))
                .willReturn(WireMock.ok()
                        .withHeader(Const.CONTENT_TYPE_HEADER, Const.DEFAULT_INDEX_MEDIA_TYPE)
                        .withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, selfDigest)
                        .withBody(nestedIndexJson(childDigest))));
    }

    @Test
    void shouldRejectBlobWhenContentDoesNotMatchPinnedDigest(WireMockRuntimeInfo wmRuntimeInfo) {
        String pinnedDigest = SupportedAlgorithm.SHA256.digest("good-data".getBytes(StandardCharsets.UTF_8));
        String evil = "evil-data";
        String selfConsistentHeader = SupportedAlgorithm.SHA256.digest(evil.getBytes(StandardCharsets.UTF_8));

        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(WireMock.get(WireMock.urlEqualTo("/v2/library/evil-blob/blobs/%s".formatted(pinnedDigest)))
                .willReturn(WireMock.ok()
                        .withBody(evil)
                        .withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, selfConsistentHeader)));

        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();
        ContainerRef ref = ContainerRef.parse("localhost:%d/library/evil-blob".formatted(wmRuntimeInfo.getHttpPort()))
                .withDigest(pinnedDigest);

        OrasException ex = assertThrows(OrasException.class, () -> registry.getBlob(ref));
        assertTrue(ex.getMessage().contains("Digest mismatch"), "Unexpected: " + ex.getMessage());
    }

    @Test
    void shouldReturnBinaryBlobWithoutCorruption(WireMockRuntimeInfo wmRuntimeInfo) {
        byte[] binary = new byte[] {0x00, (byte) 0xC3, 0x28, (byte) 0xFF, (byte) 0x80, 0x7F, (byte) 0xFE};
        String digest = SupportedAlgorithm.SHA256.digest(binary);

        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(WireMock.get(WireMock.urlEqualTo("/v2/library/bin-blob/blobs/%s".formatted(digest)))
                .willReturn(WireMock.ok().withBody(binary).withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, digest)));

        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();
        ContainerRef ref = ContainerRef.parse("localhost:%d/library/bin-blob".formatted(wmRuntimeInfo.getHttpPort()))
                .withDigest(digest);

        assertArrayEquals(binary, registry.getBlob(ref));
    }

    @Test
    void shouldRejectFetchBlobToPathOnDigestMismatch(WireMockRuntimeInfo wmRuntimeInfo) {
        String pinnedDigest = SupportedAlgorithm.SHA256.digest("good".getBytes(StandardCharsets.UTF_8));

        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(WireMock.get(WireMock.urlEqualTo("/v2/library/evil-file/blobs/%s".formatted(pinnedDigest)))
                .willReturn(WireMock.ok().withBody("tampered")));

        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();
        ContainerRef ref = ContainerRef.parse("localhost:%d/library/evil-file".formatted(wmRuntimeInfo.getHttpPort()))
                .withDigest(pinnedDigest);
        Path out = configDir.resolve("blob-out.bin");

        OrasException ex = assertThrows(OrasException.class, () -> registry.fetchBlob(ref, out));
        assertTrue(ex.getMessage().contains("Digest mismatch"), "Unexpected: " + ex.getMessage());
    }

    @Test
    void shouldRejectBlobStreamOnDigestMismatch(WireMockRuntimeInfo wmRuntimeInfo) {
        String pinnedDigest = SupportedAlgorithm.SHA256.digest("good".getBytes(StandardCharsets.UTF_8));

        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(WireMock.get(WireMock.urlEqualTo("/v2/library/evil-stream/blobs/%s".formatted(pinnedDigest)))
                .willReturn(WireMock.ok().withBody("tampered")));

        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();
        ContainerRef ref = ContainerRef.parse("localhost:%d/library/evil-stream".formatted(wmRuntimeInfo.getHttpPort()))
                .withDigest(pinnedDigest);

        // The digest is verified incrementally, so the mismatch surfaces when the stream is read to EOF.
        OrasException ex = assertThrows(OrasException.class, () -> {
            try (InputStream is = registry.getBlobStream(ref)) {
                is.readAllBytes();
            }
        });
        assertTrue(ex.getMessage().contains("Digest mismatch"), "Unexpected: " + ex.getMessage());
    }

    @Test
    void shouldRejectManifestWhoseContentDoesNotMatchPinnedDigest(WireMockRuntimeInfo wmRuntimeInfo) {
        String realManifest =
                """
                {"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",\
                "config":{"mediaType":"application/vnd.oci.empty.v1+json",\
                "digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},\
                "layers":[]}""";
        String evilManifest = realManifest.replace("\"layers\":[]", "\"layers\":[],\"annotations\":{\"x\":\"y\"}");
        String pinnedDigest = SupportedAlgorithm.SHA256.digest(realManifest.getBytes(StandardCharsets.UTF_8));
        String selfConsistentHeader = SupportedAlgorithm.SHA256.digest(evilManifest.getBytes(StandardCharsets.UTF_8));

        WireMock wireMock = wmRuntimeInfo.getWireMock();
        String manifestPath = "/v2/library/evil-manifest/manifests/%s".formatted(pinnedDigest);
        wireMock.register(WireMock.head(WireMock.urlEqualTo(manifestPath))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader(Const.CONTENT_TYPE_HEADER, Const.DEFAULT_MANIFEST_MEDIA_TYPE)
                        .withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, selfConsistentHeader)));
        wireMock.register(WireMock.get(WireMock.urlEqualTo(manifestPath))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader(Const.CONTENT_TYPE_HEADER, Const.DEFAULT_MANIFEST_MEDIA_TYPE)
                        .withHeader(Const.DOCKER_CONTENT_DIGEST_HEADER, selfConsistentHeader)
                        .withBody(evilManifest)));

        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();
        ContainerRef ref = ContainerRef.parse(
                        "localhost:%d/library/evil-manifest".formatted(wmRuntimeInfo.getHttpPort()))
                .withDigest(pinnedDigest);

        OrasException ex = assertThrows(OrasException.class, () -> registry.getManifest(ref));
        assertTrue(ex.getMessage().contains("Digest mismatch"), "Unexpected: " + ex.getMessage());
    }

    @Test
    void shouldFailOnTagListPaginationExceedingMaxPages(WireMockRuntimeInfo wmRuntimeInfo) {

        // Returns one tag and a Link header pointing back to the same URL (self-referential)
        String page1 = JsonUtils.toJson(new Tags("artifact-text", List.of("v1.0")));

        // Returns a different tag but still loops
        String page2 = JsonUtils.toJson(new Tags("artifact-text", List.of("v2.0")));

        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(WireMock.get(WireMock.urlPathEqualTo("/v2/library/artifact-text/tags/list"))
                .withQueryParam("last", WireMock.absent())
                .willReturn(WireMock.okJson(page1)
                        .withHeader("Link", "</v2/library/artifact-text/tags/list?last=v1.0>; rel=\"next\"")));
        wireMock.register(WireMock.get(WireMock.urlPathEqualTo("/v2/library/artifact-text/tags/list"))
                .withQueryParam("last", WireMock.matching(".+"))
                .willReturn(WireMock.okJson(page2)
                        .withHeader("Link", "</v2/library/artifact-text/tags/list?last=v2.0>; rel=\"next\"")));

        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .withTagListMaxPages(2)
                .build();

        OrasException exception = assertThrows(
                OrasException.class,
                () -> registry.getTags(ContainerRef.parse("%s/library/artifact-text"
                        .formatted(wmRuntimeInfo.getHttpBaseUrl().replace("http://", "")))));
        assertTrue(
                exception.getMessage().contains("Tag listing exceeded 2 pages"),
                "Unexpected message: " + exception.getMessage());
    }

    @Test
    void shouldFailOnReferrerListPaginationExceedingMaxPages(WireMockRuntimeInfo wmRuntimeInfo) {

        String digest = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
        String referrersPath = "/v2/library/artifact-text/referrers/" + digest;

        // Minimal referrers index JSON with one manifest entry per page
        String page1 =
                """
                {"mediaType":"application/vnd.oci.image.index.v1+json","manifests":\
                [{"mediaType":"application/vnd.oci.image.manifest.v1+json",\
                "digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1}]}""";
        String page2 =
                """
                {"mediaType":"application/vnd.oci.image.index.v1+json","manifests":\
                [{"mediaType":"application/vnd.oci.image.manifest.v1+json",\
                "digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":1}]}""";

        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(WireMock.get(WireMock.urlPathEqualTo(referrersPath))
                .withQueryParam("last", WireMock.absent())
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.oci.image.index.v1+json")
                        .withHeader("Link", "<" + referrersPath + "?last=sha256:aaaa>; rel=\"next\"")
                        .withBody(page1)));
        wireMock.register(WireMock.get(WireMock.urlPathEqualTo(referrersPath))
                .withQueryParam("last", WireMock.matching(".+"))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.oci.image.index.v1+json")
                        .withHeader("Link", "<" + referrersPath + "?last=sha256:bbbb>; rel=\"next\"")
                        .withBody(page2)));

        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .withReferrerListMaxPages(2)
                .build();

        ContainerRef ref = ContainerRef.parse("%s/library/artifact-text"
                        .formatted(wmRuntimeInfo.getHttpBaseUrl().replace("http://", "")))
                .withDigest(digest);

        OrasException exception = assertThrows(OrasException.class, () -> registry.getReferrers(ref, null));
        assertTrue(
                exception.getMessage().contains("Referrer listing exceeded 2 pages"),
                "Unexpected message: " + exception.getMessage());
    }

    @Test
    void shouldFallbackToReferrersTagSchemaWhenReferrersApiUnavailable(WireMockRuntimeInfo wmRuntimeInfo) {

        String digest = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
        String referrersPath = "/v2/library/artifact-text/referrers/" + digest;
        String fallbackTagPath = "/v2/library/artifact-text/manifests/"
                + "sha256-44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

        String fallbackIndex =
                """
                {"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":\
                [{"mediaType":"application/vnd.oci.image.manifest.v1+json",\
                "digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1,\
                "artifactType":"application/vnd.example+json"}]}""";

        WireMock wireMock = wmRuntimeInfo.getWireMock();
        // Registry does not implement the Referrers API (e.g. GHCR)
        wireMock.register(WireMock.get(WireMock.urlPathEqualTo(referrersPath)).willReturn(WireMock.notFound()));
        // Fallback to the referrers tag schema:
        wireMock.register(WireMock.get(WireMock.urlPathEqualTo(fallbackTagPath))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.oci.image.index.v1+json")
                        .withBody(fallbackIndex)));

        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        ContainerRef ref = ContainerRef.parse("%s/library/artifact-text"
                        .formatted(wmRuntimeInfo.getHttpBaseUrl().replace("http://", "")))
                .withDigest(digest);

        Referrers referrers = registry.getReferrers(ref, null);
        assertEquals(1, referrers.getManifests().size());
        assertEquals(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                referrers.getManifests().get(0).getDigest());
    }

    @Test
    void shouldFilterFallbackReferrersByArtifactType(WireMockRuntimeInfo wmRuntimeInfo) {

        String digest = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
        String referrersPath = "/v2/library/artifact-text/referrers/" + digest;
        String fallbackTagPath = "/v2/library/artifact-text/manifests/"
                + "sha256-44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

        String fallbackIndex =
                """
                {"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":\
                [{"mediaType":"application/vnd.oci.image.manifest.v1+json",\
                "digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1,\
                "artifactType":"application/vnd.example+json"},\
                {"mediaType":"application/vnd.oci.image.manifest.v1+json",\
                "digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":1,\
                "artifactType":"application/vnd.other+json"}]}""";

        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(WireMock.get(WireMock.urlPathEqualTo(referrersPath)).willReturn(WireMock.notFound()));
        wireMock.register(WireMock.get(WireMock.urlPathEqualTo(fallbackTagPath))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/vnd.oci.image.index.v1+json")
                        .withBody(fallbackIndex)));

        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        ContainerRef ref = ContainerRef.parse("%s/library/artifact-text"
                        .formatted(wmRuntimeInfo.getHttpBaseUrl().replace("http://", "")))
                .withDigest(digest);

        Referrers referrers = registry.getReferrers(ref, ArtifactType.from("application/vnd.example+json"));
        assertEquals(1, referrers.getManifests().size());
        assertEquals(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                referrers.getManifests().get(0).getDigest());
    }

    @Test
    void shouldReturnEmptyReferrersWhenFallbackTagDoesNotExist(WireMockRuntimeInfo wmRuntimeInfo) {

        String digest = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
        String referrersPath = "/v2/library/artifact-text/referrers/" + digest;
        String fallbackTagPath = "/v2/library/artifact-text/manifests/"
                + "sha256-44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(WireMock.get(WireMock.urlPathEqualTo(referrersPath)).willReturn(WireMock.notFound()));
        wireMock.register(WireMock.get(WireMock.urlPathEqualTo(fallbackTagPath)).willReturn(WireMock.notFound()));

        Registry registry = Registry.Builder.builder()
                .withAuthProvider(authProvider)
                .withInsecure(true)
                .build();

        ContainerRef ref = ContainerRef.parse("%s/library/artifact-text"
                        .formatted(wmRuntimeInfo.getHttpBaseUrl().replace("http://", "")))
                .withDigest(digest);

        Referrers referrers = registry.getReferrers(ref, null);
        assertTrue(referrers.getManifests().isEmpty());
    }
}
