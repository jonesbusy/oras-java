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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import land.oras.exception.OrasException;
import land.oras.utils.TlsUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

@Execution(ExecutionMode.CONCURRENT)
class HttpClientTest {

    private static final String ROOT_CA_PEM;
    private static final String ISSUING_CA_PEM;

    static {
        var rootKeyPair = TlsUtils.generateKeyPair();
        var rootCaCert = TlsUtils.generateCaCertificate("test-root-ca", rootKeyPair);
        ROOT_CA_PEM = TlsUtils.toPem(rootCaCert);

        var issuingKeyPair = TlsUtils.generateKeyPair();
        var issuingCaCert = TlsUtils.generateSignedCertificate(
                "test-issuing-ca", issuingKeyPair, rootCaCert, rootKeyPair.getPrivate());
        ISSUING_CA_PEM = TlsUtils.toPem(issuingCaCert);
    }

    @Test
    void shouldFallBackToTokenWhenAccessTokenIsEmpty() {
        HttpClient.TokenResponse response = new HttpClient.TokenResponse("token-value", "", null, null, null);

        assertEquals("token-value", response.getEffectiveToken());
    }

    @Test
    void testIsSameOriginSame() {
        URI uri1 = URI.create("https://example.com:443/path");
        URI uri2 = URI.create("https://example.com/path2");
        assertTrue(HttpClient.isSameOrigin(uri1, uri2));
    }

    @Test
    void testIsSameOriginDifferentPort() {
        URI uri1 = URI.create("http://example.com:8080");
        URI uri2 = URI.create("http://example.com");
        assertFalse(HttpClient.isSameOrigin(uri1, uri2));
    }

    @Test
    void testIsSameOriginDifferentScheme() {
        URI uri1 = URI.create("http://example.com");
        URI uri2 = URI.create("https://example.com");
        assertFalse(HttpClient.isSameOrigin(uri1, uri2));
    }

    @Test
    void testIsSameOriginDifferentHost() {
        URI uri1 = URI.create("http://example.com");
        URI uri2 = URI.create("http://example.org");
        assertFalse(HttpClient.isSameOrigin(uri1, uri2));
    }

    @Test
    void shouldAcceptPublicCrossHostBearerRealm() {
        URI registry = URI.create("https://registry.example.com/v2/");
        URI realm = HttpClient.validateRealm(registry, "https://auth.example.com/token");

        assertEquals("auth.example.com", realm.getHost());
    }

    @Test
    void shouldRejectHttpBearerRealmForHttpsRegistry() {
        URI registry = URI.create("https://registry.example.com/v2/");

        assertThrows(OrasException.class, () -> HttpClient.validateRealm(registry, "http://auth.example.com/token"));
    }

    @Test
    void shouldRejectLoopbackBearerRealmForDifferentRegistryHost() {
        URI registry = URI.create("http://registry.example.com/v2/");

        assertThrows(OrasException.class, () -> HttpClient.validateRealm(registry, "http://127.0.0.1:8080/token"));
    }

    @Test
    void shouldAllowLoopbackBearerRealmForSameRegistryHost() {
        URI registry = URI.create("http://127.0.0.1:5000/v2/");

        assertDoesNotThrow(() -> HttpClient.validateRealm(registry, "http://127.0.0.1:8080/token"));
    }

    @Test
    void testGetPortExplicit() {
        URI uri = URI.create("http://example.com:8080");
        assertEquals(8080, HttpClient.getPort(uri));
    }

    @Test
    void testGetPortDefaultHttp() {
        URI uri = URI.create("http://example.com");
        assertEquals(80, HttpClient.getPort(uri));
    }

    @Test
    void testGetPortDefaultHttps() {
        URI uri = URI.create("https://example.com");
        assertEquals(443, HttpClient.getPort(uri));
    }

    @Test
    void testShouldRedirectTrue301() {
        HttpResponse<?> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(HttpURLConnection.HTTP_MOVED_PERM);
        assertTrue(HttpClient.shouldRedirect(response));
    }

    @Test
    void testShouldRedirectTrue302() {
        HttpResponse<?> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(HttpURLConnection.HTTP_MOVED_TEMP);
        assertTrue(HttpClient.shouldRedirect(response));
    }

    @Test
    void testShouldRedirectTrue307() {
        HttpResponse<?> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(307);
        assertTrue(HttpClient.shouldRedirect(response));
    }

    @Test
    void testShouldRedirectFalse() {
        HttpResponse<?> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(200);
        assertFalse(HttpClient.shouldRedirect(response));
    }

    @Test
    void whenCaFileFromPathThenSucceed(@TempDir Path tempDir) throws IOException {
        Path caFile = tempDir.resolve("ca.pem");
        Files.writeString(caFile, ROOT_CA_PEM);
        assertDoesNotThrow(() -> HttpClient.Builder.builder().withCaFile(caFile).build());
    }

    @Test
    void whenCaFileFromStringThenSucceed(@TempDir Path tempDir) throws IOException {
        Path caFile = tempDir.resolve("ca.pem");
        Files.writeString(caFile, ROOT_CA_PEM);
        assertDoesNotThrow(
                () -> HttpClient.Builder.builder().withCaFile(caFile.toString()).build());
    }

    @Test
    void whenCaFileDoesNotExistThenThrow() {
        OrasException exception = assertThrows(
                OrasException.class,
                () -> HttpClient.Builder.builder()
                        .withCaFile(Path.of("/nonexistent/ca.pem"))
                        .build());
        assertTrue(exception.getMessage().contains("Unable to configure CA file"));
    }

    @Test
    void whenCaFileNotValidCertificateThenThrow(@TempDir Path tempDir) throws IOException {
        Path caFile = tempDir.resolve("bad.pem");
        Files.writeString(caFile, "not a certificate");
        OrasException exception = assertThrows(
                OrasException.class,
                () -> HttpClient.Builder.builder().withCaFile(caFile).build());
        assertTrue(exception.getMessage().contains("Unable to configure CA file"));
    }

    @Test
    void whenCaFileIsEmptyThenThrow(@TempDir Path tempDir) throws IOException {
        Path caFile = Files.createFile(tempDir.resolve("empty.pem"));
        OrasException exception = assertThrows(
                OrasException.class,
                () -> HttpClient.Builder.builder().withCaFile(caFile).build());
        assertTrue(exception.getMessage().contains("No certificates found in the provided CA file"));
    }

    @Test
    void whenCaContentThenSucceed() {
        assertDoesNotThrow(
                () -> HttpClient.Builder.builder().withCaContent(ROOT_CA_PEM).build());
    }

    @Test
    void whenCaContentIsEmptyThenThrow() {
        OrasException exception = assertThrows(
                OrasException.class,
                () -> HttpClient.Builder.builder().withCaContent("").build());
        assertTrue(exception.getMessage().contains("No certificates found in the provided CA content"));
    }

    @Test
    void whenCaContentNotValidCertificateThenThrow() {
        OrasException exception = assertThrows(
                OrasException.class,
                () -> HttpClient.Builder.builder()
                        .withCaContent("not a certificate")
                        .build());
        assertTrue(exception.getMessage().contains("Unable to configure CA certificates from content"));
    }

    @Test
    void whenBothCaFileAndCaContentConfiguredThenThrow(@TempDir Path tempDir) throws IOException {
        Path caFile = tempDir.resolve("ca.pem");
        Files.writeString(caFile, ROOT_CA_PEM);
        OrasException exception = assertThrows(
                OrasException.class,
                () -> HttpClient.Builder.builder()
                        .withCaFile(caFile)
                        .withCaContent(ROOT_CA_PEM)
                        .build());
        assertTrue(exception.getMessage().contains("Cannot configure both a CA file and CA content"));
    }

    @Test
    void whenSkipTlsVerifyAndCaFileThenThrow(@TempDir Path tempDir) throws IOException {
        Path caFile = tempDir.resolve("ca.pem");
        Files.writeString(caFile, ROOT_CA_PEM);
        OrasException exception = assertThrows(
                OrasException.class,
                () -> HttpClient.Builder.builder()
                        .withSkipTlsVerify(true)
                        .withCaFile(caFile)
                        .build());
        assertTrue(exception.getMessage().contains("Cannot combine skipTlsVerify"));
    }

    @Test
    void whenSkipTlsVerifyAndCaContentThenThrow() {
        OrasException exception = assertThrows(
                OrasException.class,
                () -> HttpClient.Builder.builder()
                        .withSkipTlsVerify(true)
                        .withCaContent(ROOT_CA_PEM)
                        .build());
        assertTrue(exception.getMessage().contains("Cannot combine skipTlsVerify"));
    }

    @Test
    void whenCaBundleFromFileThenSucceed(@TempDir Path tempDir) throws IOException {
        Path caFile = tempDir.resolve("ca-bundle.pem");
        Files.writeString(caFile, ROOT_CA_PEM + ISSUING_CA_PEM);
        assertDoesNotThrow(() -> HttpClient.Builder.builder().withCaFile(caFile).build());
    }

    @Test
    void whenCaBundleFromContentThenSucceed() {
        assertDoesNotThrow(() -> HttpClient.Builder.builder()
                .withCaContent(ROOT_CA_PEM + ISSUING_CA_PEM)
                .build());
    }
}
