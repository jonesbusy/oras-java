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

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Timer;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.*;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import land.oras.ContainerRef;
import land.oras.OrasModel;
import land.oras.exception.OrasException;
import land.oras.utils.Const;
import land.oras.utils.JsonUtils;
import land.oras.utils.Versions;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HTTP client for ORAS
 */
@NullMarked
public final class HttpClient {

    /**
     * Logger
     */
    private static final Logger LOG = LoggerFactory.getLogger(HttpClient.class);

    /**
     * The pattern for the WWW-Authenticate header value
     */
    private static final Pattern WWW_AUTH_VALUE_PATTERN =
            Pattern.compile("Bearer realm=\"([^\"]+)\",service=\"([^\"]+)\",scope=\"([^\"]+)\"(,error=\"([^\"]+)\")?");

    /**
     * The HTTP client builder
     */
    private final java.net.http.HttpClient.Builder builder;

    /**
     * The HTTP client
     */
    private java.net.http.HttpClient client;

    /**
     * Skip TLS verification
     */
    private boolean skipTlsVerify;

    /**
     * Path to a PEM-encoded CA certificate or bundle
     */
    private @Nullable Path caFilePath;

    /**
     * PEM-encoded CA certificate or bundle content
     */
    private @Nullable String caContent;

    /**
     * Timeout in seconds
     */
    private Integer timeout;

    /**
     * Maximum number of attempts (1 = no retry, 2 = one retry, …)
     */
    private int maxRetries = 3;

    /**
     * Initial delay between retries in milliseconds (doubles on each attempt)
     */
    private long retryDelayMs = 500L;

    /**
     * Upper bound on retry delay in milliseconds
     */
    private long maxRetryDelayMs = 30_000L;

    /**
     * The meter registry for metrics
     */
    private MeterRegistry meterRegistry;
    /**
     * Hidden constructor
     */
    private HttpClient() {
        this.builder = java.net.http.HttpClient.newBuilder();
        this.builder.followRedirects(
                java.net.http.HttpClient.Redirect
                        .NEVER); // No automatic redirect, only GET and HEAD request will redirect
        this.skipTlsVerify = false;
        this.builder.cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_NONE));
        this.setTimeout(60);
        this.meterRegistry = Metrics.globalRegistry;
    }

    /**
     * Set the timeout
     * @param timeout The timeout in seconds
     */
    private void setTimeout(@Nullable Integer timeout) {
        if (timeout != null) {
            this.timeout = timeout;
            this.builder.connectTimeout(Duration.ofSeconds(timeout));
        }
    }

    /**
     * Skip the TLS verification
     * @param skipTlsVerify Skip TLS verification
     */
    private void setSkipTlsVerify(boolean skipTlsVerify) {
        this.skipTlsVerify = skipTlsVerify;
    }

    /**
     * Set the CA certificates for TLS verification from a file
     * @param caFilePath The path to a PEM-encoded CA certificate or bundle
     */
    private void setCaFile(Path caFilePath) {
        this.caFilePath = caFilePath;
    }

    /**
     * Set the CA certificates for TLS verification from PEM-encoded content
     * @param caContent The PEM-encoded CA certificate or bundle content
     */
    private void setCaContent(String caContent) {
        this.caContent = caContent;
    }

    /**
     * Configure SSL context from a PEM-encoded CA file
     * @param caFilePath The path to a PEM-encoded CA certificate or bundle
     */
    private void configureTlsFromFile(Path caFilePath) {
        try (InputStream inputStream = new BufferedInputStream(Files.newInputStream(caFilePath))) {
            configureCaCertificates(inputStream, "CA file: " + caFilePath);
        } catch (OrasException e) {
            throw e;
        } catch (Exception e) {
            throw new OrasException("Unable to configure CA file: " + caFilePath, e);
        }
    }

    /**
     * Configure SSL context from PEM-encoded CA content
     * @param caContent The PEM-encoded CA certificate or bundle content
     */
    private void configureTlsFromContent(String caContent) {
        try (InputStream inputStream = new ByteArrayInputStream(caContent.getBytes(StandardCharsets.UTF_8))) {
            configureCaCertificates(inputStream, "CA content");
        } catch (OrasException e) {
            throw e;
        } catch (Exception e) {
            throw new OrasException("Unable to configure CA certificates from content", e);
        }
    }

    /**
     * Configure SSL context from PEM-encoded CA certificates read from the given input stream.
     * @param inputStream The input stream containing PEM-encoded certificates
     * @param source A description of the certificate source for error messages
     */
    private void configureCaCertificates(InputStream inputStream, String source) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);

        int certificateIndex = 0;
        Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(inputStream);
        if (certificates.isEmpty()) {
            throw new OrasException("No certificates found in the provided " + source);
        }
        for (var certificate : certificates) {
            trustStore.setCertificateEntry("ca-" + certificateIndex++, certificate);
        }

        TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
        builder.sslContext(sslContext);
    }

    /**
     * Configure SSL context to skip TLS verification
     */
    private void configureInsecureTls() {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] {new InsecureTrustManager()}, new SecureRandom());
            builder.sslContext(sslContext);
        } catch (Exception e) {
            throw new OrasException("Unable to skip TLS verification", e);
        }
    }

    /**
     * Create a new HTTP client
     * @return The client
     */
    public HttpClient build() {
        if (caFilePath != null && caContent != null) {
            throw new OrasException(
                    "Cannot configure both a CA file and CA content. Use either withCaFile() or withCaContent(), not both");
        }
        if (skipTlsVerify && (caFilePath != null || caContent != null)) {
            throw new OrasException(
                    "Cannot combine skipTlsVerify with a CA file or CA content. Use either withSkipTlsVerify() or withCaFile()/withCaContent(), not both");
        }

        if (skipTlsVerify) {
            configureInsecureTls();
        } else if (caFilePath != null) {
            configureTlsFromFile(caFilePath);
        } else if (caContent != null) {
            configureTlsFromContent(caContent);
        }

        this.client = this.builder.build();
        return this;
    }

    /**
     * Perform a GET request
     * @param uri The URI
     * @param headers The headers
     * @param scopes The scopes
     * @param authProvider The authentication provider
     * @return The response
     */
    public ResponseWrapper<String> get(URI uri, Map<String, String> headers, Scopes scopes, AuthProvider authProvider) {
        return executeRequest(
                "GET",
                uri,
                true,
                headers,
                new byte[0],
                HttpResponse.BodyHandlers.ofString(),
                HttpRequest.BodyPublishers.noBody(),
                scopes,
                authProvider,
                true);
    }

    private ResponseWrapper<String> getForTokenRefresh(
            URI uri, Map<String, String> headers, Scopes scopes, AuthProvider authProvider) {
        return executeRequest(
                "GET",
                uri,
                true,
                headers,
                new byte[0],
                HttpResponse.BodyHandlers.ofString(),
                HttpRequest.BodyPublishers.noBody(),
                scopes,
                authProvider,
                false);
    }

    /**
     * Download to a file
     * @param uri The URI
     * @param headers The headers
     * @param file The file
     * @param scopes The scopes
     * @param authProvider The authentication provider
     * @return The response
     */
    public ResponseWrapper<Path> download(
            URI uri, Map<String, String> headers, Path file, Scopes scopes, AuthProvider authProvider) {
        return executeRequest(
                "GET",
                uri,
                true,
                headers,
                new byte[0],
                HttpResponse.BodyHandlers.ofFile(file),
                HttpRequest.BodyPublishers.noBody(),
                scopes,
                authProvider,
                true);
    }

    /**
     * Download to to input stream
     * @param uri The URI
     * @param headers The headers
     * @param scopes The scopes
     * @param authProvider The authentication provider
     * @return The response
     */
    public ResponseWrapper<InputStream> download(
            URI uri, Map<String, String> headers, Scopes scopes, AuthProvider authProvider) {
        return executeRequest(
                "GET",
                uri,
                true,
                headers,
                new byte[0],
                HttpResponse.BodyHandlers.ofInputStream(),
                HttpRequest.BodyPublishers.noBody(),
                scopes,
                authProvider,
                true);
    }

    /**
     * Upload a file
     * @param method The method (POST or PUT)
     * @param uri The URI
     * @param headers The headers
     * @param file The file
     * @param scopes The scopes
     * @param authProvider The authentication provider
     * @return The response
     */
    public ResponseWrapper<String> upload(
            String method, URI uri, Map<String, String> headers, Path file, Scopes scopes, AuthProvider authProvider) {
        try {
            return executeRequest(
                    method,
                    uri,
                    true,
                    headers,
                    new byte[0],
                    HttpResponse.BodyHandlers.ofString(),
                    HttpRequest.BodyPublishers.ofFile(file),
                    scopes,
                    authProvider,
                    true);
        } catch (FileNotFoundException e) {
            throw new OrasException("Unable to upload file. File not found.", e);
        }
    }

    /**
     * Upload from an input stream.
     * @param uri The URI
     * @param size The size of the input stream
     * @param headers The headers
     * @param stream The input stream
     * @param scopes The scopes
     * @param authProvider The authentication provider
     * @return The response
     */
    public ResponseWrapper<String> upload(
            URI uri,
            long size,
            Map<String, String> headers,
            Supplier<InputStream> stream,
            Scopes scopes,
            AuthProvider authProvider) {
        return executeRequest(
                "PUT",
                uri,
                true,
                headers,
                new byte[0],
                HttpResponse.BodyHandlers.ofString(),
                HttpRequest.BodyPublishers.fromPublisher(HttpRequest.BodyPublishers.ofInputStream(stream), size),
                scopes,
                authProvider,
                true);
    }

    /**
     * Perform a HEAD request
     * @param uri The URI
     * @param headers The headers
     * @param scopes The scopes
     * @param authProvider The authentication provider
     * @return The response
     */
    public ResponseWrapper<String> head(
            URI uri, Map<String, String> headers, Scopes scopes, AuthProvider authProvider) {
        return executeRequest(
                "HEAD",
                uri,
                true,
                headers,
                new byte[0],
                HttpResponse.BodyHandlers.ofString(),
                HttpRequest.BodyPublishers.noBody(),
                scopes,
                authProvider,
                true);
    }

    /**
     * Perform a DELETE request
     * @param uri The URI
     * @param headers The headers
     * @param scopes The scopes
     * @param authProvider The authentication provider
     * @return The response
     */
    public ResponseWrapper<String> delete(
            URI uri, Map<String, String> headers, Scopes scopes, AuthProvider authProvider) {
        return executeRequest(
                "DELETE",
                uri,
                true,
                headers,
                new byte[0],
                HttpResponse.BodyHandlers.ofString(),
                HttpRequest.BodyPublishers.noBody(),
                scopes,
                authProvider,
                true);
    }

    /**
     * Perform a POST request. Might not be suitable for large files. Use upload for large files.
     * @param uri The URI.
     * @param body The body
     * @param headers The headers
     * @param scopes The scopes
     * @param authProvider The authentication provider
     * @return The response
     */
    public ResponseWrapper<String> post(
            URI uri, byte[] body, Map<String, String> headers, Scopes scopes, AuthProvider authProvider) {
        return executeRequest(
                "POST",
                uri,
                true,
                headers,
                body,
                HttpResponse.BodyHandlers.ofString(),
                body.length == 0 ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body),
                scopes,
                authProvider,
                true);
    }

    /**
     * Perform a Patch request
     * @param uri The URI
     * @param body The body
     * @param headers The headers
     * @param scopes The scopes
     * @param authProvider The authentication provider
     * @return The response
     */
    public ResponseWrapper<String> patch(
            URI uri, byte[] body, Map<String, String> headers, Scopes scopes, AuthProvider authProvider) {
        return executeRequest(
                "PATCH",
                uri,
                true,
                headers,
                body,
                HttpResponse.BodyHandlers.ofString(),
                HttpRequest.BodyPublishers.ofByteArray(body),
                scopes,
                authProvider,
                true);
    }

    /**
     * Upload a chunk of data from an input stream using PATCH.
     * @param uri The URI
     * @param chunkSize The size of the chunk in bytes
     * @param headers The headers (should include Content-Range)
     * @param stream A supplier providing the input stream for this chunk
     * @param scopes The scopes
     * @param authProvider The authentication provider
     * @return The response
     */
    public ResponseWrapper<String> patch(
            URI uri,
            long chunkSize,
            Map<String, String> headers,
            Supplier<InputStream> stream,
            Scopes scopes,
            AuthProvider authProvider) {
        return executeRequest(
                "PATCH",
                uri,
                true,
                headers,
                new byte[0],
                HttpResponse.BodyHandlers.ofString(),
                HttpRequest.BodyPublishers.fromPublisher(HttpRequest.BodyPublishers.ofInputStream(stream), chunkSize),
                scopes,
                authProvider,
                true);
    }

    /**
     * Perform a PUT request
     * @param uri The URI
     * @param body The body
     * @param headers The headers
     * @param scopes The scopes
     * @param authProvider The authentication provider
     * @return The response
     */
    public ResponseWrapper<String> put(
            URI uri, byte[] body, Map<String, String> headers, Scopes scopes, AuthProvider authProvider) {
        return executeRequest(
                "PUT",
                uri,
                true,
                headers,
                body,
                HttpResponse.BodyHandlers.ofString(),
                HttpRequest.BodyPublishers.ofByteArray(body),
                scopes,
                authProvider,
                true);
    }

    /**
     * Retrieve a token from the registry
     * @param response The response that may contain a the WWW-Authenticate header
     * @param scopes The scopes
     * @param authProvider The authentication provider
     * @param <T> The response type
     * @return The token
     */
    public <T> TokenResponse refreshToken(
            HttpClient.ResponseWrapper<T> response, Scopes scopes, AuthProvider authProvider) {

        String wwwAuthHeader = response.headers().getOrDefault(Const.WWW_AUTHENTICATE_HEADER.toLowerCase(), "");
        LOG.debug("WWW-Authenticate header: {}", wwwAuthHeader);
        if (wwwAuthHeader.isEmpty()) {
            throw new OrasException(response.statusCode(), "No WWW-Authenticate header found in response");
        }

        Matcher matcher = WWW_AUTH_VALUE_PATTERN.matcher(wwwAuthHeader);
        if (!matcher.matches()) {
            throw new OrasException(response.statusCode(), "Invalid WWW-Authenticate header");
        }

        // Extract parts
        String realm = matcher.group(1);
        String service = matcher.group(2);
        String scope = matcher.group(3);
        String error = matcher.group(5);

        // Add server scope to existing scopes
        Scopes newScopes = scopes.withNewScope(scope).withService(service);
        LOG.debug("New scopes with server: {}", newScopes.getScopes());

        LOG.debug("WWW-Authenticate header: realm={}, service={}, scope={}, error={}", realm, service, scope, error);

        String query = "scope=%s&service=%s".formatted(scope, URLEncoder.encode(service, StandardCharsets.UTF_8));

        URI uri = URI.create(realm + "?" + query);

        // Perform the request to get the token (no retry — a failed token request is a hard failure)
        Map<String, String> headers = new HashMap<>();
        HttpClient.ResponseWrapper<String> responseWrapper = getForTokenRefresh(uri, headers, scopes, authProvider);

        // Log the response
        LOG.debug(
                "Response: {}",
                responseWrapper
                        .response()
                        .replaceAll("\"token\"\\s*:\\s*\"([A-Za-z0-9\\-_\\.=]+)\"", "\"token\":\"<redacted>\"")
                        .replaceAll(
                                "\"access_token\"\\s*:\\s*\"([A-Za-z0-9\\-_\\.=]+)\"",
                                "\"access_token\":\"<redacted>\""));
        LOG.debug(
                "Headers: {}",
                responseWrapper.headers().entrySet().stream()
                        .collect(Collectors.toMap(
                                Map.Entry::getKey,
                                entry -> Const.AUTHORIZATION_HEADER.equalsIgnoreCase(entry.getKey())
                                        ? "<redacted" // Replace value with ****
                                        : entry.getValue())));

        // Put in the cache
        TokenResponse token = JsonUtils.fromJson(responseWrapper.response(), TokenResponse.class)
                .forService(service);
        TokenCache.put(newScopes, token);
        meterRegistry
                .counter(Const.METRIC_TOKEN_REFRESH, Const.METRIC_TAG_SERVICE, service, Const.METRIC_TAG_REALM, realm)
                .increment();
        return token;
    }

    static boolean isSameOrigin(URI uri1, URI uri2) {
        return Objects.equals(uri1.getScheme(), uri2.getScheme())
                && Objects.equals(uri1.getHost(), uri2.getHost())
                && getPort(uri1) == getPort(uri2);
    }

    static int getPort(URI uri) {
        return uri.getPort() != -1 ? uri.getPort() : ("https".equals(uri.getScheme()) ? 443 : 80);
    }

    static <T> boolean shouldRedirect(HttpResponse<T> response) {
        return response.statusCode() == HttpURLConnection.HTTP_MOVED_PERM
                || response.statusCode() == HttpURLConnection.HTTP_MOVED_TEMP
                || response.statusCode() == 307;
    }

    /**
     * Execute a request, with optional retry on transient failures (429, 5xx, network errors).
     * Token-refresh requests must pass {@code retryEnabled=false}.
     * @param method The HTTP method
     * @param uri The URI
     * @param includeAuthHeader Whether to attach an Authorization header
     * @param headers Extra headers
     * @param body Raw body bytes (used only for logging)
     * @param handler The response body handler
     * @param bodyPublisher The body publisher
     * @param scopes The scopes
     * @param authProvider The authentication provider
     * @param retryEnabled Whether transient failures should be retried
     * @return The response
     */
    private <T> ResponseWrapper<T> executeRequest(
            String method,
            URI uri,
            boolean includeAuthHeader,
            Map<String, String> headers,
            byte[] body,
            HttpResponse.BodyHandler<T> handler,
            HttpRequest.BodyPublisher bodyPublisher,
            Scopes scopes,
            AuthProvider authProvider,
            boolean retryEnabled) {

        // Scopes are invariant across retries — compute once.
        ContainerRef containerRef = scopes.getContainerRef();
        LOG.debug("Scopes are adding registry scopes");
        Scopes newScopes =
                switch (method) {
                    case "GET", "HEAD" -> scopes.withAddedRegistryScopes(Scope.PULL);
                    case "POST", "PUT", "PATCH" -> scopes.withAddedRegistryScopes(Scope.PUSH);
                    case "DELETE" -> scopes.withAddedRegistryScopes(Scope.DELETE);
                    default -> throw new OrasException("Unsupported HTTP method: " + method);
                };
        LOG.debug("Existing scopes: {}", scopes.getScopes());
        LOG.debug("New scopes: {}", newScopes.getScopes());

        int maxAttempts = retryEnabled ? this.maxRetries : 1;

        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            try {
                HttpRequest.Builder builder = HttpRequest.newBuilder().uri(uri).method(method, bodyPublisher);

                // Check token cache — may be populated by a prior attempt's 401 handling.
                TokenResponse cachedToken = TokenCache.get(newScopes);
                if (cachedToken == null) {
                    LOG.trace("No token found in cache for scopes: {}", newScopes);
                } else {
                    LOG.trace("Found token in cache for scopes: {}", newScopes.withService(cachedToken.service()));
                }

                // Add authentication header if any (from provider or cached token)
                var authHeader = authProvider.getAuthHeader(containerRef);
                if (cachedToken == null
                        && authHeader != null
                        && !authProvider.getAuthScheme().equals(AuthScheme.NONE)
                        && includeAuthHeader) {
                    builder = builder.header(Const.AUTHORIZATION_HEADER, authHeader);
                } else if (cachedToken != null && includeAuthHeader) {
                    builder = builder.header(Const.AUTHORIZATION_HEADER, "Bearer " + cachedToken.getEffectiveToken());
                }
                headers.forEach(builder::header);

                // Add user agent
                builder = builder.header(Const.USER_AGENT_HEADER, Versions.USER_AGENT_VALUE);

                HttpRequest request = builder.build();
                logRequest(request, body);
                HttpResponse<T> response = executeAndRecordRequest(request, handler);

                // Follow redirect (retryEnabled propagates into the recursive call)
                if (shouldRedirect(response)) {
                    String location = getLocationHeader(response);
                    URI redirectUri = URI.create(location);
                    LOG.debug("Redirecting to {} from domain {} to domain {}", location, uri, redirectUri);
                    boolean includeAuthHeaderForRedirect = isSameOrigin(uri, redirectUri);
                    if (!includeAuthHeaderForRedirect) {
                        LOG.debug("Skipping auth header for redirect from {} to {}", uri, redirectUri);
                    }
                    return executeRequest(
                            method,
                            redirectUri,
                            includeAuthHeaderForRedirect,
                            headers,
                            body,
                            handler,
                            bodyPublisher,
                            newScopes,
                            authProvider,
                            retryEnabled);
                }

                // Retry on 429 / 5xx before delegating 401/403 to redoRequest.
                if (retryEnabled && isRetryableStatus(response.statusCode()) && attempt < maxAttempts - 1) {
                    long delay = computeRetryDelay(response, attempt);
                    LOG.warn(
                            "Retrying request ({}/{}) after {}ms, status={}",
                            attempt + 1,
                            maxAttempts - 1,
                            delay,
                            response.statusCode());
                    meterRegistry
                            .counter(Const.METRIC_HTTP_RETRIES, "reason", retryReason(response.statusCode()))
                            .increment();
                    Thread.sleep(delay);
                    continue;
                }

                return redoRequest(uri, response, builder, handler, newScopes, authProvider);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new OrasException("Request interrupted during retry wait", e);
            } catch (OrasException e) {
                throw e;
            } catch (Exception e) {
                if (retryEnabled && attempt < maxAttempts - 1 && isRetryableException(e)) {
                    long delay = computeRetryDelay(null, attempt);
                    LOG.warn(
                            "Retrying request ({}/{}) after {}ms, error={}",
                            attempt + 1,
                            maxAttempts - 1,
                            delay,
                            e.getMessage());
                    meterRegistry
                            .counter(Const.METRIC_HTTP_RETRIES, "reason", "network_error")
                            .increment();
                    try {
                        Thread.sleep(delay);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new OrasException("Request interrupted during retry wait", ie);
                    }
                } else {
                    LOG.error("Failed to execute request", e);
                    throw new OrasException("Unable to create HTTP request", e);
                }
            }
        }
        throw new OrasException("Max retries (" + (maxAttempts - 1) + ") exceeded");
    }

    private static boolean isRetryableStatus(int statusCode) {
        return statusCode == 429 || (statusCode >= 500 && statusCode <= 599);
    }

    private static boolean isRetryableException(Exception e) {
        return e instanceof HttpTimeoutException || e instanceof java.io.IOException;
    }

    private long computeRetryDelay(@Nullable HttpResponse<?> response, int attempt) {
        if (response != null && response.statusCode() == 429) {
            String retryAfter = response.headers().firstValue("Retry-After").orElse(null);
            if (retryAfter != null) {
                try {
                    return Long.parseLong(retryAfter.trim()) * 1000L;
                } catch (NumberFormatException ignored) {
                }
            }
        }
        long delay = retryDelayMs * (1L << Math.min(attempt, 30));
        return Math.min(delay, maxRetryDelayMs);
    }

    private static String retryReason(int statusCode) {
        if (statusCode == 429) return "rate_limit";
        if (statusCode >= 500) return "server_error";
        return "unknown";
    }

    private <T> HttpResponse<T> executeAndRecordRequest(HttpRequest request, HttpResponse.BodyHandler<T> handler)
            throws Exception {
        long start = System.nanoTime();
        HttpResponse<T> response = client.send(request, handler);
        long duration = System.nanoTime() - start;
        Timer.builder(Const.METRIC_HTTP_REQUESTS)
                .tag("method", request.method())
                .tag("host", request.uri().getHost())
                .tag("status", response != null ? String.valueOf(response.statusCode()) : "IO_ERROR")
                .register(meterRegistry)
                .record(duration, TimeUnit.NANOSECONDS);
        if (response == null) {
            throw new OrasException("No response received");
        }
        return response;
    }

    private <T> String getLocationHeader(HttpResponse<T> response) {
        return response.headers()
                .firstValue("Location")
                .orElseThrow(() -> new OrasException("No Location header found"));
    }

    private <T> ResponseWrapper<T> redoRequest(
            URI originUri,
            HttpResponse<T> response,
            HttpRequest.Builder builder,
            HttpResponse.BodyHandler<T> handler,
            Scopes scopes,
            AuthProvider authProvider) {
        if ((response.statusCode() == 401 || response.statusCode() == 403)) {
            LOG.debug("Requesting new token...");
            HttpClient.TokenResponse token =
                    refreshToken(toResponseWrapper(response, scopes.getService()), scopes, authProvider);
            if (token.issued_at() != null && token.expires_in() != null) {
                LOG.debug(
                        "Received token issued_at {}, expire_id {} and expiring at {} ",
                        token.issued_at(),
                        token.expires_in(),
                        token.issued_at().plusSeconds(token.expires_in()));
            }
            String bearerToken = token.getEffectiveToken();
            String service = token.service();
            try {
                builder = builder.setHeader(Const.AUTHORIZATION_HEADER, "Bearer " + bearerToken);
                HttpResponse<T> newResponse = executeAndRecordRequest(builder.build(), handler);

                // Follow redirect
                if (shouldRedirect(newResponse)) {
                    String location = getLocationHeader(newResponse);
                    URI redirectUri = URI.create(location);
                    LOG.debug("Redirecting to {} from domain {} to domain {}", location, originUri, redirectUri);
                    boolean includeAuthHeaderForRedirect = isSameOrigin(originUri, redirectUri);
                    if (!includeAuthHeaderForRedirect) {
                        LOG.debug("Skipping auth header for redirect from {} to {}", originUri, redirectUri);
                        builder = HttpRequest.newBuilder(
                                builder.build(), (name, value) -> !name.equalsIgnoreCase(Const.AUTHORIZATION_HEADER));
                    }

                    return toResponseWrapper(
                            executeAndRecordRequest(
                                    builder.uri(URI.create(location)).build(), handler),
                            service);
                }
                return toResponseWrapper(newResponse, service);

            } catch (Exception e) {
                LOG.error("Failed to redo request", e);
                throw new OrasException("Unable to redo HTTP request", e);
            }
        }
        return toResponseWrapper(response, scopes.getService());
    }

    private <T> ResponseWrapper<T> toResponseWrapper(HttpResponse<T> response, @Nullable String service) {
        return new ResponseWrapper<>(
                response.body(),
                response.statusCode(),
                response.headers().map().entrySet().stream()
                        .collect(Collectors.toMap(
                                Map.Entry::getKey, e -> e.getValue().get(0))),
                service);
    }

    /**
     * Logs the request in debug/trace mode
     * @param request The request
     * @param body The body
     */
    private void logRequest(HttpRequest request, byte[] body) {
        LOG.debug("Executing {} request to {}", request.method(), request.uri());
        LOG.debug(
                "Headers: {}",
                request.headers().map().entrySet().stream()
                        .collect(Collectors.toMap(
                                Map.Entry::getKey,
                                entry -> Const.AUTHORIZATION_HEADER.equalsIgnoreCase(entry.getKey())
                                        ? List.of("<redacted>") // Replace value with ****
                                        : entry.getValue())));
        // Log the body in trace mode
        if (LOG.isTraceEnabled()) {
            LOG.trace("Body: {}", new String(body, StandardCharsets.UTF_8));
        }
    }

    /**
     * Response wrapper
     * @param <T> The response type
     * @param response The response
     * @param statusCode The status code
     * @param headers The headers
     * @param service The service (not on response but on HTTP headers)
     */
    public record ResponseWrapper<T>(
            T response, int statusCode, Map<String, String> headers, @Nullable String service) {}

    /**
     * Insecure trust manager when skipping TLS verification
     */
    private static class InsecureTrustManager extends X509ExtendedTrustManager {
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[] {};
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            // Intentionally empty: this trust manager skips all certificate verification
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            // Intentionally empty: this trust manager skips all certificate verification
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {
            // Intentionally empty: this trust manager skips all certificate verification
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
            // Intentionally empty: this trust manager skips all certificate verification
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
            // Intentionally empty: this trust manager skips all certificate verification
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
            // Intentionally empty: this trust manager skips all certificate verification
        }
    }

    /**
     * The token response
     * @param token The token
     * @param service The service (not on response but on HTTP headers)
     * @param access_token The access token
     * @param expires_in The expires in
     * @param issued_at The issued at
     */
    @OrasModel
    public record TokenResponse(
            String token,
            @Nullable String access_token,
            @Nullable String service,
            @Nullable Integer expires_in,
            @Nullable ZonedDateTime issued_at) {

        /**
         * Create a new token response with the service field set
         * @param service The service
         * @return A new token response with the service field set
         */
        public TokenResponse forService(String service) {
            return new TokenResponse(token, access_token, service, expires_in, issued_at);
        }

        /**
         * >>>>>>> 6379975 (Store token into caffeine cache (#631))
         * Get the effective token
         * @return The effective token, which is either the access_token or the token field depending on which one is present
         */
        public String getEffectiveToken() {
            return access_token != null ? access_token : token;
        }

        @Override
        public String toString() {
            return "TokenResponse{" + "expires_in=" + expires_in + ", issued_at=" + issued_at + '}';
        }
    }

    /**
     * Builder for the HTTP client
     */
    public static class Builder {
        private final HttpClient client = new HttpClient();

        /**
         * Hidden constructor
         */
        private Builder() {}

        /**
         * Set the timeout
         * @param timeout The timeout in seconds
         * @return The builder
         */
        public Builder withTimeout(@Nullable Integer timeout) {
            client.setTimeout(timeout);
            return this;
        }

        /**
         * Skip the TLS verification
         * @param skipTlsVerify Skip TLS verification
         * @return The builder
         */
        public Builder withSkipTlsVerify(boolean skipTlsVerify) {
            client.setSkipTlsVerify(skipTlsVerify);
            return this;
        }

        /**
         * Set the meter registry for metrics. Following Micrometer best practices for libraries,
         * @param meterRegistry The meter registry
         * @return The builder
         */
        public Builder withMeterRegistry(MeterRegistry meterRegistry) {
            client.meterRegistry = meterRegistry;
            return this;
        }

        /**
         * Set the maximum number of attempts for retryable requests (default: 3).
         * A value of 1 disables retries entirely.
         * @param maxRetries Maximum attempts (must be &gt;= 1)
         * @return The builder
         */
        public Builder withMaxRetries(int maxRetries) {
            if (maxRetries < 1) throw new IllegalArgumentException("maxRetries must be >= 1");
            client.maxRetries = maxRetries;
            return this;
        }

        /**
         * Set the initial delay before the first retry in milliseconds (default: 500).
         * Subsequent delays are doubled up to {@link #withMaxRetryDelay}.
         * @param retryDelayMs Initial delay in milliseconds (must be &gt;= 0)
         * @return The builder
         */
        public Builder withRetryDelay(long retryDelayMs) {
            if (retryDelayMs < 0) throw new IllegalArgumentException("retryDelayMs must be >= 0");
            client.retryDelayMs = retryDelayMs;
            return this;
        }

        /**
         * Set the upper bound on retry delay in milliseconds (default: 30 000).
         * @param maxRetryDelayMs Maximum delay cap in milliseconds (must be &gt;= 0)
         * @return The builder
         */
        public Builder withMaxRetryDelay(long maxRetryDelayMs) {
            if (maxRetryDelayMs < 0) throw new IllegalArgumentException("maxRetryDelayMs must be >= 0");
            client.maxRetryDelayMs = maxRetryDelayMs;
            return this;
        }

        /**
         * Set the CA file for TLS verification
         * @param caFilePath The path to a PEM-encoded CA certificate or bundle
         * @return The builder
         */
        public Builder withCaFile(Path caFilePath) {
            client.setCaFile(caFilePath);
            return this;
        }

        /**
         * Set the CA file for TLS verification
         * @param caFilePath The path to a PEM-encoded CA certificate or bundle
         * @return The builder
         */
        public Builder withCaFile(String caFilePath) {
            return withCaFile(Path.of(caFilePath));
        }

        /**
         * Set the CA certificates from PEM-encoded content
         * @param caContent The PEM-encoded CA certificate or bundle content
         * @return The builder
         */
        public Builder withCaContent(String caContent) {
            client.setCaContent(caContent);
            return this;
        }

        /**
         * Build the client
         * @return The client
         */
        public static Builder builder() {
            return new Builder();
        }

        /**
         * Build the client
         * @return The client
         */
        public HttpClient build() {
            return client.build();
        }
    }
}
