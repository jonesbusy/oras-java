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

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import land.oras.ContainerRef;
import land.oras.OrasModel;
import land.oras.exception.OrasException;
import land.oras.utils.JsonUtils;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implements a credentials store using a configuration file
 * to keep the credentials in plain-text.
 * Reference: <a href="https://docs.docker.com/engine/reference/commandline/cli/#docker-cli-configuration-file-configjson-properties">Docker config</a>
 */
@NullMarked
public class AuthStore {

    private static final Logger LOG = LoggerFactory.getLogger(AuthStore.class);

    /**
     * Credentials helper for all registries
     */
    private static final String ALL_REGISTRIES_HELPER = "*";

    /**
     * Allowed characters for a credential-helper suffix
     */
    private static final Pattern VALID_HELPER_SUFFIX = Pattern.compile("^[A-Za-z0-9_-]+$");

    /**
     * Build the credential-helper binary name for a suffix
     */
    static String credentialHelperBinaryName(@Nullable String suffix) {
        if (suffix == null || !VALID_HELPER_SUFFIX.matcher(suffix).matches()) {
            throw new OrasException(
                    "Invalid credential helper name '%s': only letters, digits, '_' and '-' are allowed (no path separators or '..')"
                            .formatted(suffix));
        }
        return "docker-credential-" + suffix;
    }

    /**
     * The internal config
     */
    private final Config config;

    /**
     * Constructor for FileStore.
     *
     * @param config configuration instance.
     */
    AuthStore(Config config) {
        this.config = Objects.requireNonNull(config, "Config cannot be null");
    }

    /**
     * Creates a new FileStore based on the given configuration file path.
     *
     * @param configPaths Path to the configuration files.
     * @return FileStore instance.
     */
    public static AuthStore newStore(List<Path> configPaths) {
        List<ConfigFile> files = new ArrayList<>();
        for (Path configPath : configPaths) {
            if (Files.exists(configPath)) {
                ConfigFile configFile = JsonUtils.fromJson(configPath, ConfigFile.class);
                LOG.debug("Loaded auth config file: {}", configPath);
                files.add(configFile);
            }
        }
        return new AuthStore(Config.load(files));
    }

    /**
     * Creates a new FileStore from default location.
     * If the {@code REGISTRY_AUTH_FILE} environment variable is set it is used exclusively.
     * Otherwise, the Docker config and (when {@code XDG_RUNTIME_DIR} is set) the Podman auth file are searched.
     *
     * @return FileStore instance.
     */
    public static AuthStore newStore() {
        String registryAuthFile = System.getenv("REGISTRY_AUTH_FILE");
        if (registryAuthFile != null) {
            LOG.debug("Using auth file from REGISTRY_AUTH_FILE: {}", registryAuthFile);
            return newStore(List.of(Path.of(registryAuthFile)));
        }
        return newStore(defaultAuthPaths());
    }

    /**
     * Returns the ordered list of auth file paths to search when no {@code REGISTRY_AUTH_FILE} is set.
     * Docker config is always included; the Podman auth file is added when {@code XDG_RUNTIME_DIR} is set.
     *
     * @return list of candidate paths.
     */
    private static List<Path> defaultAuthPaths() {
        Path dockerPath = Path.of(System.getProperty("user.home"), ".docker", "config.json");
        String xdgRuntimeDir = System.getenv("XDG_RUNTIME_DIR");
        if (xdgRuntimeDir != null) {
            // https://docs.podman.io/en/stable/markdown/podman-login.1.html#description
            return List.of(dockerPath, Path.of(xdgRuntimeDir, "containers", "auth.json"));
        }
        return List.of(dockerPath);
    }

    /**
     * Retrieves credentials for the given containerRef.
     *
     * @param containerRef ContainerRef.
     * @return Credential object or null if no credential is found.
     */
    public @Nullable Credential get(ContainerRef containerRef) throws OrasException {
        return config.getCredential(containerRef);
    }

    /**
     * Get the credential helper binary for the given containerRef.
     * @param containerRef ContainerRef.
     * @return Credential helper binary name or null if not found.
     */
    public @Nullable String getCredentialHelperBinary(ContainerRef containerRef) {
        String helper = config.credentialHelperStore.get(containerRef.getRegistry());
        if (helper == null) {
            return null;
        }
        return credentialHelperBinaryName(helper);
    }

    /**
     * Nested ConfigFile class to represent the configuration file.
     * @param auths The auths map.
     * @param credHelpers The credential helpers map.
     * @param credsStore The credentials store.
     */
    @OrasModel
    record ConfigFile(
            Map<String, Map<String, String>> auths,
            @Nullable Map<String, String> credHelpers,
            @Nullable String credsStore) {

        /**
         * Constructs a new {@code ConfigFile} object with the specified auths.
         * @param credential The credential.
         * @return ConfigFile object.
         */
        static ConfigFile fromCredential(Credential credential) {
            return new ConfigFile(
                    Map.of(
                            "auths",
                            Map.of(
                                    "auth",
                                    java.util.Base64.getEncoder()
                                            .encodeToString(
                                                    (credential.username + ":" + credential.password).getBytes()))),
                    Map.of(),
                    null);
        }
    }

    /**
     * Nested Config class for configuration management.
     */
    static class Config {

        /**
         * Private constructor to prevent instantiation.
         */
        private Config() {}

        /**
         * Stores the credentials
         */
        private final ConcurrentHashMap<String, Credential> credentialStore = new ConcurrentHashMap<>();

        /**
         * Stores the credential helpers binaries
         */
        private final ConcurrentHashMap<String, String> credentialHelperStore = new ConcurrentHashMap<>();

        /**
         * Loads the configuration from a JSON file at the specified path and populates the credential store.
         *
         * @param configFiles The config files
         * @return A {@code Config} object populated with the credentials from the JSON file.
         * @throws OrasException If an error occurs while reading or parsing the JSON file.
         */
        public static Config load(List<ConfigFile> configFiles) throws OrasException {
            Config config = new Config();
            for (ConfigFile configFile : configFiles) {
                config.credentialHelperStore.putAll(configFile.credHelpers != null ? configFile.credHelpers : Map.of());
                config.credentialHelperStore.putAll(
                        configFile.credsStore != null
                                ? Map.of(ALL_REGISTRIES_HELPER, configFile.credsStore)
                                : Map.of());
                configFile.auths.forEach((host, value) -> {
                    String auth = value.get("auth");
                    if (auth != null) {
                        String base64Decoded =
                                new String(java.util.Base64.getDecoder().decode(auth), StandardCharsets.UTF_8);
                        String[] parts = base64Decoded.split(":", 2);
                        if (parts.length != 2) {
                            LOG.warn(
                                    "Skipping credential for '{}': malformed auth entry (expected user:password)",
                                    host);
                            return;
                        }
                        config.credentialStore.put(host, new Credential(parts[0], parts[1]));
                    }
                });
            }
            return config;
        }

        /**
         * Retrieves the {@code Credential} associated with the specified containerRef.
         * Implements hierarchical credential lookup from most-specific to least-specific.
         * For example, "my-registry.local/namespace/user/image:latest" is looked up as:
         * <ol>
         *   <li>my-registry.local/namespace/user/image</li>
         *   <li>my-registry.local/namespace/user</li>
         *   <li>my-registry.local/namespace</li>
         *   <li>my-registry.local</li>
         * </ol>
         *
         * @param containerRef The containerRef whose credential is to be retrieved.
         * @return The {@code Credential} associated with the containerRef, or {@code null} if no credential is found.
         */
        public @Nullable Credential getCredential(ContainerRef containerRef) throws OrasException {
            String registry = containerRef.getRegistry();

            // Start at the most specific key: registry/namespace/repository (or registry/repository)
            String key = registry + "/" + containerRef.getFullRepository();

            LOG.debug("Looking for credentials for containerRef starting at key '{}'", key);

            // Iterate from most-specific to least-specific, stopping when only the registry remains
            while (!key.equals(registry)) {
                Credential cred = credentialStore.get(key);
                if (cred != null) {
                    LOG.debug("Found credential for key '{}'", key);
                    return cred;
                }
                // Remove the last path segment and continue with the less specific key
                key = key.substring(0, key.lastIndexOf('/'));
            }

            // Check the registry-only key
            Credential registryCred = credentialStore.get(key);
            if (registryCred != null) {
                LOG.debug("Found credential for registry '{}'", key);
                return registryCred;
            }

            // Try credential helper scoped to the registry
            String helperSuffix = credentialHelperStore.get(registry);
            if (helperSuffix != null) {
                try {
                    LOG.debug("Using credential helper '{}' for registry '{}'", helperSuffix, registry);
                    return getFromCredentialHelper(helperSuffix, registry);
                } catch (OrasException e) {
                    LOG.warn("Failed to get credential from helper for registry {}: {}", registry, e.getMessage());
                }
            }

            // Finally, try all-registries helper
            helperSuffix = credentialHelperStore.get(ALL_REGISTRIES_HELPER);
            if (helperSuffix != null) {
                try {
                    LOG.debug("Using all-registries credential helper for registry '{}'", registry);
                    return getFromCredentialHelper(helperSuffix, registry);
                } catch (OrasException e) {
                    LOG.warn(
                            "Failed to get credential from all-registries helper for registry {}: {}",
                            registry,
                            e.getMessage());
                }
            }

            return null;
        }

        private static Credential getFromCredentialHelper(String suffix, String hostname) throws OrasException {

            LOG.debug("Looking for credential helper 'docker-credential-{}' for hostname '{}'", suffix, hostname);

            String binary = credentialHelperBinaryName(suffix);
            ProcessBuilder pb = new ProcessBuilder(binary, "get");

            try {
                Process proc = pb.start();

                // Hostname is in stdin
                try (OutputStream os = proc.getOutputStream()) {
                    os.write(hostname.getBytes(StandardCharsets.UTF_8));
                    os.flush();
                }

                // Wait
                int exit = proc.waitFor();
                if (exit != 0) {
                    String stderr = new String(proc.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
                    String stdout = new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                    String message = "Credential helper '%s' exited with code %d and error: '%s' and stdout '%s'."
                            .formatted(binary, exit, stderr.trim(), stdout.trim());
                    LOG.warn(message);
                    throw new OrasException(message);
                }

                return JsonUtils.fromJson(proc.getInputStream(), CredentialHelperResponse.class)
                        .asCredential();

            } catch (IOException e) {
                LOG.warn("Failed to execute credential helper '{}': {}", binary, e.getMessage());
                throw new OrasException("Credential helper '" + binary + "' not found or IO error", e);
            } catch (InterruptedException e) {
                LOG.warn("Credential helper execution interrupted: {}", e.getMessage());
                throw new OrasException("Credential helper execution interrupted", e);
            }
        }
    }

    /**
     * Nested Credential class to represent username and password pairs.
     * @param username The username for the credential.
     * @param password The password for the credential.
     */
    @OrasModel
    public record Credential(String username, String password) {
        /**
         * Constructs a new {@code Credential} object with the specified username and password.
         *
         * @param username The username for the credential. Must not be {@code null}.
         * @param password The password for the credential. Must not be {@code null}.
         */
        public Credential(String username, String password) {
            this.username = Objects.requireNonNull(username, "Username cannot be null");
            this.password = Objects.requireNonNull(password, "Password cannot be null");
        }
    }

    /**
     * Credential helper response
     * @param serverUrl The server URL
     * @param username The username
     * @param secret The secret (password or token)
     */
    @OrasModel
    public record CredentialHelperResponse(
            @JsonProperty("ServerURL") String serverUrl,
            @JsonProperty("Username") String username,
            @JsonProperty("Secret") String secret) {
        /**
         * Convert to Credential
         * @return Credential
         */
        public Credential asCredential() {
            return new Credential(username, secret);
        }
    }
}
