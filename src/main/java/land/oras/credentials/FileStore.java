/*-
 * =LICENSE=
 * ORAS Java SDK
 * ===
 * Copyright (C) 2024 - 2025 ORAS
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

package land.oras.credentials;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import land.oras.ContainerRef;
import land.oras.exception.OrasException;
import land.oras.utils.JsonUtils;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * FileStore implements a credentials store using a configuration file
 * to keep the credentials in plain-text.
 * Reference: <a href="https://docs.docker.com/engine/reference/commandline/cli/#docker-cli-configuration-file-configjson-properties">Docker config</a>
 */
@NullMarked
public class FileStore {

    private static final Logger LOG = LoggerFactory.getLogger(FileStore.class);

    /**
     * The internal config
     */
    private final Config config;

    /**
     * Error message indicating that the format of the provided credential is invalid.
     * This is typically used when credentials do not match the expected structure or format.
     */
    public static final String ERR_BAD_CREDENTIAL_FORMAT = "Bad credential format";

    /**
     * Constructor for FileStore.
     *
     * @param config configuration instance.
     */
    FileStore(Config config) {
        this.config = Objects.requireNonNull(config, "Config cannot be null");
    }

    /**
     * Creates a new FileStore based on the given configuration file path.
     *
     * @param configPaths Path to the configuration files.
     * @return FileStore instance.
     */
    public static FileStore newFileStore(List<Path> configPaths) {
        List<ConfigFile> files = new ArrayList<>();
        for (Path configPath : configPaths) {
            if (Files.exists(configPath)) {
                ConfigFile configFile = JsonUtils.fromJson(configPath, ConfigFile.class);
                LOG.debug("Loaded auth config file: {}", configPath);
                files.add(configFile);
            }
        }
        return new FileStore(Config.load(files));
    }

    /**
     * Creates a new FileStore from default location
     * @return FileStore instance.
     */
    public static FileStore newFileStore() {
        List<Path> paths = List.of(
                Path.of(System.getProperty("user.home"), ".docker", "config.json"), // Docker
                Path.of(System.getenv("XDG_RUNTIME_DIR"), "containers", "auth.json") // Podman
                );
        return newFileStore(paths);
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
     * Saves credentials for the given ContainerRef.
     *
     * @param containerRef ContainerRef.
     * @param credential Credential object.
     * @throws Exception if saving fails.
     */
    public void put(ContainerRef containerRef, Credential credential) throws Exception {
        validateCredentialFormat(credential);
        config.putCredential(containerRef, credential);
    }

    /**
     * Deletes credentials for the given container.
     *
     * @param containerRef .
     * @throws OrasException if deletion fails.
     */
    public void delete(ContainerRef containerRef) throws OrasException {
        config.deleteCredential(containerRef);
    }

    /**
     * Validates the format of the credential.
     *
     * @param credential Credential object.
     * @throws Exception if the credential format is invalid.
     */
    private void validateCredentialFormat(Credential credential) throws Exception {
        if (credential.username().contains(":")) {
            throw new IllegalArgumentException(ERR_BAD_CREDENTIAL_FORMAT + ": colons(:) are not allowed in username");
        }
    }

    /**
     * Nested ConfigFile class to represent the configuration file.
     * @param auths The auths map.
     */
    record ConfigFile(Map<String, Map<String, String>> auths) {

        /**
         * Constructs a new {@code ConfigFile} object with the specified auths.
         * @param credential The credential.
         * @return ConfigFile object.
         */
        static ConfigFile fromCredential(Credential credential) {
            return new ConfigFile(Map.of(
                    "auths",
                    Map.of(
                            "auth",
                            java.util.Base64.getEncoder()
                                    .encodeToString((credential.username + ":" + credential.password).getBytes()))));
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
         * Loads the configuration from a JSON file at the specified path and populates the credential store.
         *
         * @param configFiles The config files
         * @return A {@code Config} object populated with the credentials from the JSON file.
         * @throws OrasException If an error occurs while reading or parsing the JSON file.
         */
        public static Config load(List<ConfigFile> configFiles) throws OrasException {
            Config config = new Config();
            for (ConfigFile configFile : configFiles) {
                configFile.auths.forEach((host, value) -> {
                    String auth = value.get("auth");
                    if (auth != null) {
                        String base64Decoded =
                                new String(java.util.Base64.getDecoder().decode(auth));
                        String[] parts = base64Decoded.split(":");
                        if (parts.length != 2) {
                            throw new OrasException("Invalid credential format");
                        }
                        config.credentialStore.put(host, new Credential(parts[0], parts[1]));
                    }
                });
            }
            return config;
        }

        /**
         * Retrieves the {@code Credential} associated with the specified containerRef.
         *
         * @param containerRef The containerRef whose credential is to be retrieved.
         * @return The {@code Credential} associated with the containerRef, or {@code null} if no credential is found.
         */
        public @Nullable Credential getCredential(ContainerRef containerRef) throws OrasException {
            return credentialStore.getOrDefault(containerRef.getRegistry(), null);
        }

        /**
         * Associates the specified {@code Credential} with the given containerRef.
         * If a credential already exists for the containerRef, it will be replaced.
         *
         * @param containerRef The containerRef to associate with the credential.
         * @param credential    The {@code Credential} to store. Must not be {@code null}.
         * @throws NullPointerException If the provided credential is {@code null}.
         */
        public void putCredential(ContainerRef containerRef, Credential credential) {
            credentialStore.put(containerRef.getRegistry(), credential);
        }

        /**
         * Removes the {@code Credential} associated with the specified containerRef.
         * If no credential is associated with the containerRef, this method does nothing.
         *
         * @param containerRef The containerRef whose credential is to be removed.
         */
        public void deleteCredential(ContainerRef containerRef) {
            credentialStore.remove(containerRef.toString());
        }
    }

    /**
     * Nested Credential class to represent username and password pairs.
     * @param username The username for the credential.
     * @param password The password for the credential.
     */
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
}
