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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import land.oras.OrasModel;
import land.oras.exception.OrasException;
import land.oras.utils.JsonUtils;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/**
 * Represents the containers trust policy loaded from a {@code policy.json} file.
 *
 * <p>This class loads and models the
 * <a href="https://github.com/containers/image/blob/main/docs/containers-policy.json.5.md">
 * containers-policy.json</a> format used by Podman, Skopeo, Buildah, and other
 * containers/image-based tools to control which images may be pulled and what level of
 * verification is required.
 *
 * @see PolicyRequirement
 */
@NullMarked
public class ContainersPolicy {

    private static final Logger LOG = LoggerFactory.getLogger(ContainersPolicy.class);

    /**
     * A dedicated Jackson mapper for policy.json that supports {@link PolicyRequirement}
     * polymorphic deserialization.
     *
     * <p>The global mapper in {@link JsonUtils} has a {@code NON_EMPTY} global inclusion filter
     * that would interfere with the {@code @JsonTypeInfo} resolution here, so we use a separate
     * instance.
     */
    static final ObjectMapper POLICY_MAPPER = JsonMapper.builder().build();

    private final PolicyFile policyFile;

    /**
     * Package-private constructor. Use the static factory methods to obtain instances.
     *
     * @param policyFile the parsed policy file model.
     */
    ContainersPolicy(PolicyFile policyFile) {
        this.policyFile = policyFile;
    }

    /**
     * Load the containers policy from the standard locations.
     *
     * @return a {@link ContainersPolicy} instance.
     * @throws OrasException if a candidate file exists but cannot be read or parsed.
     */
    public static ContainersPolicy newPolicy() {
        for (Path candidate : defaultPolicyPaths()) {
            LOG.debug("Checking for containers policy at: {}", candidate);
            if (Files.exists(candidate)) {
                LOG.debug("Loading containers policy from: {}", candidate);
                return newPolicy(candidate);
            }
        }

        LOG.warn("No containers policy.json found; using insecureAcceptAnything default");
        return new ContainersPolicy(PolicyFile.fromJson(List.of(new PolicyRequirement.InsecureAcceptAnything()), null));
    }

    /**
     * Load the containers policy from the given path.
     *
     * @param path the path to the {@code policy.json} file.
     * @return a {@link ContainersPolicy} instance.
     * @throws OrasException if the file cannot be read or parsed.
     */
    public static ContainersPolicy newPolicy(Path path) {
        try {
            String json = JsonUtils.readFile(path);
            PolicyFile policyFile = POLICY_MAPPER.readValue(json, PolicyFile.class);
            LOG.debug("Loaded containers policy from: {}", path);
            return new ContainersPolicy(policyFile);
        } catch (Exception e) {
            throw new OrasException("Failed to load containers policy from " + path, e);
        }
    }

    /**
     * Determine whether an image is allowed under this policy using the lightweight, content-free
     * scope gate.
     *
     * <p>All requirements in the resolved list must pass (logical AND). Because no image content is
     * available, signature-based requirements ({@code signedBy}, {@code sigstoreSigned}) allow the
     * operation to proceed here; their cryptographic check runs in {@link #verify(PolicyContext)} once
     * the image has been resolved during a pull.
     *
     * @param transport the transport, e.g. {@link Transport#DOCKER}.
     * @param scope     the image scope, e.g. {@code "docker.io/library/nginx"}.
     * @return {@code true} if all resolved requirements pass.
     */
    public boolean isAllowed(Transport transport, String scope) {
        PolicyContext context = PolicyContext.forScope(transport, scope);
        List<PolicyRequirement> requirements = resolveRequirements(transport, scope);
        for (PolicyRequirement req : requirements) {
            if (!req.verify(context)) {
                LOG.debug("Policy requirement {} failed for transport {} and scope {}", req, transport, scope);
                return false;
            }
        }
        LOG.debug("Policy all requirements passed for transport {} and scope {}", transport, scope);
        return true;
    }

    /**
     * Verify a resolved image against this policy, performing content-based checks (such as Sigstore
     * signature verification) that {@link #isAllowed(Transport, String)} cannot perform.
     *
     * <p>All resolved requirements must pass (logical AND). If any requirement fails, an
     * {@link OrasException} is thrown describing the failure.
     *
     * @param context the policy context carrying the resolved digest and a signature fetcher.
     * @throws OrasException if any resolved requirement rejects the image.
     */
    public void verify(PolicyContext context) {
        List<PolicyRequirement> requirements = resolveRequirements(context.getTransport(), context.getScope());
        for (PolicyRequirement req : requirements) {
            if (!req.verify(context)) {
                throw new OrasException("Image '%s' rejected by containers policy requirement '%s'"
                        .formatted(context.getReference(), req.getType()));
            }
        }
        LOG.debug("Policy verification passed for {}", context.getReference());
    }

    /**
     * Resolve the list of {@link PolicyRequirement} objects that apply to the given transport and
     * scope, following the precedence rules described in {@link #isAllowed}.
     *
     * @param transport the transport, e.g. {@link Transport#DOCKER}.
     * @param scope     the image scope, e.g. {@code "docker.io/library/nginx"}.
     * @return the non-null, possibly empty list of requirements (empty means global default
     *         was used and it too was empty — treat as reject-by-default for safety).
     */
    public List<PolicyRequirement> resolveRequirements(Transport transport, String scope) {
        Map<String, List<PolicyRequirement>> transportMap =
                policyFile.transports().getOrDefault(transport, Collections.emptyMap());

        // Exact match
        if (transportMap.containsKey(scope)) {
            LOG.debug("Policy: exact match for transport {} and scope {}", transport, scope);
            return transportMap.get(scope);
        }

        // Longest path prefix match
        String best = null;
        for (String key : transportMap.keySet()) {
            if (key.isEmpty()) continue; // skip transport default in this pass
            if (isScopePrefix(scope, key)) {
                if (best == null || key.length() > best.length()) {
                    best = key;
                }
            }
        }
        if (best != null) {
            LOG.debug("Policy: prefix match '{}' for transport {} and scope {}", best, transport, scope);
            return transportMap.get(best);
        }

        // Wildcard subdomain match
        String bestWildcard = null;
        for (String key : transportMap.keySet()) {
            if (key.startsWith("*.") && wildcardMatches(scope, key)) {
                if (bestWildcard == null || key.length() > bestWildcard.length()) {
                    bestWildcard = key;
                }
            }
        }
        if (bestWildcard != null) {
            LOG.debug("Policy: wildcard match '{}' for transport {} and scope {}", bestWildcard, transport, scope);
            return transportMap.get(bestWildcard);
        }

        // Transport default
        if (transportMap.containsKey("")) {
            LOG.debug("Policy: transport default for transport {}", transport);
            return transportMap.get("");
        }

        // Default
        LOG.debug("Policy: global default for transport {} and scope {}", transport, scope);
        return policyFile.defaultRequirements();
    }

    /**
     * Return the global default requirements.
     *
     * @return an unmodifiable view of the default requirement list.
     */
    public List<PolicyRequirement> getDefaultRequirements() {
        return Collections.unmodifiableList(policyFile.defaultRequirements());
    }

    /**
     * Return all transport-scoped requirements as an unmodifiable map.
     *
     * @return a map from {@link Transport} to a map of scope → requirements.
     */
    public Map<Transport, Map<String, List<PolicyRequirement>>> getTransports() {
        return Collections.unmodifiableMap(policyFile.transports());
    }

    /**
     * Return {@code true} if {@code candidate} is a valid path-prefix of {@code scope}.
     * A prefix must end at a {@code /} boundary (or equal the scope exactly).
     *
     * @param scope     the full scope string.
     * @param candidate the candidate prefix key.
     * @return {@code true} if candidate is a prefix of scope at a path boundary.
     */
    private boolean isScopePrefix(String scope, String candidate) {
        if (scope.equals(candidate)) return true;
        return scope.startsWith(candidate + "/");
    }

    private boolean wildcardMatches(String scope, String pattern) {
        // pattern: "*.example.com" or "*.example.com/path"
        String withoutWildcard = pattern.substring(2); // "example.com" or "example.com/path"
        // Extract host of scope
        int slash = scope.indexOf('/');
        String scopeHost = slash < 0 ? scope : scope.substring(0, slash);
        String scopePath = slash < 0 ? "" : scope.substring(slash); // includes leading '/'

        // Split pattern into host part and optional path part
        int patternSlash = withoutWildcard.indexOf('/');
        String patternHost = patternSlash < 0 ? withoutWildcard : withoutWildcard.substring(0, patternSlash);
        String patternPath = patternSlash < 0 ? "" : withoutWildcard.substring(patternSlash);

        // Host must end with ".<patternHost>" (subdomain)
        if (!scopeHost.endsWith("." + patternHost)) {
            return false;
        }
        // If pattern has a path component, scope path must start with it
        if (!patternPath.isEmpty()) {
            return scopePath.equals(patternPath) || scopePath.startsWith(patternPath + "/");
        }
        return true;
    }

    private static List<Path> defaultPolicyPaths() {
        return List.of(Path.of("/etc/containers/policy.json"));
    }

    /**
     * The raw JSON model for a {@code policy.json} file.
     *
     * @param defaultRequirements the mandatory global default requirement list (key
     *                            {@code "default"} in JSON).
     * @param transports          optional per-transport requirement map.
     */
    @OrasModel
    record PolicyFile(
            List<PolicyRequirement> defaultRequirements,
            Map<Transport, Map<String, List<PolicyRequirement>>> transports) {

        /**
         * Deserialize a {@link PolicyFile} from its JSON form, mapping the raw transport keys to the
         * {@link Transport} enum (any non-{@code docker} transport is merged into {@link Transport#UNKNOWN}).
         *
         * @param defaultRequirements the global default requirements (key {@code "default"}).
         * @param rawTransports       the per-transport requirements keyed by raw transport name.
         * @return the parsed policy file.
         */
        @JsonCreator
        static PolicyFile fromJson(
                @JsonProperty("default") @Nullable List<PolicyRequirement> defaultRequirements,
                @JsonProperty("transports") @Nullable Map<String, Map<String, List<PolicyRequirement>>> rawTransports) {
            List<PolicyRequirement> defaults =
                    defaultRequirements != null ? defaultRequirements : Collections.emptyList();
            Map<Transport, Map<String, List<PolicyRequirement>>> byTransport = new LinkedHashMap<>();
            if (rawTransports != null) {
                rawTransports.forEach((name, scopes) -> byTransport
                        .computeIfAbsent(Transport.fromValue(name), t -> new LinkedHashMap<>())
                        .putAll(scopes));
            }
            return new PolicyFile(defaults, byTransport);
        }
    }
}
