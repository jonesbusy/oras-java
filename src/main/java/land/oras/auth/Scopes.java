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

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import land.oras.ContainerRef;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/**
 * Store scopes
 */
@NullMarked
public final class Scopes {

    /**
     * List of scopes
     */
    private final List<String> scopeItems;

    /**
     * Service
     */
    private @Nullable final String service;

    /**
     * The container reference
     */
    private final ContainerRef containerRef;

    /**
     * Registry scope prefix
     */
    private static final String REGISTRY_PREFIX = "registry:";

    /**
     * Private constructor
     * @param containerRef The container reference
     * @param service The service
     * @param scopes The scopes
     */
    private Scopes(ContainerRef containerRef, @Nullable String service, Scope... scopes) {
        this(containerRef, service, ScopeUtils.appendRepositoryScope(List.of(), containerRef, scopes));
    }

    /**
     * Private constructor
     * @param containerRef The container reference
     * @param service The service
     * @param scopes The scopes
     */
    private Scopes(ContainerRef containerRef, @Nullable String service, List<String> scopes) {
        this.containerRef = containerRef;
        this.service = service;
        this.scopeItems = scopes;
    }

    /**
     * Create a new Scopes object
     * @param containerRef The container reference
     * @param scopes The scopes
     * @return A new Scopes object
     */
    public static Scopes of(ContainerRef containerRef, Scope... scopes) {
        return new Scopes(containerRef, null, scopes);
    }

    /**
     * Create a new Scopes object
     * @param service The service
     * @param containerRef The container reference
     * @param scopes The scopes
     * @return A new Scopes object
     */
    public static Scopes of(String service, ContainerRef containerRef, Scope... scopes) {
        return new Scopes(containerRef, service, scopes);
    }

    /**
     * Create a new Scopes object with no scopes
     * @param containerRef The container reference
     * @param service The service
     * @return A new Scopes object with no scopes
     */
    public static Scopes empty(ContainerRef containerRef, String service) {
        return new Scopes(containerRef, service, List.of());
    }

    /**
     * Return a new copy of the Scopes object with the given scopes
     * @param scopes The scopes to set
     * @return A new Scopes object with the given scopes
     */
    public Scopes withRegistryScopes(Scope... scopes) {
        return new Scopes(containerRef, service, scopes);
    }

    /**
     * Return a new copy of the Scopes object with the added scopes
     * @param newScopes The scopes to add
     * @return A new Scopes object with the given scopes
     */
    public Scopes withAddedRegistryScopes(Scope... newScopes) {
        return new Scopes(
                containerRef, service, ScopeUtils.appendRepositoryScope(this.scopeItems, containerRef, newScopes));
    }

    /**
     * Return a new copy of the Scopes object with the given scopes
     * @param globalScopes The global scopes to add
     * @return A new Scopes object with the given scopes
     */
    public Scopes withAddedGlobalScopes(String... globalScopes) {
        List<String> newScopes = new LinkedList<>(scopeItems);
        newScopes.addAll(List.of(globalScopes));
        return new Scopes(
                containerRef, service, newScopes.stream().sorted().distinct().toList());
    }

    /**
     * Return scopes that only contains global scopes (i.e. no repository or registry scopes)
     * @return A new Scopes object with only global scopes
     */
    public Scopes withOnlyGlobalScopes() {
        List<String> globalScopes = scopeItems.stream()
                .filter(s -> !s.startsWith("repository:") && !s.startsWith(REGISTRY_PREFIX))
                .sorted()
                .distinct()
                .toList();
        return new Scopes(containerRef, service, globalScopes);
    }

    /**
     * Return scopes that only contains non-global scopes (i.e. only repository or registry scopes)
     * @return A new Scopes object with only non-global scopes
     */
    public Scopes withoutGlobalScopes() {
        List<String> nonGlobalScopes = scopeItems.stream()
                .filter(s -> s.startsWith("repository:") || s.startsWith(REGISTRY_PREFIX))
                .sorted()
                .distinct()
                .toList();
        return new Scopes(containerRef, service, nonGlobalScopes);
    }

    /**
     * Return a new copy of the Scopes object with the given scope
     * @param scope The scope to add
     * @return A new Scopes object with the given scope
     */
    public Scopes withNewScope(String scope) {
        List<String> newScopes = new LinkedList<>(scopeItems);
        newScopes.add(scope);
        return new Scopes(containerRef, service, ScopeUtils.cleanScopes(newScopes));
    }

    /**
     * Return a new copy of the Scopes object with the given service
     * @param service The service to set
     * @return A new Scopes object with the given service
     */
    public Scopes withService(@Nullable String service) {
        return new Scopes(containerRef, service, scopeItems);
    }

    /**
     * Get the service
     * @return The service
     */
    public @Nullable String getService() {
        return service;
    }

    /**
     * Get the scopes
     * @return The scopes
     */
    public List<String> getScopes() {
        return scopeItems;
    }

    /**
     * Get the registry
     * @return The registry
     */
    public String getRegistry() {
        return containerRef.getRegistry();
    }

    /**
     * Get the container reference
     * @return The container reference
     */
    public ContainerRef getContainerRef() {
        return containerRef;
    }

    /**
     * Return if these are global scopes (i.e. no repository or registry scopes)
     * Typically AWS ECR uses global scopes for authentication, while Docker Hub uses repository scopes.
     * @return True if these are global scopes, false otherwise
     */
    public boolean isGlobal() {
        return scopeItems.stream().noneMatch(s -> s.startsWith("repository:") || s.startsWith(REGISTRY_PREFIX));
    }

    /**
     * Return if these scopes include global scopes (i.e. at least one scope that is not a repository or registry scope)
     * @return True if these scopes include global scopes, false otherwise
     */
    public boolean hasGlobalScopes() {
        return scopeItems.stream().anyMatch(s -> !s.startsWith("repository:") && !s.startsWith(REGISTRY_PREFIX));
    }

    /**
     * Return if these are pull-only scopes (i.e. all scopes end with ":pull" and there are no global scopes)
     * @return True if these are pull-only scopes, false otherwise
     */
    public boolean isPullOnly() {
        return !isGlobal() && scopeItems.stream().allMatch(s -> s.endsWith(":pull"));
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Scopes scopes1 = (Scopes) o;
        return Objects.equals(getScopes(), scopes1.getScopes())
                && Objects.equals(getService(), scopes1.getService())
                && Objects.equals(
                        getContainerRef().getRegistry(),
                        scopes1.getContainerRef().getRegistry());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getScopes(), getService(), getContainerRef().getRegistry());
    }

    @Override
    public String toString() {
        return "Scopes{" + "scopeItems="
                + scopeItems + ", service='"
                + service + '\'' + ", registry="
                + containerRef.getRegistry() + '}';
    }
}
