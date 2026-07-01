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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import land.oras.ContainerRef;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/**
 * Utility class for handling scopes in authentication.
 */
@NullMarked
final class ScopeUtils {

    /**
     * Append the repository scope to the existing scopes.
     * @param existingScopes the existing scopes
     * @param ref the container reference
     * @param scope the scopes to append
     * @return the updated scopes
     */
    public static List<String> appendRepositoryScope(
            @Nullable List<String> existingScopes, ContainerRef ref, Scope... scope) {
        if (existingScopes == null) {
            existingScopes = new ArrayList<>();
        }
        List<String> cleaned = new LinkedList<>(cleanScopes(existingScopes));
        String repositoryScope = scopeRepository(ref, scope);
        if (!repositoryScope.isEmpty()) {
            cleaned.add(repositoryScope);
        }
        return cleanScopes(cleaned);
    }
    /**
     * Create a scope for a repository.
     * @param ref the container reference
     * @param scopes the scopes to include
     * @return the formatted scope string
     */
    static String scopeRepository(ContainerRef ref, Scope... scopes) {
        List<String> actions = Arrays.stream(scopes).map(Scope::toLowerCase).collect(Collectors.toList());
        List<String> cleaned = cleanActions(actions);
        String repository = ref.getFullRepository();
        if (cleaned.isEmpty()) {
            return "";
        }
        return String.join(":", "repository", repository, String.join(",", cleaned));
    }

    /**
     * cleanScopes merges and sort the actions in ascending order if the scopes have
     * the same resource type and name. The final scopes are sorted in ascending
     * order. In other words, the scopes passed in are de-duplicated and sorted.
     * Therefore, the output of this function is deterministic.
     * @param scopes List of scopes
     * @return the cleaned scopes
     */
    static List<String> cleanScopes(@Nullable List<String> scopes) {

        // Empty or null
        if (scopes == null || scopes.isEmpty()) return Collections.emptyList();

        // Single scope
        if (scopes.size() == 1) {
            String scope = scopes.get(0);
            int i = scope.lastIndexOf(':');
            if (i == -1) return Collections.singletonList(scope);

            List<String> actions =
                    cleanActions(Arrays.asList(scope.substring(i + 1).split(",")));
            if (actions.isEmpty()) return Collections.emptyList();

            String cleaned = scope.substring(0, i + 1) + String.join(",", actions);
            return Collections.singletonList(cleaned);
        }

        Map<String, Map<String, Set<String>>> resourceTypes = new HashMap<>();
        List<String> result = new ArrayList<>();

        parseScopes(scopes, resourceTypes, result);
        buildScopeEntries(resourceTypes, result);

        Collections.sort(result);
        return result;
    }

    private static void parseScopes(
            List<String> scopes, Map<String, Map<String, Set<String>>> resourceTypes, List<String> result) {
        for (String scope : scopes) {
            int firstColon = scope.indexOf(':');
            if (firstColon == -1) {
                result.add(scope);
                continue;
            }
            String resourceType = scope.substring(0, firstColon);
            String rest = scope.substring(firstColon + 1);
            int lastColon = rest.lastIndexOf(':');
            if (lastColon == -1) {
                result.add(scope);
                continue;
            }

            String resourceName = rest.substring(0, lastColon);
            String actionPart = rest.substring(lastColon + 1);
            if (actionPart.isEmpty()) continue;

            Set<String> actions = Arrays.stream(actionPart.split(","))
                    .filter(s -> !s.isEmpty())
                    .collect(Collectors.toSet());

            resourceTypes
                    .computeIfAbsent(resourceType, k -> new HashMap<>())
                    .computeIfAbsent(resourceName, k -> new HashSet<>())
                    .addAll(actions);
        }
    }

    private static void buildScopeEntries(
            Map<String, Map<String, Set<String>>> resourceTypes, List<String> result) {
        for (Map.Entry<String, Map<String, Set<String>>> resourceEntry : resourceTypes.entrySet()) {
            String resourceType = resourceEntry.getKey();
            for (Map.Entry<String, Set<String>> nameEntry :
                    resourceEntry.getValue().entrySet()) {
                String resourceName = nameEntry.getKey();
                Set<String> actionSet = nameEntry.getValue();
                if (actionSet.isEmpty()) continue;

                List<String> actions = new ArrayList<>(actionSet);
                if (actions.contains("*")) {
                    actions = Collections.singletonList("*");
                } else {
                    Collections.sort(actions);
                }

                result.add(resourceType + ":" + resourceName + ":" + String.join(",", actions));
            }
        }
    }

    /**
     * cleanActions removes the duplicated actions and sort in ascending order.
     * If there is a wildcard `*` in the action, other actions are ignored.
     * @param actions List of action
     * @return the cleaned actions
     */
    static List<String> cleanActions(@Nullable List<String> actions) {
        if (actions == null || actions.isEmpty()) return Collections.emptyList();
        if (actions.size() == 1) {
            return actions.get(0).isEmpty() ? Collections.emptyList() : actions;
        }

        List<String> sorted = new ArrayList<>(actions);
        Collections.sort(sorted);

        List<String> result = new ArrayList<>();
        String prev = null;
        for (String action : sorted) {
            if ("*".equals(action)) {
                return Collections.singletonList("*");
            }
            if (!action.equals(prev)) {
                result.add(action);
                prev = action;
            }
        }

        // If the first is empty string, drop it unless it's the only one
        if (!result.isEmpty() && result.get(0).isEmpty()) {
            return result.size() == 1 ? Collections.emptyList() : result.subList(1, result.size());
        }

        return result;
    }
}
