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

import land.oras.utils.SupportedAlgorithm;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/**
 * A referer of a container on a {@link OCI}.
 * @param <T> The type of the ref
 */
@NullMarked
public abstract sealed class Ref<T extends Ref<T>> permits ContainerRef, LayoutRef {

    /**
     * The tag of the container.
     */
    protected final @Nullable String tag;

    /**
     * Constructor
     * @param tag The tag
     */
    protected Ref(@Nullable String tag) {
        this.tag = tag;
    }

    /**
     * Get the tag
     * @return The tag
     */
    public @Nullable String getTag() {
        return tag;
    }

    /**
     * Return the ref with the digest
     * @param digest The digest
     * @return The ref
     */
    public abstract T withDigest(String digest);

    /**
     * Get the algorithm
     * @return The algorithm
     */
    public abstract SupportedAlgorithm getAlgorithm();

    /**
     * Get the repository where to find the ref
     * @return The repository
     */
    public abstract String getRepository();

    /**
     * Return a container ref for the target repository
     * @param target The target repository
     * @return The container ref
     */
    public abstract T forTarget(String target);

    /**
     * Return a container ref for the target repository
     * @param target The target repository
     * @return The container ref
     */
    public abstract T forTarget(OCI<T> target);

    /**
     * Get the target repository for the ref
     * @param target The target repository
     * @return The target repository
     */
    public abstract String getTarget(OCI<T> target);
}
