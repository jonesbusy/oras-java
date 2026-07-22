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

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/**
 * The tags response object
 * @param name The name
 * @param tags The tags
 * @param last The last tag index, to iterate
 * @param n The n parameter, to iterate. As part of link response
 */
@NullMarked
@OrasModel
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Tags(String name, List<String> tags, @Nullable String last, @Nullable Integer n) {

    /**
     * Constructor without last
     * @param name The name
     * @param tags The tags
     */
    public Tags(String name, List<String> tags) {
        this(name, tags, null, null);
    }

    /**
     * With last
     * @param last The last tag index, to iterate
     * @return A new Tags object with the last index
     */
    public Tags withLast(@Nullable String last) {
        return new Tags(this.name, this.tags, last, n);
    }

    /**
     * With n param
     * @param n The n param
     * @return A new Tags object with the n param
     */
    public Tags withN(@Nullable Integer n) {
        return new Tags(this.name, this.tags, last, n);
    }
}
