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

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@Execution(ExecutionMode.CONCURRENT)
class AgentGatewayDevITCase {

    @Test
    void shouldGetTags() {
        Registry registry = Registry.builder().build();
        ContainerRef containerRef = ContainerRef.parse("cr.agentgateway.dev/agentgateway");
        Tags tags = registry.getTags(containerRef);
        assertTrue(tags.tags().contains("v1.3.0"), "Tag v1.3.0 must exists");
        assertTrue(tags.tags().size() > 400, "More that 400 must be returned");
    }
}
