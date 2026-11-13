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

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(providers = EnvironmentLock.class)
class TransferExecutorTest {

    @Test
    void shouldReleaseIdleThreadsOfDefaultRegistryExecutor() throws Exception {
        Registry registry = Registry.builder().withParallelism(3).build();
        ThreadPoolExecutor executor = assertInstanceOf(ThreadPoolExecutor.class, registry.getExecutorService());
        assertEquals(0, executor.getPoolSize(), "No thread must be started before the first transfer");
        assertEquals(3, executor.getMaximumPoolSize());
        assertEquals(OCI.TRANSFER_WORKER_KEEP_ALIVE_SECONDS, executor.getKeepAliveTime(TimeUnit.SECONDS));
        assertTrue(executor.allowsCoreThreadTimeOut(), "Idle threads must be released without explicit shutdown");
        assertIdleThreadsReleased(executor);
    }

    @Test
    void shouldReleaseIdleThreadsOfLayoutExecutor(@TempDir Path layoutPath) throws Exception {
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(layoutPath).build();
        ThreadPoolExecutor executor = assertInstanceOf(ThreadPoolExecutor.class, ociLayout.getExecutorService());
        assertEquals(1, executor.getMaximumPoolSize());
        assertTrue(executor.allowsCoreThreadTimeOut(), "Idle threads must be released without explicit shutdown");
        assertIdleThreadsReleased(executor);
    }

    @Test
    void shouldShareDefaultExecutorWithDerivedRegistries() {
        Registry registry = Registry.builder().build();
        ExecutorService executor = registry.getExecutorService();
        assertSame(executor, registry.copy("registry.example").getExecutorService());
        assertSame(executor, registry.asInsecure().getExecutorService());
    }

    @Test
    void shouldNotManageCallerSuppliedExecutor() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Registry registry = Registry.builder().withExecutorService(executor).build();
            assertSame(executor, registry.getExecutorService());
        } finally {
            executor.shutdownNow();
        }
    }

    private static void assertIdleThreadsReleased(ThreadPoolExecutor executor) throws Exception {
        // Speed up the idle timeout to observe the release
        executor.setKeepAliveTime(50, TimeUnit.MILLISECONDS);
        assertTrue(executor.submit(() -> Thread.currentThread().isDaemon()).get(5, TimeUnit.SECONDS));
        Awaitility.await().atMost(Duration.ofSeconds(5)).until(() -> executor.getPoolSize() == 0);

        // Still usable after the threads were released
        assertEquals(42, executor.submit(() -> 42).get(5, TimeUnit.SECONDS));
    }
}
