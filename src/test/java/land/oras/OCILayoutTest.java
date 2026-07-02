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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import land.oras.exception.OrasException;
import land.oras.policy.ContainersPolicy;
import land.oras.utils.Const;
import land.oras.utils.SupportedAlgorithm;
import land.oras.utils.ZotContainer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers(disabledWithoutDocker = true)
@Execution(ExecutionMode.CONCURRENT)
class OCILayoutTest {

    private static final Logger LOG = LoggerFactory.getLogger(OCILayoutTest.class);

    @TempDir
    private Path extractDir;

    @TempDir
    private Path blobDir;

    @TempDir
    private Path layoutPath;

    @Container
    private final ZotContainer registry = new ZotContainer().withStartupAttempts(3);

    @Test
    void shouldPushEmptyManifest() {
        Path path = layoutPath.resolve("shouldPushManifest");
        LayoutRef layoutRef = LayoutRef.parse("%s".formatted(path.toString()));
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(path).build();
        Manifest manifest = Manifest.empty().withConfig(Config.empty());
        manifest = ociLayout.pushManifest(layoutRef, manifest);

        // Assertion
        assertOciLayout(path);
        assertIndex(path, manifest, 1, 0);
        assertBlobExists(path, manifest.getDescriptor().getDigest());
        assertEquals(408, manifest.getDescriptor().getSize());

        // One element in the index
        Index index = Index.fromPath(path.resolve(Const.OCI_LAYOUT_INDEX));
        assertEquals(1, index.getManifests().size());

        // Ensure one layer for compatibility
        assertEquals(1, manifest.getLayers().size(), "Should have at least one layer");
        assertLayerExists(path, manifest.getLayers().get(0));
        assertEquals("e30=", manifest.getLayers().get(0).getData());

        // Copy again
        manifest = ociLayout.pushManifest(layoutRef, manifest);
        assertEquals(408, manifest.getDescriptor().getSize());

        // Same manifest
        index = Index.fromPath(path.resolve(Const.OCI_LAYOUT_INDEX));
        assertEquals(1, index.getManifests().size());

        // Add an other manifest with different digest
        Manifest manifest2 = Manifest.empty().withConfig(Config.empty()).withAnnotations(Map.of("foo", "bar"));
        ociLayout.pushManifest(layoutRef, manifest2);

        // Two elements in the index
        index = Index.fromPath(path.resolve(Const.OCI_LAYOUT_INDEX));
        assertEquals(2, index.getManifests().size());

        // First doesn't have any annotations, second yes
        assertNull(index.getManifests().get(0).getAnnotations());
        assertNotNull(index.getManifests().get(1).getAnnotations());
        assertEquals("bar", index.getManifests().get(1).getAnnotations().get("foo"));
    }

    @Test
    void shouldPushIndex() {
        Path path = layoutPath.resolve("shouldPushIndex");
        LayoutRef layoutRef = LayoutRef.parse("%s".formatted(path.toString()));
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(path).build();
        Index index = Index.fromManifests(List.of(Manifest.empty().getDescriptor()));
        index = ociLayout.pushIndex(layoutRef, index);

        // Assertion
        assertOciLayout(path);
        assertIndex(path, index, 1);
        assertBlobExists(path, index.getDescriptor().getDigest());
        assertEquals(229, index.getDescriptor().getSize());

        // One element in the index
        Index ociIndex = Index.fromPath(path.resolve(Const.OCI_LAYOUT_INDEX));
        assertEquals(1, ociIndex.getManifests().size());

        // Check latest tag
        assertNull(index.getManifests().get(0).getAnnotations());
    }

    @Test
    void shouldListTags() throws Exception {
        Path extractDir1 = extractDir.resolve("shouldListTags");
        Files.createDirectory(extractDir1);

        LayoutRef layoutRef = LayoutRef.parse("src/test/resources/oci/subject:latest");
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(layoutRef.getFolder()).build();
        Tags tags = ociLayout.getTags(layoutRef);
        assertEquals("subject", tags.name());
        assertEquals(1, tags.tags().size());
        assertEquals("latest", tags.tags().get(0));
    }

    @Test
    void shouldPushSignedLayoutAndPullItAndValidateSignature(@TempDir Path homeDir) throws Exception {

        // A signed alpine OCI layout
        String imageDigest = "sha256:9e56ed4cb843f61658fcdb17d4205a87d5e217515f23831314b2173a776174d6";
        LayoutRef layoutRef = LayoutRef.parse("src/test/resources/oci/alpine-signed@%s".formatted(imageDigest));
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(layoutRef.getFolder()).build();

        // Push the image AND its signature referrer to the registry (deep copy = include referrers).
        Registry pushRegistry = Registry.Builder.builder()
                .defaults("myuser", "mypass")
                .withInsecure(true)
                .build();
        ContainerRef targetRef =
                ContainerRef.parse("%s/library/alpine-signed:latest".formatted(registry.getRegistry()));
        CopyUtils.copy(ociLayout, layoutRef, pushRegistry, targetRef, CopyUtils.CopyOptions.deep());

        // Trust policy: accept only images carrying a valid Sigstore signature made by this key.
        Path publicKeyPath = Path.of("src/test/resources/keys/sigstore/alpine-signed.pub");
        Path policyPath = homeDir.resolve("policy.json");

        // language=json
        Files.writeString(
                policyPath,
                """
                {
                  "default": [{"type": "reject"}],
                  "transports": {
                    "docker": {
                      "%s/library/alpine-signed": [{"type": "sigstoreSigned", "keyPath": "%s"}]
                    }
                  }
                }
                """
                        .formatted(registry.getRegistry(), publicKeyPath.toAbsolutePath()));
        ContainersPolicy policy = ContainersPolicy.newPolicy(policyPath);

        // Pull the manifest with the policy: the attached signature is fetched and verified.
        Registry verifyingRegistry = Registry.Builder.builder()
                .defaults("myuser", "mypass")
                .withInsecure(true)
                .withPolicy(policy)
                .build();
        Manifest manifest = verifyingRegistry.getManifest(targetRef.withDigest(imageDigest));
        assertNotNull(manifest);
        assertEquals(imageDigest, manifest.getDescriptor().getDigest());
    }

    @Test
    void shouldListTagsWithLimit() throws Exception {
        Path extractDir1 = extractDir.resolve("shouldListTags");
        Files.createDirectory(extractDir1);

        LayoutRef layoutRef = LayoutRef.parse("src/test/resources/oci/subject:latest");
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(layoutRef.getFolder()).build();
        Tags tags = ociLayout.getTags(layoutRef, 1, null);
        assertEquals("subject", tags.name());
        assertEquals(1, tags.tags().size());
        assertEquals("latest", tags.tags().get(0));
    }

    @Test
    void shouldThrowIfLastTagInvalid() throws Exception {
        Path extractDir1 = extractDir.resolve("shouldListTags");
        Files.createDirectory(extractDir1);

        LayoutRef layoutRef = LayoutRef.parse("src/test/resources/oci/subject:latest");
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(layoutRef.getFolder()).build();
        assertThrows(OrasException.class, () -> {
            ociLayout.getTags(layoutRef, 1, "unknown");
        });
    }

    @Test
    void shouldListRepositories() throws Exception {
        Path extractDir1 = extractDir.resolve("shouldListRepositories");
        Files.createDirectory(extractDir1);

        LayoutRef layoutRef = LayoutRef.parse("src/test/resources/oci/subject:latest");
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(layoutRef.getFolder()).build();
        Repositories repositories = ociLayout.getRepositories();
        assertEquals(1, repositories.repositories().size());
        assertEquals("subject", repositories.repositories().get(0));
    }

    @Test
    void shouldPushConfig() throws IOException {
        Path path = layoutPath.resolve("shouldPushConfig");
        LayoutRef layoutRef = LayoutRef.parse("%s".formatted(path.toString()));
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(path).build();
        Config config = Config.empty();
        ociLayout.pushConfig(layoutRef.withDigest(config.getDigest()), config);

        // Assertion
        assertOciLayout(path);
        assertBlobExists(path, config.getDigest());

        // Try to pull config
        InputStream content = ociLayout.pullConfig(layoutRef, config);
        assertNotNull(content);
        assertEquals("{}", new String(content.readAllBytes(), StandardCharsets.UTF_8));
    }

    @Test
    void shouldPushConfigWithReference() throws IOException {
        Path path = layoutPath.resolve("shouldPushConfigWithReference");
        LayoutRef layoutRef = LayoutRef.parse("%s".formatted(path.toString()));
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(path).build();
        Path configFile = blobDir.resolve("config.txt");
        Files.writeString(configFile, "hello");
        Layer configLayer = Layer.fromFile(configFile);
        Config config = Config.fromBlob("application/vnd.oci.image.config.v1+json", configLayer);
        String digest = SupportedAlgorithm.getDefault().digest(configFile);
        ociLayout.pushBlob(layoutRef.withDigest(digest), configFile);

        // Assertion
        assertOciLayout(path);
        assertBlobExists(path, config.getDigest());

        // Try to pull config
        InputStream content = ociLayout.pullConfig(layoutRef, config);
        assertNotNull(content);
        assertEquals("hello", new String(content.readAllBytes(), StandardCharsets.UTF_8));
    }

    @Test
    void shouldRejectTamperedBlobOnRead() throws IOException {
        Path path = layoutPath.resolve("tamperedBlob");
        LayoutRef layoutRef = LayoutRef.parse("%s".formatted(path.toString()));
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(path).build();

        // Push a known blob into the layout
        Path blobFile = blobDir.resolve("blob.txt");
        Files.writeString(blobFile, "hello");
        String digest = SupportedAlgorithm.getDefault().digest(blobFile);
        ociLayout.pushBlob(layoutRef.withDigest(digest), blobFile);

        // Untampered blob reads back correctly
        assertEquals("hello", new String(ociLayout.getBlob(layoutRef.withDigest(digest)), StandardCharsets.UTF_8));

        // Tamper the blob on disk at its digest-derived path (simulating a co-tenant / shared FS)
        String hex = digest.substring(digest.indexOf(':') + 1);
        Path onDisk = path.resolve(Const.OCI_LAYOUT_BLOBS).resolve("sha256").resolve(hex);
        Files.writeString(onDisk, "evil");

        // The tampered content must be rejected rather than served as authentic
        LayoutRef tamperedRef = layoutRef.withDigest(digest);
        OrasException viaGetBlob = assertThrows(OrasException.class, () -> ociLayout.getBlob(tamperedRef));
        assertTrue(
                viaGetBlob.getMessage().contains("integrity check failed"),
                "Unexpected message: " + viaGetBlob.getMessage());

        // Every blob read path (getBlob, fetchBlob(ref), fetchBlob(ref, path)) is protected
        assertThrows(OrasException.class, () -> ociLayout.fetchBlob(tamperedRef));
        Path out = extractDir.resolve("out.bin");
        assertThrows(OrasException.class, () -> ociLayout.fetchBlob(tamperedRef, out));
    }

    @Test
    void shouldReadUntamperedBlobAfterIntegrityCheck() throws IOException {
        Path path = layoutPath.resolve("untamperedBlob");
        LayoutRef layoutRef = LayoutRef.parse("%s".formatted(path.toString()));
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(path).build();

        Path blobFile = blobDir.resolve("intact.txt");
        Files.writeString(blobFile, "intact-content");
        String digest = SupportedAlgorithm.getDefault().digest(blobFile);
        ociLayout.pushBlob(layoutRef.withDigest(digest), blobFile);

        // The integrity check must not break a legitimate, untouched blob on any read path
        LayoutRef ref = layoutRef.withDigest(digest);
        assertEquals("intact-content", new String(ociLayout.getBlob(ref), StandardCharsets.UTF_8));
        try (InputStream is = ociLayout.fetchBlob(ref)) {
            assertEquals("intact-content", new String(is.readAllBytes(), StandardCharsets.UTF_8));
        }
        Path out = extractDir.resolve("intact-out.txt");
        ociLayout.fetchBlob(ref, out);
        assertEquals("intact-content", Files.readString(out));
    }

    @Test
    void shouldRejectTamperedLayerOnPullArtifact() throws IOException {
        Path ociLayoutPath = layoutPath.resolve("tamperedLayerPull");
        Path artifactPath = blobDir.resolve("artifact.txt");
        Files.writeString(artifactPath, "artifact-content");

        LayoutRef layoutRef = LayoutRef.parse("%s:latest".formatted(ociLayoutPath.toString()));
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(ociLayoutPath).build();
        Annotations annotations = Annotations.ofManifest(Map.of(Const.ANNOTATION_CREATED, Const.currentTimestamp()));
        ociLayout.pushArtifact(
                layoutRef, ArtifactType.from("foo/bar"), annotations, LocalPath.of(artifactPath, "text/plain"));

        // Tamper the layer blob on disk at its digest-derived path
        String digest = SupportedAlgorithm.SHA256.digest(artifactPath);
        String hex = digest.substring(digest.indexOf(':') + 1);
        Path onDisk =
                ociLayoutPath.resolve(Const.OCI_LAYOUT_BLOBS).resolve("sha256").resolve(hex);
        Files.writeString(onDisk, "tampered-artifact");

        Path target = extractDir.resolve("pull-target");
        Files.createDirectories(target);
        OrasException ex = assertThrows(OrasException.class, () -> ociLayout.pullArtifact(layoutRef, target, true));
        assertTrue(ex.getMessage().contains("integrity check failed"), "Unexpected message: " + ex.getMessage());
    }

    @Test
    void verifyBlobDigestRejectsNonContentAddressedPath() throws IOException {
        Path ociLayoutPath = layoutPath.resolve("nonCasPath");
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(ociLayoutPath).build();

        // An existing file whose "<parentDir>:<fileName>" is not a valid digest ("notanalgo:somefile")
        Path notContentAddressed = blobDir.resolve("notanalgo").resolve("somefile");
        Files.createDirectories(notContentAddressed.getParent());
        Files.writeString(notContentAddressed, "data");

        OrasException ex = assertThrows(OrasException.class, () -> ociLayout.verifyBlobDigest(notContentAddressed));
        assertTrue(
                ex.getMessage().contains("not stored at a content-addressed path"),
                "Unexpected message: " + ex.getMessage());
    }

    @Test
    void verifyBlobDigestRejectsPathWithoutResolvableDigest() {
        Path ociLayoutPath = layoutPath.resolve("noDigestPath");
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(ociLayoutPath).build();

        // The filesystem root exists but has no file name (and no parent), so no digest can be derived
        Path root = layoutPath.getRoot();
        assertNotNull(root);
        assertNull(root.getFileName());
        OrasException ex = assertThrows(OrasException.class, () -> ociLayout.verifyBlobDigest(root));
        assertTrue(
                ex.getMessage().contains("Cannot resolve expected digest"), "Unexpected message: " + ex.getMessage());
    }

    @Test
    void verifyBlobDigestIgnoresMissingBlob() {
        Path ociLayoutPath = layoutPath.resolve("missingBlob");
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(ociLayoutPath).build();

        // A missing blob is not the integrity check's concern: it returns without throwing and lets
        // the caller (Files.newInputStream / Files.copy) surface the absence.
        Path missing = blobDir.resolve("does-not-exist");
        assertDoesNotThrow(() -> ociLayout.verifyBlobDigest(missing));
    }

    @Test
    void shouldPushIndexWithTag() {
        Path path = layoutPath.resolve("shouldPushIndexWithTag");
        LayoutRef layoutRef = LayoutRef.parse("%s".formatted(path.toString()));
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(path).build();
        Index index = Index.fromManifests(List.of(Manifest.empty().getDescriptor()));
        index = ociLayout.pushIndex(layoutRef.withTag("latest"), index);

        // Assertion
        assertOciLayout(path);
        assertIndex(path, index, 1);
        assertBlobExists(path, index.getDescriptor().getDigest());
        assertEquals(229, index.getDescriptor().getSize());

        // One element in the index
        Index ociIndex = Index.fromPath(path.resolve(Const.OCI_LAYOUT_INDEX));
        assertEquals(1, ociIndex.getManifests().size());

        // Check latest tag
        assertEquals("latest", ociIndex.getManifests().get(0).getAnnotations().get(Const.ANNOTATION_REF));
    }

    @Test
    void shouldPushManifestFromFile() {

        Path path = layoutPath.resolve("shouldPushManifetFromFile");
        LayoutRef layoutRef = LayoutRef.parse("%s".formatted(path.toString()));
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(path).build();

        Manifest manifest = Manifest.fromPath(
                Path.of(
                        "src/test/resources/oci/artifact/blobs/sha256/cb1d49baba271af2c56d493d66dddb112ecf1c2c52f47e6f45f3617bb2155d34"));

        manifest = ociLayout.pushManifest(layoutRef, manifest);

        // Assertion
        assertOciLayout(path);
        assertIndex(path, manifest, 1, 0);
        assertBlobExists(path, manifest.getDescriptor().getDigest());
        assertEquals(556, manifest.getDescriptor().getSize());

        // One element in the index
        Index index = Index.fromPath(path.resolve(Const.OCI_LAYOUT_INDEX));
        assertEquals(1, index.getManifests().size());

        // Assert the manifest
        assertNull(manifest.getLayers().get(0).getData());

        // Copy again
        manifest = ociLayout.pushManifest(layoutRef, manifest);
        assertEquals(556, manifest.getDescriptor().getSize());

        // Same manifest
        index = Index.fromPath(path.resolve(Const.OCI_LAYOUT_INDEX));
        assertEquals(1, index.getManifests().size());

        // Two elements in the index
        index = Index.fromPath(path.resolve(Const.OCI_LAYOUT_INDEX));
        assertEquals(1, index.getManifests().size());
    }

    @Test
    void shouldPushEmptyManifestWithRef() {
        Path path = layoutPath.resolve("shouldPushManifest");
        LayoutRef layoutRef = LayoutRef.parse("%s:latest".formatted(path.toString()));
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(path).build();
        Manifest manifest = Manifest.empty().withConfig(Config.empty());
        manifest = ociLayout.pushManifest(layoutRef, manifest);

        // Assertion
        assertOciLayout(path);
        assertIndex(path, manifest, 1, 0);
        assertBlobExists(path, manifest.getDescriptor().getDigest());
        assertEquals(408, manifest.getDescriptor().getSize());

        // One element in the index
        Index index = Index.fromPath(path.resolve(Const.OCI_LAYOUT_INDEX));
        assertEquals(1, index.getManifests().size());

        // Check latest tag
        assertEquals("latest", index.getManifests().get(0).getAnnotations().get(Const.ANNOTATION_REF));

        // Ensure one layer for compatibility
        assertEquals(1, manifest.getLayers().size(), "Should have at least one layer");
        assertLayerExists(path, manifest.getLayers().get(0));
        assertEquals("e30=", manifest.getLayers().get(0).getData());

        // Copy again
        manifest = ociLayout.pushManifest(layoutRef, manifest);
        assertEquals(408, manifest.getDescriptor().getSize());

        index = Index.fromPath(path.resolve(Const.OCI_LAYOUT_INDEX));
        assertEquals(1, index.getManifests().size());

        // Add an other manifest with different digest
        Manifest manifest2 = Manifest.empty().withConfig(Config.empty()).withAnnotations(Map.of("foo", "bar"));
        ociLayout.pushManifest(layoutRef, manifest2);

        // Two elements in the index
        index = Index.fromPath(path.resolve(Const.OCI_LAYOUT_INDEX));
        assertEquals(2, index.getManifests().size());

        // Ensure manifest1 doesn't have any annotations
        assertNull(index.getManifests().get(0).getAnnotations());

        // Ref was moved to manifest2
        assertEquals("latest", index.getManifests().get(1).getAnnotations().get(Const.ANNOTATION_REF));
    }

    @Test
    void shouldEnforceTagWhenPullArtifact() throws IOException {
        LayoutRef layoutRef = LayoutRef.parse("src/test/resources/oci/artifact");
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(layoutRef.getFolder()).build();
        assertThrows(OrasException.class, () -> {
            ociLayout.pullArtifact(layoutRef, extractDir, false);
        });
    }

    @Test
    void shouldEnforceTagWhenGettingDescriptor() throws IOException {
        LayoutRef layoutRef = LayoutRef.parse("src/test/resources/oci/artifact");
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(layoutRef.getFolder()).build();
        assertThrows(OrasException.class, () -> {
            ociLayout.getDescriptor(layoutRef);
        });
    }

    @Test
    void failToCreateLayoutIfFileExists() throws IOException {
        Path path = layoutPath.resolve("failToCreateLayoutIfFileExists");
        Files.createFile(path);
        assertThrows(OrasException.class, () -> {
            LayoutRef layoutRef = LayoutRef.parse("%s".formatted(path.toString()));
            OCILayout.Builder.builder().defaults(layoutRef.getFolder()).build();
        });
    }

    @Test
    void shouldPushToOciLayoutWithoutTag() throws IOException {

        Path ociLayoutPath = layoutPath.resolve("shouldPushToOciLayoutWithoutTag");
        Path artifactPath = blobDir.resolve("shouldPushToOciLayoutWithoutTag.txt");
        Files.writeString(artifactPath, "hi");

        LayoutRef layoutRef = LayoutRef.parse("%s".formatted(ociLayoutPath.toString()));
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(ociLayoutPath).build();

        // Ensure we have time created time
        Annotations annotations = Annotations.ofManifest(Map.of(Const.ANNOTATION_CREATED, Const.currentTimestamp()));

        Manifest manifest = ociLayout.pushArtifact(
                layoutRef, ArtifactType.from("foo/bar"), annotations, LocalPath.of(artifactPath, "text/plain"));

        assertOciLayout(ociLayoutPath);

        // Assert the empty config
        assertBlobContent(ociLayoutPath, Config.empty().getDigest(), "{}");

        // Check index exists
        assertIndex(ociLayoutPath, manifest, 1, 0);

        // Assert blobs and their content
        assertBlobExists(ociLayoutPath, SupportedAlgorithm.SHA256.digest(artifactPath));
        assertBlobContent(ociLayoutPath, SupportedAlgorithm.SHA256.digest(artifactPath), "hi");

        // Push again
        Manifest manifest1 = ociLayout.pushArtifact(
                layoutRef, ArtifactType.from("foo/bar"), annotations, LocalPath.of(artifactPath, "text/plain"));

        // Check index exists
        assertIndex(ociLayoutPath, manifest1, 1, 0);

        Index index = Index.fromPath(ociLayoutPath.resolve(Const.OCI_LAYOUT_INDEX));

        // No annotation
        assertNotNull(index.getManifests().get(0).getAnnotations(), "Annotation should not be null");
        assertEquals(1, index.getManifests().get(0).getAnnotations().size());
        assertTrue(
                index.getManifests().get(0).getAnnotations().containsKey(Const.ANNOTATION_CREATED),
                "Should have created annotation");

        // Test attaching artifact
        // Create fake signature
        String artifactType = "application/vnd.maven+type";
        Path signedPomFile = blobDir.resolve("pom.xml.asc");
        Files.writeString(signedPomFile, "my signed pom file");

        // Attach artifact
        Manifest signedPomFileManifest = ociLayout.attachArtifact(
                layoutRef.withDigest(manifest.getDigest()),
                ArtifactType.from(artifactType),
                LocalPath.of(signedPomFile));

        index = Index.fromPath(ociLayoutPath.resolve(Const.OCI_LAYOUT_INDEX));

        // 2 manifests
        assertEquals(2, index.getManifests().size());
        assertEquals(1, index.getManifests().get(1).getAnnotations().size());
        assertTrue(
                index.getManifests().get(1).getAnnotations().containsKey(Const.ANNOTATION_CREATED),
                "Should have created annotation");

        // Check if we can mount blobs
        assertTrue(ociLayout.canMount(ociLayout, layoutRef, layoutRef));
        assertFalse(ociLayout.canMount(ociLayout, layoutRef, layoutRef.forTarget("other")));
        assertFalse(ociLayout.canMount(Registry.builder().build(), layoutRef, layoutRef.forTarget("other")));
    }

    @Test
    void shouldMount() {
        Path pathSource = layoutPath.resolve("shouldMountSource");
        Path pathTarget = layoutPath.resolve("shouldMountTarget");
        byte[] content = "hi".getBytes(StandardCharsets.UTF_8);
        String digest = SupportedAlgorithm.getDefault().digest(content);
        OCILayout ociLayoutSource =
                OCILayout.Builder.builder().defaults(pathSource).build();
        OCILayout ociLayoutTarget =
                OCILayout.Builder.builder().defaults(pathTarget).build();
        LayoutRef layoutRef = LayoutRef.of(ociLayoutSource, digest);
        ociLayoutSource.pushBlob(layoutRef, "hi".getBytes(StandardCharsets.UTF_8));
        Manifest manifest = Manifest.empty().withLayers(List.of(Layer.fromDigest(digest, 2L)));
        ociLayoutSource.pushManifest(layoutRef.withTag("latest"), manifest);
        ociLayoutTarget.mountBlob(layoutRef, layoutRef);
        ociLayoutTarget.mountBlob(layoutRef, layoutRef);
        OrasException e = assertThrows(
                OrasException.class,
                () -> {
                    ociLayoutTarget.mountBlob(LayoutRef.of(ociLayoutSource), layoutRef);
                },
                "Missing digest");
        assertEquals("Digest is required to mount blob", e.getMessage());
    }

    @Test
    void shouldPushToOciLayoutWithTag() throws IOException {

        Path ociLayoutPath = layoutPath.resolve("shouldPushToOciLayoutWithTag");
        Path artifactPath = blobDir.resolve("shouldPushToOciLayoutWithTag.txt");
        Files.writeString(artifactPath, "hi");

        LayoutRef layoutRef = LayoutRef.parse("%s:latest".formatted(ociLayoutPath.toString()));
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(ociLayoutPath).build();

        // Ensure we have time created time
        Annotations annotations = Annotations.ofManifest(Map.of(Const.ANNOTATION_CREATED, Const.currentTimestamp()));

        Manifest manifest = ociLayout.pushArtifact(
                layoutRef, ArtifactType.from("foo/bar"), annotations, LocalPath.of(artifactPath, "text/plain"));

        assertOciLayout(ociLayoutPath);

        // Assert the empty config
        assertBlobContent(ociLayoutPath, Config.empty().getDigest(), "{}");

        // Check index exists
        assertIndex(ociLayoutPath, manifest, 1, 0);

        // Assert blobs and their content
        assertBlobExists(ociLayoutPath, SupportedAlgorithm.SHA256.digest(artifactPath));
        assertBlobContent(ociLayoutPath, SupportedAlgorithm.SHA256.digest(artifactPath), "hi");

        // Push again
        Manifest manifest1 = ociLayout.pushArtifact(
                layoutRef, ArtifactType.from("foo/bar"), annotations, LocalPath.of(artifactPath, "text/plain"));

        // Check index exists
        assertIndex(ociLayoutPath, manifest1, 1, 0);

        Index index = Index.fromPath(ociLayoutPath.resolve(Const.OCI_LAYOUT_INDEX));

        // No annotation
        assertNotNull(index.getManifests().get(0).getAnnotations(), "Some annotations should not be null");
        assertEquals(2, index.getManifests().get(0).getAnnotations().size(), "Annotation should have 2 elements");
        assertNotNull(index.getManifests().get(0).getAnnotations().get(Const.ANNOTATION_CREATED));
        assertEquals("latest", index.getManifests().get(0).getAnnotations().get(Const.ANNOTATION_REF));
    }

    @Test
    void shouldPullViaTagFromOciLayout() throws IOException {

        Path extractDir1 = extractDir.resolve("shouldPullViaTagFromOciLayout");
        Files.createDirectory(extractDir1);

        LayoutRef layoutRef = LayoutRef.parse("src/test/resources/oci/artifact:latest");
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(layoutRef.getFolder()).build();
        ociLayout.pullArtifact(layoutRef, extractDir1, false);

        // Check file exists
        assertTrue(Files.exists(extractDir1.resolve("hi.txt")));

        // Fetch the manifest
        byte[] blob = ociLayout.getBlob(layoutRef);
        Manifest manifest = Manifest.fromJson(new String(blob, StandardCharsets.UTF_8));
        assertEquals(1, manifest.getLayers().size());
        ociLayout.fetchBlob(layoutRef, extractDir1.resolve("manifest.json"));

        // Ensure digest
        String manifestDigest = SupportedAlgorithm.getDefault().digest(blob);
        assertEquals("sha256:cb1d49baba271af2c56d493d66dddb112ecf1c2c52f47e6f45f3617bb2155d34", manifestDigest);

        manifest = ociLayout.getManifest(layoutRef);
        manifestDigest =
                SupportedAlgorithm.getDefault().digest(manifest.getJson().getBytes(StandardCharsets.UTF_8));
        assertEquals("sha256:cb1d49baba271af2c56d493d66dddb112ecf1c2c52f47e6f45f3617bb2155d34", manifestDigest);

        // Cannot get blob without ref
        assertThrows(OrasException.class, () -> {
            ociLayout.fetchBlobDescriptor(LayoutRef.parse("src/test/resources/oci/artifact"));
        });

        // Cannot get manifest without ref
        assertThrows(OrasException.class, () -> {
            ociLayout.getManifest(LayoutRef.parse("src/test/resources/oci/artifact"));
        });

        Descriptor manifestDescriptor = ociLayout.fetchBlobDescriptor(layoutRef);
        assertEquals(556, manifestDescriptor.getSize());
        assertEquals(Const.DEFAULT_MANIFEST_MEDIA_TYPE, manifestDescriptor.getMediaType());
        assertNotNull(manifestDescriptor.getArtifactType());
        assertEquals("foo/bar", manifestDescriptor.getArtifactType().getMediaType());
        assertEquals(
                "sha256:cb1d49baba271af2c56d493d66dddb112ecf1c2c52f47e6f45f3617bb2155d34",
                manifestDescriptor.getDigest());
        assertNotNull(manifestDescriptor.getAnnotations());
        assertNotNull(manifestDescriptor.getAnnotations().get(Const.ANNOTATION_CREATED));
        assertEquals("latest", manifestDescriptor.getAnnotations().get(Const.ANNOTATION_REF));

        // By digest
        LayoutRef layoutRefDigest = LayoutRef.parse(
                "src/test/resources/oci/artifact@sha256:98ea6e4f216f2fb4b69fff9b3a44842c38686ca685f3f55dc48c5d3fb1107be4");
        ociLayout.fetchBlob(layoutRefDigest, extractDir1.resolve("new_hi.txt"));

        // Ensure file exists
        assertTrue(Files.exists(extractDir1.resolve("manifest.json")));
        assertTrue(Files.exists(extractDir1.resolve("new_hi.txt")));

        // Assert content
        assertEquals(
                Files.readString(
                        Path.of(
                                "src/test/resources/oci/artifact/blobs/sha256/98ea6e4f216f2fb4b69fff9b3a44842c38686ca685f3f55dc48c5d3fb1107be4")),
                Files.readString(extractDir1.resolve("new_hi.txt")));
        assertEquals(
                Files.readString(
                        Path.of(
                                "src/test/resources/oci/artifact/blobs/sha256/cb1d49baba271af2c56d493d66dddb112ecf1c2c52f47e6f45f3617bb2155d34")),
                Files.readString(extractDir1.resolve("manifest.json")));
    }

    @Test
    void shouldGetReferrers() throws IOException {

        Path extractDir1 = extractDir.resolve("shouldGetReferrers");
        Files.createDirectory(extractDir1);

        LayoutRef layoutRef = LayoutRef.parse("src/test/resources/oci/subject:latest");
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(layoutRef.getFolder()).build();

        Referrers referrers = ociLayout.getReferrers(layoutRef, null);
        assertEquals(1, referrers.getManifests().size());

        ManifestDescriptor manifestDescriptor = referrers.getManifests().get(0);
        assertEquals(
                "sha256:ccec2a2be7ce7c6aadc8ed0dc03df8f91cbd3534272dd1f8284226a8d3516dd6",
                manifestDescriptor.getDigest());
        assertEquals(746, manifestDescriptor.getSize());
        assertEquals("application/vnd.oci.image.manifest.v1+json", manifestDescriptor.getMediaType());
        assertNotNull(manifestDescriptor.getAnnotations());
        assertEquals(1, manifestDescriptor.getAnnotations().size());
        assertEquals("2025-04-07T14:54:25Z", manifestDescriptor.getAnnotations().get(Const.ANNOTATION_CREATED));
    }

    @Test
    void shouldPullIndex() throws IOException {

        Path extractDir1 = extractDir.resolve("shouldPullViaTagFromOciLayout");
        Files.createDirectory(extractDir1);

        LayoutRef layoutRef = LayoutRef.parse("src/test/resources/oci/artifact:latest");
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(layoutRef.getFolder()).build();
        Index index = ociLayout.getIndex(layoutRef);
        assertEquals(2, index.getSchemaVersion());
        assertEquals(1, index.getManifests().size());

        ManifestDescriptor manifestDescriptor = index.getManifests().get(0);
        assertEquals("foo/bar", manifestDescriptor.getArtifactType());
        assertEquals(
                "sha256:cb1d49baba271af2c56d493d66dddb112ecf1c2c52f47e6f45f3617bb2155d34",
                manifestDescriptor.getDigest());
        assertEquals(556, manifestDescriptor.getSize());
        assertNotNull(manifestDescriptor.getAnnotations());
        assertNotNull(manifestDescriptor.getAnnotations().get(Const.ANNOTATION_CREATED));
        assertEquals("latest", manifestDescriptor.getAnnotations().get(Const.ANNOTATION_REF));
        assertNotNull(manifestDescriptor.getPlatform());
        assertEquals(Platform.empty(), manifestDescriptor.getPlatform());
    }

    @Test
    void shouldPullViaDigestFromOciLayout() throws IOException {

        Path extractDir1 = extractDir.resolve("shouldPullViaDigestFromOciLayout");
        Files.createDirectory(extractDir1);

        LayoutRef layoutRef = LayoutRef.parse(
                "src/test/resources/oci/artifact@sha256:cb1d49baba271af2c56d493d66dddb112ecf1c2c52f47e6f45f3617bb2155d34");
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(layoutRef.getFolder()).build();
        ociLayout.pullArtifact(layoutRef, extractDir1, false);

        // Check file exists
        assertTrue(Files.exists(extractDir1.resolve("hi.txt")));

        // We get the manifest via digest
        Descriptor manifestDescriptor = ociLayout.fetchBlobDescriptor(layoutRef);
        assertEquals(556, manifestDescriptor.getSize());
        assertEquals(Const.DEFAULT_DESCRIPTOR_MEDIA_TYPE, manifestDescriptor.getMediaType());
        assertEquals(
                "sha256:cb1d49baba271af2c56d493d66dddb112ecf1c2c52f47e6f45f3617bb2155d34",
                manifestDescriptor.getDigest());
    }

    @Test
    void shouldPushBlob() throws IOException {

        Path path = layoutPath.resolve("shouldPushBlob");

        byte[] content = "hi".getBytes(StandardCharsets.UTF_8);
        String digest = SupportedAlgorithm.SHA256.digest(content);

        OCILayout ociLayout = OCILayout.Builder.builder().defaults(path).build();
        LayoutRef layoutRef = LayoutRef.of(ociLayout, digest);

        // Push more blobs
        ociLayout.pushBlob(layoutRef, "hi".getBytes(StandardCharsets.UTF_8));

        // Assert file exists
        assertBlobExists(path, digest);
        assertBlobContent(path, digest, "hi");

        // Push again
        ociLayout.pushBlob(layoutRef, "hi".getBytes(StandardCharsets.UTF_8));

        assertBlobExists(path, digest);
        assertBlobContent(path, digest, "hi");
    }

    @Test
    void shouldFailToPushBlobViaStreamWithoutDigest() {
        Path path = layoutPath.resolve("shouldFailToPushBlobViaStreamWithoutDigest");
        byte[] content = "hi".getBytes(StandardCharsets.UTF_8);
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(path).build();
        LayoutRef layoutRef = LayoutRef.parse("test");
        OrasException e = assertThrows(OrasException.class, () -> {
            ociLayout.pushBlob(layoutRef, content.length, () -> InputStream.nullInputStream(), Map.of());
        });
        assertEquals("Digest is required to push blob to layout", e.getMessage());
    }

    @Test
    void shouldFailToPushBlobViaStreamWithInvalidDigest() {
        Path path = layoutPath.resolve("shouldFailToPushBlobViaStreamWithInvalidDigest");
        byte[] content = "hi".getBytes(StandardCharsets.UTF_8);
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(path).build();
        LayoutRef layoutRef = LayoutRef.parse("test:1234");
        OrasException e = assertThrows(OrasException.class, () -> {
            ociLayout.pushBlob(layoutRef, content.length, () -> InputStream.nullInputStream(), Map.of());
        });
        assertEquals("Unsupported digest: 1234", e.getMessage());
    }

    @Test
    void cannotPushBlobWithoutTagOrDigest() throws IOException {

        Path invalidBlobPushDir = layoutPath.resolve("shouldPushArtifact");

        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(invalidBlobPushDir).build();

        LayoutRef noTagLayout = LayoutRef.of(ociLayout);
        LayoutRef noDigestLayout = LayoutRef.of(ociLayout, "latest");

        // Push more blobs
        assertThrows(OrasException.class, () -> {
            ociLayout.pushBlob(noTagLayout, "hi".getBytes(StandardCharsets.UTF_8));
        });
        assertThrows(OrasException.class, () -> {
            ociLayout.pushBlob(noDigestLayout, "hi".getBytes(StandardCharsets.UTF_8));
        });
    }

    @Test
    void cannotPushBlobFromPathWithoutTagOrDigest() throws IOException {
        Path invalidBlobPushDir = layoutPath.resolve("cannotPushBlobFromPathWithoutTagOrDigest");
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(invalidBlobPushDir).build();
        Path blobFile = blobDir.resolve("cannotPushBlobFromPathWithoutTagOrDigest.txt");
        Files.writeString(blobFile, "hello");

        LayoutRef noTagLayout = LayoutRef.of(ociLayout);
        OrasException e1 = assertThrows(OrasException.class, () -> ociLayout.pushBlob(noTagLayout, blobFile, Map.of()));
        assertEquals("Missing ref", e1.getMessage());

        LayoutRef noDigestLayout = LayoutRef.of(ociLayout, "latest");
        OrasException e2 =
                assertThrows(OrasException.class, () -> ociLayout.pushBlob(noDigestLayout, blobFile, Map.of()));
        assertEquals("Unsupported digest: latest", e2.getMessage());
    }

    @Test
    void cannotPushWithInvalidDigest() {
        Path invalidBlobPushDir = layoutPath.resolve("cannotPushWithInvalidDigest");

        LayoutRef wrongDigest1 = LayoutRef.parse("%s@sha234:1234".formatted(invalidBlobPushDir.toString()));
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(invalidBlobPushDir).build();

        // Push more blobs
        assertThrows(OrasException.class, () -> {
            ociLayout.pushBlob(wrongDigest1, "hi".getBytes(StandardCharsets.UTF_8));
        });

        LayoutRef wrongDigest2 = LayoutRef.parse("%s@sha256:1234".formatted(invalidBlobPushDir.toString()));

        // Push more blobs
        assertThrows(OrasException.class, () -> {
            ociLayout.pushBlob(wrongDigest2, "hi".getBytes(StandardCharsets.UTF_8));
        });
    }

    @Test
    void testShouldCopyArtifactFromRegistryIntoOciLayout() throws IOException {

        Registry registry = Registry.Builder.builder()
                .defaults("myuser", "mypass")
                .withInsecure(true)
                .build();

        OCILayout ociLayout = OCILayout.builder().defaults(layoutPath).build();
        LayoutRef layoutRef = LayoutRef.of(ociLayout);

        ContainerRef containerRef =
                ContainerRef.parse("%s/library/artifact-oci-layout".formatted(this.registry.getRegistry()));
        Path file1 = blobDir.resolve("artifact-oci-layout.txt");
        Path file2 = blobDir.resolve("artifact-recursive-oci-attached.txt");
        Files.writeString(file1, "artifact-oci-layout");
        Files.writeString(file2, "reference");

        // Push
        Manifest manifest = registry.pushArtifact(containerRef, LocalPath.of(file1));
        registry.attachArtifact(containerRef, ArtifactType.from("application/foo"), LocalPath.of(file2));

        // Copy to oci layout
        CopyUtils.copy(registry, containerRef, ociLayout, layoutRef, CopyUtils.CopyOptions.shallow());

        assertOciLayout(layoutPath);

        // Assert the empty config
        assertBlobContent(layoutPath, Config.empty().getDigest(), "{}");

        // Check index exists
        assertIndex(layoutPath, manifest, 1, 0);

        // Assert blobs and their content
        assertBlobExists(layoutPath, SupportedAlgorithm.SHA256.digest(file1));
        assertBlobContent(layoutPath, SupportedAlgorithm.SHA256.digest(file1), "artifact-oci-layout");

        // Blob is absent
        assertBlobAbsent(layoutPath, SupportedAlgorithm.SHA256.digest(file2));
    }

    @Test
    void testShouldCopyIndexWithPlatformFilterFromRegistryIntoOciLayout() throws IOException {

        Registry registry = Registry.Builder.builder()
                .defaults("myuser", "mypass")
                .withInsecure(true)
                .build();

        Path ociLayoutPath = layoutPath.resolve("testShouldCopyIndexWithPlatformFilterFromRegistryIntoOciLayout");
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(ociLayoutPath).build();
        LayoutRef layoutRef = LayoutRef.parse("%s:latest".formatted(ociLayoutPath.toString()));

        ContainerRef containerRef =
                ContainerRef.parse("%s/library/platform-filter-source".formatted(this.registry.getRegistry()));

        // Push two manifests with different content, one per platform
        Path fileAmd64 = blobDir.resolve("platform-filter-amd64.txt");
        Path fileArm64 = blobDir.resolve("platform-filter-arm64.txt");
        Files.writeString(fileAmd64, "content-amd64");
        Files.writeString(fileArm64, "content-arm64");

        Manifest manifestAmd64 = registry.pushArtifact(containerRef.withTag("amd64"), LocalPath.of(fileAmd64));
        Manifest manifestArm64 = registry.pushArtifact(containerRef.withTag("arm64"), LocalPath.of(fileArm64));

        assertNotNull(manifestAmd64.getDescriptor());
        assertNotNull(manifestArm64.getDescriptor());

        // Build a multi-platform index and push it
        ManifestDescriptor descAmd64 = manifestAmd64.getDescriptor().withPlatform(Platform.linuxAmd64());
        ManifestDescriptor descArm64 = manifestArm64.getDescriptor().withPlatform(Platform.linuxArm64V8());
        Index sourceIndex = Index.fromManifests(List.of(descAmd64, descArm64));
        registry.pushIndex(containerRef.withTag("latest"), sourceIndex);

        // Copy only linux/amd64 into the OCI layout
        CopyUtils.copy(
                registry,
                containerRef.withTag("latest"),
                ociLayout,
                layoutRef,
                CopyUtils.CopyOptions.shallow().withPlatformFilter(Set.of(Platform.linuxAmd64())));

        // The layout must be a valid OCI layout
        assertOciLayout(ociLayoutPath);

        // The OCI layout root index.json has two entries:
        //   1. the amd64 manifest blob (pushed individually, no tag)
        //   2. the filtered index blob (tagged "latest")
        Index ociIndex = Index.fromPath(ociLayoutPath.resolve(Const.OCI_LAYOUT_INDEX));
        assertEquals(2, ociIndex.getManifests().size(), "OCI layout index.json must have two entries");

        // Find the filtered-index entry by its tag annotation
        ManifestDescriptor filteredIndexDescriptor = ociIndex.getManifests().stream()
                .filter(d -> d.getAnnotations() != null
                        && "latest".equals(d.getAnnotations().get(Const.ANNOTATION_REF)))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No entry with tag 'latest' found in OCI layout index.json"));
        assertBlobExists(ociLayoutPath, filteredIndexDescriptor.getDigest());

        // The filtered index blob itself contains only the amd64 manifest descriptor
        Index filteredIndex = Index.fromJson(Files.readString(ociLayoutPath
                .resolve("blobs")
                .resolve("sha256")
                .resolve(SupportedAlgorithm.getDigest(filteredIndexDescriptor.getDigest()))));
        assertEquals(1, filteredIndex.getManifests().size(), "Filtered index must contain exactly one manifest");
        assertEquals(
                Platform.linuxAmd64(),
                filteredIndex.getManifests().get(0).getPlatform(),
                "The single manifest in the filtered index must be linux/amd64");

        // The amd64 layer blob and its config must be present
        assertBlobExists(ociLayoutPath, SupportedAlgorithm.SHA256.digest(fileAmd64));
        assertBlobContent(ociLayoutPath, SupportedAlgorithm.SHA256.digest(fileAmd64), "content-amd64");
        assertBlobContent(ociLayoutPath, Config.empty().getDigest(), "{}");

        // The arm64 layer blob must be absent — it was filtered out
        assertBlobAbsent(ociLayoutPath, SupportedAlgorithm.SHA256.digest(fileArm64));
    }

    @Test
    void testShouldCopyFromOciLayoutIntoOciLayoutRecursive() throws IOException {

        // Source
        LayoutRef sourceRef = LayoutRef.parse("src/test/resources/oci/subject:latest");
        OCILayout source = OCILayout.builder().defaults(sourceRef.getFolder()).build();

        // Target
        Path ociLayoutPath = layoutPath.resolve("testShouldCopyFromOciLayoutIntoOciLayoutRecursive");
        LayoutRef targetRef = LayoutRef.parse("%s".formatted(ociLayoutPath.toString()));
        OCILayout target = OCILayout.builder().defaults(targetRef.getFolder()).build();

        // Copy to oci layout
        CopyUtils.copy(source, sourceRef, target, targetRef, CopyUtils.CopyOptions.deep());

        // Assertion
        assertOciLayout(ociLayoutPath);
        Manifest manifest = target.getManifest(
                targetRef.withDigest("sha256:bb329f103a5fd68e96771f7dcfaa7722e9ec727bb9ab83c2beee96d6f25b08d6"));
        assertIndex(ociLayoutPath, manifest, 2, 0);

        assertBlobContent(ociLayoutPath, Config.empty().getDigest(), "{}");

        // 2 artifacts
        assertBlobExists(
                ociLayoutPath, "sha256:98ea6e4f216f2fb4b69fff9b3a44842c38686ca685f3f55dc48c5d3fb1107be4"); // hi.txt
        assertBlobExists(
                ociLayoutPath, "sha256:e094bc809626f0a401a40d75c56df478e546902ff812772c4594265203b23980"); // hi2.txt
    }

    @Test
    void testShouldCopyFromOciLayoutIntoOciLayoutNonRecursive() throws IOException {

        // Source
        LayoutRef sourceRef = LayoutRef.parse("src/test/resources/oci/subject:latest");
        OCILayout source = OCILayout.builder().defaults(sourceRef.getFolder()).build();

        // Target
        Path ociLayoutPath = layoutPath.resolve("testShouldCopyFromOciLayoutIntoOciLayoutNonRecursive");
        LayoutRef targetRef = LayoutRef.parse("%s".formatted(ociLayoutPath.toString()));
        OCILayout target = OCILayout.builder().defaults(targetRef.getFolder()).build();

        // Copy to oci layout
        CopyUtils.copy(source, sourceRef, target, targetRef, CopyUtils.CopyOptions.shallow());

        // Assertion
        assertOciLayout(ociLayoutPath);
        Manifest manifest = target.getManifest(
                targetRef.withDigest("sha256:bb329f103a5fd68e96771f7dcfaa7722e9ec727bb9ab83c2beee96d6f25b08d6"));
        assertIndex(ociLayoutPath, manifest, 1, 0);

        assertBlobContent(ociLayoutPath, Config.empty().getDigest(), "{}");

        // 1 artifacts
        assertBlobExists(
                ociLayoutPath, "sha256:98ea6e4f216f2fb4b69fff9b3a44842c38686ca685f3f55dc48c5d3fb1107be4"); // hi.txt
        assertBlobAbsent(
                ociLayoutPath, "sha256:e094bc809626f0a401a40d75c56df478e546902ff812772c4594265203b23980"); // hi2.txt
    }

    @Test
    void testShouldCopyRecursivelyArtifactFromRegistryIntoOciLayout() throws IOException {

        Registry registry = Registry.Builder.builder()
                .defaults("myuser", "mypass")
                .withInsecure(true)
                .build();

        OCILayout ociLayout = OCILayout.Builder.builder().defaults(layoutPath).build();
        LayoutRef layoutRef = LayoutRef.parse("%s".formatted(ociLayout.getPath()));

        ContainerRef containerRef =
                ContainerRef.parse("%s/library/artifact-recursive-oci-layout".formatted(this.registry.getRegistry()));
        Path file1 = blobDir.resolve("artifact-recursive-oci-layout.txt");
        Path file2 = blobDir.resolve("artifact-recursive-oci-attached.txt");
        Path file3 = blobDir.resolve("artifact-recursive-oci-attached2.txt");

        Files.writeString(file1, "artifact-oci-layout");
        Files.writeString(file2, "linked-file");
        Files.writeString(file3, "linked-file2");

        // Push
        Manifest manifest = registry.pushArtifact(containerRef, LocalPath.of(file1));
        Manifest attached =
                registry.attachArtifact(containerRef, ArtifactType.from("application/foo"), LocalPath.of(file2));
        registry.attachArtifact(
                containerRef.withDigest(attached.getDescriptor().getDigest()),
                ArtifactType.from("application/bar"),
                LocalPath.of(file3));

        // Copy to oci layout
        CopyUtils.copy(registry, containerRef, ociLayout, layoutRef, CopyUtils.CopyOptions.deep());

        assertOciLayout(layoutPath);

        // Assert the empty config
        assertBlobExists(layoutPath, Config.empty().getDigest());
        assertBlobContent(layoutPath, Config.empty().getDigest(), "{}");

        // Check index exists
        assertIndex(layoutPath, manifest, 3, 0);

        // Assert blobs and their content
        assertBlobExists(layoutPath, SupportedAlgorithm.SHA256.digest(file1));
        assertBlobContent(layoutPath, SupportedAlgorithm.SHA256.digest(file1), "artifact-oci-layout");
        assertBlobExists(layoutPath, SupportedAlgorithm.SHA256.digest(file2));
        assertBlobContent(layoutPath, SupportedAlgorithm.SHA256.digest(file2), "linked-file");
        assertBlobExists(layoutPath, SupportedAlgorithm.SHA256.digest(file3));
        assertBlobContent(layoutPath, SupportedAlgorithm.SHA256.digest(file3), "linked-file2");
    }

    @Test
    void testShouldCopyImageIntoOciLayoutWithoutIndexAndTag() {

        Registry registry = Registry.Builder.builder()
                .defaults("myuser", "mypass")
                .withInsecure(true)
                .build();

        OCILayout ociLayout = OCILayout.Builder.builder().defaults(layoutPath).build();
        LayoutRef layoutRef = LayoutRef.parse("%s:the-tag".formatted(ociLayout.getPath()));

        ContainerRef containerRef =
                ContainerRef.parse("%s/library/image-no-index".formatted(this.registry.getRegistry()));

        Layer layer1 = registry.pushBlob(containerRef, Layer.empty().getDataBytes());
        Layer layer2 = registry.pushBlob(containerRef, "foobar".getBytes());

        assertNotNull(layer1.getDigest());
        assertNotNull(layer2.getDigest());

        Manifest emptyManifest = Manifest.empty()
                .withLayers(List.of(Layer.fromDigest(layer1.getDigest(), 2), Layer.fromDigest(layer2.getDigest(), 6)));
        String configDigest = Config.empty().getDigest();

        assertNotNull(configDigest);

        // Push config and manifest
        registry.pushConfig(containerRef.withDigest(configDigest), Config.empty());
        Manifest pushedManifest = registry.pushManifest(containerRef, emptyManifest);

        // Copy to oci layout
        CopyUtils.copy(registry, containerRef, ociLayout, layoutRef, CopyUtils.CopyOptions.deep());

        assertOciLayout(layoutPath);

        // Check index exists
        assertIndex(layoutPath, pushedManifest, 1, 0);

        // Check manifest exists
        assertTrue(Files.exists(layoutPath
                .resolve("blobs")
                .resolve("sha256")
                .resolve(SupportedAlgorithm.getDigest(
                        pushedManifest.getDescriptor().getDigest()))));

        // Ensure manifest serialized correctly (check sha256)
        String computedManifestDigest = SupportedAlgorithm.SHA256.digest(layoutPath
                .resolve("blobs")
                .resolve("sha256")
                .resolve(SupportedAlgorithm.getDigest(
                        pushedManifest.getDescriptor().getDigest())));
        assertEquals(
                SupportedAlgorithm.getDigest(pushedManifest.getDescriptor().getDigest()),
                SupportedAlgorithm.getDigest(computedManifestDigest),
                "Manifest digest should match");

        // Asser layers
        assertLayerExists(layoutPath, layer1);
        assertLayerExists(layoutPath, layer2);

        // Copy to oci layout again
        CopyUtils.copy(registry, containerRef, ociLayout, layoutRef, CopyUtils.CopyOptions.deep());

        // Check manifest exists
        assertBlobExists(layoutPath, pushedManifest.getDescriptor().getDigest());

        // Ensure the manifest on index contains the ref tag
        assertIndex(layoutPath, pushedManifest, 1, 0);

        Index index = Index.fromPath(layoutPath.resolve(Const.OCI_LAYOUT_INDEX));

        // Check latest tag
        assertEquals("the-tag", index.getManifests().get(0).getAnnotations().get(Const.ANNOTATION_REF));
    }

    @Test
    void testShouldCopyImageIntoOciLayoutWithIndex() {

        Path layoutPathIndex = layoutPath.resolve("testShouldCopyImageIntoOciLayoutWithIndex");

        Registry registry = Registry.Builder.builder()
                .defaults("myuser", "mypass")
                .withInsecure(true)
                .build();

        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(layoutPathIndex).build();
        LayoutRef layoutRef = LayoutRef.parse("%s:latest".formatted(ociLayout.getPath()));

        ContainerRef containerRef =
                ContainerRef.parse("%s/library/artifact-image-pull".formatted(this.registry.getRegistry()));

        Layer layer1 = registry.pushBlob(containerRef, Layer.empty().getDataBytes());
        Layer layer2 = registry.pushBlob(containerRef, "foobar".getBytes());

        Manifest emptyManifest = Manifest.empty()
                .withLayers(List.of(Layer.fromDigest(layer1.getDigest(), 2), Layer.fromDigest(layer2.getDigest(), 6)));
        String manifestDigest =
                SupportedAlgorithm.SHA256.digest(emptyManifest.toJson().getBytes(StandardCharsets.UTF_8));
        String configDigest = Config.empty().getDigest();

        // Push config and manifest
        registry.pushConfig(containerRef.withDigest(configDigest), Config.empty());
        Manifest pushedManifest = registry.pushManifest(containerRef.withDigest(manifestDigest), emptyManifest);
        Index index = registry.pushIndex(containerRef, Index.fromManifests(List.of(pushedManifest.getDescriptor())));

        // Copy to oci layout
        CopyUtils.copy(registry, containerRef, ociLayout, layoutRef, CopyUtils.CopyOptions.deep());

        assertOciLayout(layoutPathIndex);

        // Check index and manifest are stored in index
        assertIndex(layoutPathIndex, index, 2);
        assertIndex(layoutPathIndex, pushedManifest, 2, 0);

        // Check manifest exists
        assertBlobExists(layoutPathIndex, pushedManifest.getDescriptor().getDigest());

        // Ensure manifest serialized correctly (check sha256)
        String computedManifestDigest = SupportedAlgorithm.SHA256.digest(layoutPathIndex
                .resolve("blobs")
                .resolve("sha256")
                .resolve(SupportedAlgorithm.getDigest(
                        pushedManifest.getDescriptor().getDigest())));

        assertEquals(
                SupportedAlgorithm.getDigest(pushedManifest.getDescriptor().getDigest()),
                SupportedAlgorithm.getDigest(computedManifestDigest),
                "Manifest digest should match");

        // Assert blobs
        assertLayerExists(layoutPathIndex, layer1);
        assertLayerExists(layoutPathIndex, layer1);
        assertBlobExists(layoutPathIndex, index.getDescriptor().getDigest());
        assertBlobExists(layoutPathIndex, pushedManifest.getDescriptor().getDigest());

        // Copy to oci layout again
        CopyUtils.copy(registry, containerRef, ociLayout, layoutRef, CopyUtils.CopyOptions.deep());

        // Check manifest exists
        assertLayerExists(layoutPathIndex, layer1);
        assertLayerExists(layoutPathIndex, layer1);
        assertBlobExists(layoutPathIndex, index.getDescriptor().getDigest());
        assertBlobExists(layoutPathIndex, pushedManifest.getDescriptor().getDigest());

        // Check latest tag
        Index ociIndex = Index.fromPath(layoutPathIndex.resolve(Const.OCI_LAYOUT_INDEX));
        assertEquals(2, ociIndex.getManifests().size());
        assertEquals("latest", ociIndex.getManifests().get(1).getAnnotations().get(Const.ANNOTATION_REF));
    }

    @Test
    void testShouldCopyIntoOciLayoutWithBlobConfig() throws IOException {
        Registry registry = Registry.Builder.builder()
                .defaults("myuser", "mypass")
                .withInsecure(true)
                .build();

        OCILayout ociLayout = OCILayout.Builder.builder().defaults(layoutPath).build();
        LayoutRef layoutRef = LayoutRef.parse("%s".formatted(ociLayout.getPath()));

        ContainerRef containerRef =
                ContainerRef.parse("%s/library/artifact-oci-layout".formatted(this.registry.getRegistry()));
        Path file1 = blobDir.resolve("artifact-oci-layout.txt");
        Files.writeString(file1, "artifact-oci-layout");

        // Push
        Layer layer = registry.pushBlob(containerRef, "foobartest".getBytes(StandardCharsets.UTF_8));
        Config config = Config.fromBlob("text/plain", layer);
        Manifest manifest = registry.pushArtifact(
                containerRef, ArtifactType.from("my/artifact"), Annotations.empty(), config, LocalPath.of(file1));

        // Copy to oci layout
        CopyUtils.copy(registry, containerRef, ociLayout, layoutRef, CopyUtils.CopyOptions.deep());

        assertOciLayout(layoutPath);

        // Assert the config
        assertLayerExists(layoutPath, layer);
        assertBlobContent(layoutPath, layer.getDigest(), "foobartest");

        // Check index exists
        assertIndex(layoutPath, manifest, 1, 0);
    }

    private void assertOciLayout(Path layoutPath) {
        assertTrue(Files.exists(layoutPath.resolve(Const.OCI_LAYOUT_FILE)));
        OCILayout layoutFile = OCILayout.fromLayoutIndex(layoutPath);
        assertEquals("1.0.0", layoutFile.getImageLayoutVersion());
    }

    private void assertIndex(Path ociLayoutPath, Manifest manifest, int size, int index) {
        assertTrue(Files.exists(ociLayoutPath.resolve(Const.OCI_LAYOUT_INDEX)));
        Index indexObject = Index.fromPath(ociLayoutPath.resolve(Const.OCI_LAYOUT_INDEX));
        LOG.debug("Index is {}", indexObject.toJson());
        assertEquals(2, indexObject.getSchemaVersion());
        assertEquals(size, indexObject.getManifests().size());
        assertEquals(Const.DEFAULT_INDEX_MEDIA_TYPE, indexObject.getMediaType());
        assertNotNull(manifest.getDescriptor(), "Manifest descriptor should not be null");
        assertEquals(
                manifest.getDescriptor().getSize(),
                indexObject.getManifests().get(index).getSize(),
                "Manifest size should match");
    }

    private void assertIndex(Path ociLayoutPath, Index index, int size) {
        assertTrue(Files.exists(ociLayoutPath.resolve(Const.OCI_LAYOUT_INDEX)));
        Index ociIndex = Index.fromPath(ociLayoutPath.resolve(Const.OCI_LAYOUT_INDEX));
        LOG.debug("OCI Index JSON is {}", ociIndex.toJson());
        LOG.debug("Expected Index JSON is {}", index.toJson());
        assertEquals(2, ociIndex.getSchemaVersion());
        assertEquals(size, ociIndex.getManifests().size());
        assertEquals(index.getArtifactType(), ociIndex.getArtifactType());
        assertEquals(index.getArtifactTypeAsString(), ociIndex.getArtifactTypeAsString());
        assertEquals(Const.DEFAULT_INDEX_MEDIA_TYPE, ociIndex.getMediaType());
        assertEquals(
                index.getDescriptor().getSize(),
                ociIndex.getManifests().get(ociIndex.getManifests().size() - 1).getSize());
    }

    private void assertLayerExists(Path ociLayoutPath, Layer layer) {
        if (layer.getData() == null) {
            assertTrue(
                    Files.exists(ociLayoutPath
                            .resolve("blobs")
                            .resolve("sha256")
                            .resolve(SupportedAlgorithm.getDigest(layer.getDigest()))),
                    "Expect layer to exist");
        }
    }

    private void assertBlobExists(Path ociLayoutPath, String digest) {
        assertTrue(
                Files.exists(ociLayoutPath
                        .resolve("blobs")
                        .resolve(SupportedAlgorithm.fromDigest(digest).getPrefix())
                        .resolve(SupportedAlgorithm.getDigest(digest))),
                "Expect blob to exist");
    }

    private void assertBlobAbsent(Path ociLayoutPath, String digest) {
        assertFalse(
                Files.exists(ociLayoutPath
                        .resolve("blobs")
                        .resolve(SupportedAlgorithm.fromDigest(digest).getPrefix())
                        .resolve(SupportedAlgorithm.getDigest(digest))),
                "Expect blob to be absent");
    }

    private void assertBlobContent(Path ociLayoutPath, String digest, String content) throws IOException {
        assertEquals(
                content,
                Files.readString(ociLayoutPath
                        .resolve("blobs")
                        .resolve(SupportedAlgorithm.fromDigest(digest).getPrefix())
                        .resolve(SupportedAlgorithm.getDigest(digest))),
                "Expect blob content to match");
    }

    @Test
    void pullArtifactShouldRejectInvalidTitleAnnotation() throws IOException {

        // Create a valid OCI layout via the normal push API
        Path ociLayoutPath = layoutPath.resolve("traversal-test");
        Path artifactFile = blobDir.resolve("safe.txt");
        Files.writeString(artifactFile, "safe content");

        LayoutRef layoutRef = LayoutRef.parse("%s:latest".formatted(ociLayoutPath.toString()));
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(ociLayoutPath).build();
        ociLayout.pushArtifact(
                layoutRef, ArtifactType.from("foo/bar"), Annotations.empty(), LocalPath.of(artifactFile, "text/plain"));

        // 2. Read the manifest stored on disk and replace the title annotation with a traversal path
        Index index = Index.fromPath(ociLayoutPath.resolve(Const.OCI_LAYOUT_INDEX));
        String originalManifestDigest = index.getManifests().get(0).getDigest(); // e.g. sha256:abc...
        Path manifestBlobPath = ociLayoutPath
                .resolve("blobs")
                .resolve("sha256")
                .resolve(SupportedAlgorithm.getDigest(originalManifestDigest));

        String originalManifestJson = Files.readString(manifestBlobPath);

        // Invalid path
        String tamperedManifestJson = originalManifestJson.replace("\"safe.txt\"", "\"../traversed-file.txt\"");

        // Write tampered manifest as a new blob and update index.json
        byte[] tamperedBytes = tamperedManifestJson.getBytes(StandardCharsets.UTF_8);
        String tamperedDigest = SupportedAlgorithm.SHA256.digest(tamperedBytes);
        Path tamperedBlobPath =
                ociLayoutPath.resolve("blobs").resolve("sha256").resolve(SupportedAlgorithm.getDigest(tamperedDigest));
        Files.write(tamperedBlobPath, tamperedBytes);

        // Rewrite index.json to reference the tampered manifest digest
        String updatedIndexJson = Files.readString(ociLayoutPath.resolve(Const.OCI_LAYOUT_INDEX))
                .replace(
                        SupportedAlgorithm.getDigest(originalManifestDigest),
                        SupportedAlgorithm.getDigest(tamperedDigest));
        Files.writeString(ociLayoutPath.resolve(Const.OCI_LAYOUT_INDEX), updatedIndexJson);

        // Attempt to pull — must be rejected because the title escapes the output directory
        Path outputDir = extractDir.resolve("traversal-output");
        Files.createDirectories(outputDir);

        OCILayout tampered = OCILayout.Builder.builder().defaults(ociLayoutPath).build();
        OrasException exception = assertThrows(
                OrasException.class,
                () -> tampered.pullArtifact(layoutRef, outputDir, true),
                "Expected OrasException for title annotation");
        assertTrue(
                exception.getMessage().contains("is not withing folder"),
                "Exception message should mention is not withing folder but was: " + exception.getMessage());

        // 5. The file must NOT have been written outside the output directory
        assertFalse(
                Files.exists(outputDir.getParent().resolve("traversed-file.txt")),
                "Blob must not be written outside the output directory");
    }

    @Test
    void shouldCreateNewTarBackedLayout() {
        // Arrange: a path ending in .tar that does not yet exist
        Path tarFile = layoutPath.resolve("new-layout.tar");
        assertFalse(Files.exists(tarFile), "Tar file should not exist before build()");

        // Act
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(tarFile).build();

        // Assert: tar file was created on disk
        assertTrue(Files.exists(tarFile), "Tar file must be created by build()");
        assertEquals(tarFile, ociLayout.getTarPath());

        // The working directory should contain the minimal OCI layout structure
        Path workDir = ociLayout.getPath();
        assertTrue(Files.exists(workDir.resolve(Const.OCI_LAYOUT_INDEX)));
        assertTrue(Files.exists(workDir.resolve(Const.OCI_LAYOUT_FILE)));
        assertTrue(Files.isDirectory(workDir.resolve(Const.OCI_LAYOUT_BLOBS)));
    }

    @Test
    void shouldPushManifestToTarBackedLayout() {
        // Arrange
        Path tarFile = layoutPath.resolve("push-manifest.tar");
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(tarFile).build();
        LayoutRef ref = LayoutRef.parse(tarFile.toString());

        // Act
        Manifest manifest = Manifest.empty().withConfig(Config.empty());
        manifest = ociLayout.pushManifest(ref, manifest);

        // Assert: tar file is updated
        assertTrue(Files.exists(tarFile), "Tar must be re-packed after pushManifest");

        // Open from the tar again and verify the manifest is present
        Path reopenedWorkDir = ociLayout.getPath();
        Index index = Index.fromPath(reopenedWorkDir.resolve(Const.OCI_LAYOUT_INDEX));
        assertEquals(1, index.getManifests().size());
        assertNotNull(manifest.getDescriptor());
    }

    @Test
    void shouldPushAndPullArtifactViaTagInTarBackedLayout() throws IOException {
        // Arrange
        Path tarFile = layoutPath.resolve("push-pull.tar");
        Path artifactFile = blobDir.resolve("hello-tar.txt");
        Files.writeString(artifactFile, "hello from tar");

        LayoutRef ref = LayoutRef.parse("%s:latest".formatted(tarFile.toString()));
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(tarFile).build();

        // Act: push
        ociLayout.pushArtifact(
                ref, ArtifactType.from("foo/bar"), Annotations.empty(), LocalPath.of(artifactFile, "text/plain"));

        // Assert tar was updated
        assertTrue(Files.exists(tarFile));

        // Re-open the layout from the same tar (simulate a second process)
        OCILayout reopened = OCILayout.Builder.builder().defaults(tarFile).build();
        LayoutRef reopenedRef = LayoutRef.parse("%s:latest".formatted(tarFile.toString()));

        // Pull the artifact
        Path pullDir = extractDir.resolve("tar-pull-out");
        Files.createDirectories(pullDir);
        reopened.pullArtifact(reopenedRef, pullDir, false);

        // Verify the file was extracted correctly
        Path extracted = pullDir.resolve("hello-tar.txt");
        assertTrue(Files.exists(extracted), "Extracted file must exist");
        assertEquals("hello from tar", Files.readString(extracted));
    }

    @Test
    void shouldListTagsFromTarBackedLayout() throws IOException {
        // Open the pre-built artifact.tar fixture
        Path tarFile = Path.of("src/test/resources/oci/artifact.tar");
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(tarFile).build();
        LayoutRef ref = LayoutRef.parse("%s:latest".formatted(tarFile.toString()));

        Tags tags = ociLayout.getTags(ref);
        assertEquals(1, tags.tags().size());
        assertEquals("latest", tags.tags().get(0));
    }

    @Test
    void shouldGetReferrersFromTarBackedLayout() throws IOException {
        // Open the pre-built subject.tar fixture (has one referrer)
        Path tarFile = Path.of("src/test/resources/oci/subject.tar");
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(tarFile).build();
        LayoutRef ref = LayoutRef.parse("%s:latest".formatted(tarFile.toString()));

        Referrers referrers = ociLayout.getReferrers(ref, null);
        assertEquals(1, referrers.getManifests().size());
        assertEquals(
                "sha256:ccec2a2be7ce7c6aadc8ed0dc03df8f91cbd3534272dd1f8284226a8d3516dd6",
                referrers.getManifests().get(0).getDigest());
    }

    @Test
    void shouldPullArtifactFromTarFixture() throws IOException {
        // Open the pre-built artifact.tar fixture
        Path tarFile = Path.of("src/test/resources/oci/artifact.tar");
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(tarFile).build();
        LayoutRef ref = LayoutRef.parse("%s:latest".formatted(tarFile.toString()));

        Path pullDir = extractDir.resolve("tar-fixture-pull");
        Files.createDirectories(pullDir);
        ociLayout.pullArtifact(ref, pullDir, false);

        assertTrue(Files.exists(pullDir.resolve("hi.txt")));
        assertEquals("hi\n", Files.readString(pullDir.resolve("hi.txt")));
    }

    @Test
    void shouldReopenExistingTarAndPushAdditionalManifest() throws IOException {
        // First session: create a tar-backed layout and push one manifest
        Path tarFile = layoutPath.resolve("reopen-test.tar");
        LayoutRef ref1 = LayoutRef.parse("%s:v1".formatted(tarFile.toString()));
        OCILayout session1 = OCILayout.Builder.builder().defaults(tarFile).build();
        session1.pushManifest(ref1, Manifest.empty().withConfig(Config.empty()));

        // Second session: reopen the same tar and push another manifest
        LayoutRef ref2 = LayoutRef.parse("%s:v2".formatted(tarFile.toString()));
        OCILayout session2 = OCILayout.Builder.builder().defaults(tarFile).build();
        Manifest m2 = Manifest.empty().withConfig(Config.empty()).withAnnotations(Map.of("version", "2"));
        session2.pushManifest(ref2, m2);

        // Third session: verify both tags are present
        OCILayout session3 = OCILayout.Builder.builder().defaults(tarFile).build();
        LayoutRef refAny = LayoutRef.parse(tarFile.toString());
        Tags tags = session3.getTags(refAny);
        assertEquals(2, tags.tags().size(), "Both v1 and v2 tags must be present after reopening");
        assertTrue(tags.tags().contains("v1"));
        assertTrue(tags.tags().contains("v2"));
    }

    @Test
    void shouldReportTarFileNameAsRepository() throws IOException {
        Path tarFile = layoutPath.resolve("my-layout.tar");
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(tarFile).build();
        Repositories repos = ociLayout.getRepositories();
        assertEquals(1, repos.repositories().size());
        assertEquals("my-layout.tar", repos.repositories().get(0));
    }

    @Test
    void testShouldCopyArtifactFromRegistryIntoTarBackedOciLayout() throws IOException {

        Registry registry = Registry.Builder.builder()
                .defaults("myuser", "mypass")
                .withInsecure(true)
                .build();

        Path tarFile = layoutPath.resolve("copy-shallow.tar");
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(tarFile).build();
        LayoutRef layoutRef = LayoutRef.of(ociLayout);

        ContainerRef containerRef =
                ContainerRef.parse("%s/library/artifact-oci-layout-tar".formatted(this.registry.getRegistry()));
        Path file1 = blobDir.resolve("artifact-oci-layout-tar.txt");
        Files.writeString(file1, "artifact-oci-layout-tar");

        // Push to registry
        Manifest manifest = registry.pushArtifact(containerRef, LocalPath.of(file1));

        // Shallow copy to tar-backed OCI layout
        CopyUtils.copy(registry, containerRef, ociLayout, layoutRef, CopyUtils.CopyOptions.shallow());

        // The tar file must exist and contain a valid layout
        assertTrue(Files.exists(tarFile), "Tar file must exist after copy");

        // Re-open from the tar to verify contents are persisted correctly
        OCILayout reopened = OCILayout.Builder.builder().defaults(tarFile).build();
        Path workDir = reopened.getPath();

        assertOciLayout(workDir);
        assertIndex(workDir, manifest, 1, 0);
        assertBlobContent(workDir, Config.empty().getDigest(), "{}");
        assertBlobExists(workDir, SupportedAlgorithm.SHA256.digest(file1));
        assertBlobContent(workDir, SupportedAlgorithm.SHA256.digest(file1), "artifact-oci-layout-tar");
    }

    @Test
    void testShouldCopyArtifactRecursivelyFromRegistryIntoTarBackedOciLayout() throws IOException {

        Registry registry = Registry.Builder.builder()
                .defaults("myuser", "mypass")
                .withInsecure(true)
                .build();

        Path tarFile = layoutPath.resolve("copy-deep.tar");
        OCILayout ociLayout = OCILayout.Builder.builder().defaults(tarFile).build();
        LayoutRef layoutRef = LayoutRef.parse("%s".formatted(ociLayout.getPath()));

        ContainerRef containerRef = ContainerRef.parse(
                "%s/library/artifact-recursive-oci-layout-tar".formatted(this.registry.getRegistry()));
        Path file1 = blobDir.resolve("artifact-recursive-oci-layout-tar.txt");
        Path file2 = blobDir.resolve("artifact-recursive-oci-attached-tar.txt");
        Path file3 = blobDir.resolve("artifact-recursive-oci-attached2-tar.txt");
        Files.writeString(file1, "artifact-oci-layout-tar");
        Files.writeString(file2, "linked-file-tar");
        Files.writeString(file3, "linked-file2-tar");

        // Push to registry with referrer chain
        Manifest manifest = registry.pushArtifact(containerRef, LocalPath.of(file1));
        Manifest attached =
                registry.attachArtifact(containerRef, ArtifactType.from("application/foo"), LocalPath.of(file2));
        registry.attachArtifact(
                containerRef.withDigest(attached.getDescriptor().getDigest()),
                ArtifactType.from("application/bar"),
                LocalPath.of(file3));

        // Deep copy to tar-backed OCI layout
        CopyUtils.copy(registry, containerRef, ociLayout, layoutRef, CopyUtils.CopyOptions.deep());

        // The tar file must exist
        assertTrue(Files.exists(tarFile), "Tar file must exist after copy");

        // Re-open from the tar to verify the full referrer chain is present
        OCILayout reopened = OCILayout.Builder.builder().defaults(tarFile).build();
        Path workDir = reopened.getPath();

        assertOciLayout(workDir);
        assertIndex(workDir, manifest, 3, 0);
        assertBlobContent(workDir, Config.empty().getDigest(), "{}");
        assertBlobExists(workDir, SupportedAlgorithm.SHA256.digest(file1));
        assertBlobContent(workDir, SupportedAlgorithm.SHA256.digest(file1), "artifact-oci-layout-tar");
        assertBlobExists(workDir, SupportedAlgorithm.SHA256.digest(file2));
        assertBlobContent(workDir, SupportedAlgorithm.SHA256.digest(file2), "linked-file-tar");
        assertBlobExists(workDir, SupportedAlgorithm.SHA256.digest(file3));
        assertBlobContent(workDir, SupportedAlgorithm.SHA256.digest(file3), "linked-file2-tar");
    }

    @Test
    void shouldGarbageCollectReturnEmptyWhenNoBlobsAreOrphaned() throws IOException {
        Path ociLayoutPath = layoutPath.resolve("gc-no-orphan");
        Path artifactFile = blobDir.resolve("gc-no-orphan.txt");
        Files.writeString(artifactFile, "no-orphan");

        LayoutRef layoutRef = LayoutRef.parse("%s:latest".formatted(ociLayoutPath.toString()));
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(ociLayoutPath).build();
        ociLayout.pushArtifact(
                layoutRef, ArtifactType.from("foo/bar"), Annotations.empty(), LocalPath.of(artifactFile, "text/plain"));

        List<String> removed = ociLayout.garbageCollect();

        // No orphaned blobs — nothing should be removed
        assertTrue(removed.isEmpty(), "Expected no blobs to be garbage collected");

        // Original blobs still present
        assertBlobExists(ociLayoutPath, Config.empty().getDigest());
        assertBlobExists(ociLayoutPath, SupportedAlgorithm.SHA256.digest(artifactFile));
    }

    @Test
    void shouldGarbageCollectRemoveOrphanedBlob() throws IOException {
        Path ociLayoutPath = layoutPath.resolve("gc-orphan");
        Path artifactFile = blobDir.resolve("gc-orphan.txt");
        Files.writeString(artifactFile, "referenced");
        Path orphanFile = blobDir.resolve("gc-orphan-extra.txt");
        Files.writeString(orphanFile, "orphaned-blob-content");

        LayoutRef layoutRef = LayoutRef.parse("%s:latest".formatted(ociLayoutPath.toString()));
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(ociLayoutPath).build();
        ociLayout.pushArtifact(
                layoutRef, ArtifactType.from("foo/bar"), Annotations.empty(), LocalPath.of(artifactFile, "text/plain"));

        // Inject an orphaned blob directly into the blobs/sha256/ directory
        String orphanDigest = SupportedAlgorithm.SHA256.digest(orphanFile);
        Path orphanBlobPath = ociLayoutPath
                .resolve(Const.OCI_LAYOUT_BLOBS)
                .resolve("sha256")
                .resolve(SupportedAlgorithm.getDigest(orphanDigest));
        Files.copy(orphanFile, orphanBlobPath);
        assertBlobExists(ociLayoutPath, orphanDigest);

        List<String> removed = ociLayout.garbageCollect();

        // Exactly the orphaned blob should be removed
        assertEquals(1, removed.size(), "Expected exactly one blob to be garbage collected");
        assertEquals(orphanDigest, removed.get(0));

        // The orphaned blob must no longer exist
        assertBlobAbsent(ociLayoutPath, orphanDigest);

        // Referenced blobs must still be present
        assertBlobExists(ociLayoutPath, Config.empty().getDigest());
        assertBlobExists(ociLayoutPath, SupportedAlgorithm.SHA256.digest(artifactFile));
    }

    @Test
    void shouldGarbageCollectMultipleOrphanedBlobs() throws IOException {
        Path ociLayoutPath = layoutPath.resolve("gc-multi-orphan");
        Path artifactFile = blobDir.resolve("gc-multi-orphan.txt");
        Files.writeString(artifactFile, "referenced-multi");

        LayoutRef layoutRef = LayoutRef.parse("%s:latest".formatted(ociLayoutPath.toString()));
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(ociLayoutPath).build();
        ociLayout.pushArtifact(
                layoutRef, ArtifactType.from("foo/bar"), Annotations.empty(), LocalPath.of(artifactFile, "text/plain"));

        // Inject two orphaned blobs
        Path orphan1 = blobDir.resolve("gc-orphan1.txt");
        Path orphan2 = blobDir.resolve("gc-orphan2.txt");
        Files.writeString(orphan1, "orphan-one");
        Files.writeString(orphan2, "orphan-two");

        String orphanDigest1 = SupportedAlgorithm.SHA256.digest(orphan1);
        String orphanDigest2 = SupportedAlgorithm.SHA256.digest(orphan2);

        Path algoDir = ociLayoutPath.resolve(Const.OCI_LAYOUT_BLOBS).resolve("sha256");
        Files.copy(orphan1, algoDir.resolve(SupportedAlgorithm.getDigest(orphanDigest1)));
        Files.copy(orphan2, algoDir.resolve(SupportedAlgorithm.getDigest(orphanDigest2)));

        List<String> removed = ociLayout.garbageCollect();

        assertEquals(2, removed.size(), "Expected two blobs to be garbage collected");
        assertTrue(removed.contains(orphanDigest1), "orphanDigest1 should be in removed list");
        assertTrue(removed.contains(orphanDigest2), "orphanDigest2 should be in removed list");

        assertBlobAbsent(ociLayoutPath, orphanDigest1);
        assertBlobAbsent(ociLayoutPath, orphanDigest2);

        // Referenced blobs must still be present
        assertBlobExists(ociLayoutPath, Config.empty().getDigest());
        assertBlobExists(ociLayoutPath, SupportedAlgorithm.SHA256.digest(artifactFile));
    }

    @Test
    void shouldGarbageCollectKeepAllBlobsAfterMultipleManifests() throws IOException {
        Path ociLayoutPath = layoutPath.resolve("gc-multi-manifest");
        Path file1 = blobDir.resolve("gc-multi-manifest-1.txt");
        Path file2 = blobDir.resolve("gc-multi-manifest-2.txt");
        Files.writeString(file1, "first-artifact");
        Files.writeString(file2, "second-artifact");

        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(ociLayoutPath).build();

        LayoutRef ref1 = LayoutRef.parse("%s:v1".formatted(ociLayoutPath.toString()));
        LayoutRef ref2 = LayoutRef.parse("%s:v2".formatted(ociLayoutPath.toString()));

        ociLayout.pushArtifact(ref1, ArtifactType.from("foo/bar"), Annotations.empty(), LocalPath.of(file1));
        ociLayout.pushArtifact(ref2, ArtifactType.from("foo/bar"), Annotations.empty(), LocalPath.of(file2));

        List<String> removed = ociLayout.garbageCollect();

        // Nothing should be removed — both artifacts are fully referenced
        assertTrue(removed.isEmpty(), "Expected no blobs to be garbage collected with two valid manifests");

        assertBlobExists(ociLayoutPath, SupportedAlgorithm.SHA256.digest(file1));
        assertBlobExists(ociLayoutPath, SupportedAlgorithm.SHA256.digest(file2));
    }

    @Test
    void shouldGarbageCollectKeepReferrerBlobsWhenCopiedDeep() throws IOException {
        Path ociLayoutPath = layoutPath.resolve("gc-referrer");
        Path mainFile = blobDir.resolve("gc-referrer-main.txt");
        Path attachFile = blobDir.resolve("gc-referrer-attach.txt");
        Files.writeString(mainFile, "main-artifact");
        Files.writeString(attachFile, "attached-artifact");

        LayoutRef layoutRef = LayoutRef.parse("%s:latest".formatted(ociLayoutPath.toString()));
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(ociLayoutPath).build();

        // Push main artifact
        ociLayout.pushArtifact(
                layoutRef, ArtifactType.from("foo/bar"), Annotations.empty(), LocalPath.of(mainFile, "text/plain"));

        // Attach a referrer to the main artifact
        ociLayout.attachArtifact(
                layoutRef,
                ArtifactType.from("application/referrer"),
                Annotations.empty(),
                LocalPath.of(attachFile, "text/plain"));

        // No orphans — both main and referrer blobs are valid
        List<String> removed = ociLayout.garbageCollect();

        assertTrue(removed.isEmpty(), "Expected no blobs to be removed when referrers are properly referenced");

        assertBlobExists(ociLayoutPath, SupportedAlgorithm.SHA256.digest(mainFile));
        assertBlobExists(ociLayoutPath, SupportedAlgorithm.SHA256.digest(attachFile));
    }

    @Test
    void shouldGarbageCollectOnEmptyLayout() {
        Path ociLayoutPath = layoutPath.resolve("gc-empty");
        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(ociLayoutPath).build();

        // An empty layout has no blobs at all — GC must return empty list without error
        List<String> removed = ociLayout.garbageCollect();

        assertTrue(removed.isEmpty(), "Expected no blobs to be removed from an empty layout");
    }

    @Test
    void shouldGarbageCollectWithNestedIndex() throws IOException {

        // Build a layout
        Path ociLayoutPath = layoutPath.resolve("gc-nested-index");
        Path file1 = blobDir.resolve("gc-nested-index-1.txt");
        Path file2 = blobDir.resolve("gc-nested-index-2.txt");
        Path orphanFile = blobDir.resolve("gc-nested-index-orphan.txt");
        Files.writeString(file1, "nested-index-artifact-one");
        Files.writeString(file2, "nested-index-artifact-two");
        Files.writeString(orphanFile, "nested-index-orphan-content");

        OCILayout ociLayout =
                OCILayout.Builder.builder().defaults(ociLayoutPath).build();

        // Push two independent manifests (without a top-level tag so they get digest-only entries)
        LayoutRef ref1 = LayoutRef.parse("%s".formatted(ociLayoutPath.toString()));
        LayoutRef ref2 = LayoutRef.parse("%s".formatted(ociLayoutPath.toString()));
        Manifest manifest1 = ociLayout.pushArtifact(
                ref1, ArtifactType.from("foo/bar"), Annotations.empty(), LocalPath.of(file1, "text/plain"));
        Manifest manifest2 = ociLayout.pushArtifact(
                ref2, ArtifactType.from("foo/bar"), Annotations.empty(), LocalPath.of(file2, "text/plain"));

        // Group the two manifests into a nested index and push it.
        assertNotNull(manifest1.getDescriptor(), "Manifest 1 descriptor should not be null");
        assertNotNull(manifest2.getDescriptor(), "Manifest 2 descriptor should not be null");
        Index nestedIndex = Index.fromManifests(List.of(manifest1.getDescriptor(), manifest2.getDescriptor()));
        LayoutRef indexRef = LayoutRef.parse("%s:multi".formatted(ociLayoutPath.toString()));
        Index pushedIndex = ociLayout.pushIndex(indexRef, nestedIndex);

        // Collect the digests that must survive GC
        assertNotNull(pushedIndex.getDescriptor(), "Pushed index descriptor should not be null");
        String nestedIndexDigest = pushedIndex.getDescriptor().getDigest();
        String manifest1Digest = manifest1.getDescriptor().getDigest();
        String manifest2Digest = manifest2.getDescriptor().getDigest();
        String layer1Digest = SupportedAlgorithm.SHA256.digest(file1);
        String layer2Digest = SupportedAlgorithm.SHA256.digest(file2);
        String configDigest = Config.empty().getDigest();

        // Inject an orphaned blob directly on disk
        Layer orphanedLayer =
                ociLayout.pushBlob(indexRef.withDigest(SupportedAlgorithm.SHA256.digest(orphanFile)), orphanFile);
        String orphanDigest = orphanedLayer.getDigest();
        assertBlobExists(ociLayoutPath, orphanDigest);

        // Run GC
        List<String> removed = ociLayout.garbageCollect();

        // Only the orphan must have been removed
        assertEquals(1, removed.size(), "Expected exactly one blob to be garbage collected");
        assertEquals(orphanDigest, removed.get(0));
        assertBlobAbsent(ociLayoutPath, orphanDigest);

        // The nested index blob itself must be kept (it is referenced from root index.json)
        assertBlobExists(ociLayoutPath, nestedIndexDigest);

        // Both manifests reachable via the nested index must be kept
        assertBlobExists(ociLayoutPath, manifest1Digest);
        assertBlobExists(ociLayoutPath, manifest2Digest);

        // All layer blobs reached by recursing into the nested index must be kept
        assertBlobExists(ociLayoutPath, layer1Digest);
        assertBlobExists(ociLayoutPath, layer2Digest);

        // Shared config blob must be kept
        assertBlobExists(ociLayoutPath, configDigest);
    }
}
