# Security model

Read this before touching reference resolution, mirrors, `registries.conf`, `policy.json` or credential handling.

## Resolve, then check, then connect

Security checks always run on the resolved reference, never on the one the caller passed. The order is fixed:

1. Resolve: short-name / unqualified-search expansion (`nginx` → `docker.io/library/nginx`), `prefix` → `location` rewrites, mirror selection. Code: `RegistriesConf.rewrite`, `RegistriesConf.rewriteForMirror`, `ContainerRef.getEffectiveRegistry`.
2. Check: `ContainerRef.checkBlocked`, `ContainerRef.isInsecure`, and `Registry.verifyContainersPolicy`, all on the resolved reference.
3. Connect.

Don't move a check before step 1. If checks ran on the original name, a mirror or alias could route traffic to a blocked or plain-HTTP host that was only approved under its original name.

## Mirrors

Mirror fallback goes through `Registry.withMirrorFallback`, and each mirror gets its own `Registry` from `Registry.copyForNewTransport`.

- No silent HTTP downgrade. Mirror registries are built with `transportLocked = true`. When it is set, `ContainerRef.isInsecure` returns the registry's own transport and skips `registries.conf`, so a registry-level `insecure = true` entry for the mirror host can't downgrade a mirror configured as secure.
- Credentials are re-scoped to the mirror. Static providers (`UsernamePasswordProvider`, `BearerTokenProvider`) ignore the target host, so they are never forwarded to a different host. An insecure mirror gets `NoAuthProvider`, unless the mirror is the same host or the provider is a host-scoped `AuthStoreAuthenticationProvider`. In those two cases the provider is kept, because those checks run last.
- Don't add a global "no credentials over HTTP" rule in `HttpClient`. Basic auth over plain HTTP is a supported setup, and the main test registry (`ZotContainer`) uses it. The protection belongs in the mirror path.

Regression tests: `RegistryTlsTest#shouldNotDowngradeSecureMirrorWhenRegistryLevelInsecureSetForMirrorHost` and `RegistryWireMockTest#shouldNotForwardParentCredentialsToInsecureMirror`.

## Known limitations

These are intentional. Don't change them without a design discussion.

- Policy is repository-scoped. `ContainerRef` strips `:tag` and `@digest` before matching, as the `policy.json` format requires. A rule can't target one tag or digest.
- Policy is a pull-time gate. `getManifest` calls `verifyContainersPolicy`. `deleteManifest` only calls `checkBlocked`, so deletes aren't content-verified.
- Configuration is trusted. `registries.conf` and `policy.json` belong to the operator. An attacker who can edit them is outside the threat model.
- `sigstoreSigned` supports one key (`keyPath` or `keyData`). Multiple keys, keyless verification and `signedIdentity` are not supported.
