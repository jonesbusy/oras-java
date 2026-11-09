# Contributing

Please refer to the [ORAS Contributing guide](https://oras.land/docs/community/contributing_guide) for general aspects.

## Java SDK

This section is specific to the Java SDK.

### Requirements

- Java 17 or later
- Maven 3.9.9 or later
- Container engine like Docker or Podman (due to testcontainers)
- Pre-commit `3.6.2` or later

If using `sdkman` you can install the required versions with:

```bash
sdk env
```

Some tests require the `docker-credential-secretservice` to be installed to run tests

```
brew install docker-credential-helper
```

### Before opening a PR

- All commits are signed off with `git commit -s`
- All commits have a verified signature `git verify-commit HEAD`
- Your branch is rebased on the main branch and have a linear history use multiple remotes or `gh repo sync` to keep your fork in sync
- Ensure new files have a license `mvn license:update-file-header` and are formatted with `mvn spotless:apply` of not the build with fail
- Run `pre-commit run -a` or ensure the pre-commit hooks are installed with `pre-commit install-hooks`
- Run the tests with `mvn clean install`
- Javadoc is well formatted for public methods. If not the build will fail
- Coverage on new code is at least `80%`. You can check jacoco reports in `target/site/jacoco/index.html`
- Pull request template is filled with the correct information (Specially the testing done section)

### Snapshots and releases

SNAPSHOTs are deployed automatically on every push to `main` (see [deploy-snapshots.yml](.github/workflows/deploy-snapshots.yml)).

To release:

- Check that the draft release version matches the version in `pom.xml`, especially when bumping the major or minor version. Patch versions are updated automatically.
- Run the [release workflow](.github/workflows/release.yml).
