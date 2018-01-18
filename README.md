# tick-my-feedstocks

This is a program designed to help keep any [conda-forge](https://conda-forge.github.io/) feedstocks that you administer up to do date. It's _not_ a polished, up-to-date package. It's a supplement to help folks eyeball their packages more easily, not a replacement for checking all of your packages.

## Usage

```
python tick_my_feedstocks.py [-h]
                             [--password <GH_PASSWORD>] [--user <GH_USER>]
                             [--no-regenerate] [--no-rerender] [--dry-run]
                             [--targetfile <TARGETFILE>]
                             [--target-feedstocks <TARGET_FEEDSTOCKS_1> [<TARGET_FEEDSTOCKS_2> …]]
                             [--limit-feedstocks <LIMIT_FEEDSTOCKS>]
                             [--limit-outdated <LIMIT_OUTDATED>]
                             [--skipfile <SKIPFILE>]
                             [--skip-feedstocks <SKIP_FEEDSTOCKS_1> [<SKIP_FEEDSTOCKS_2> …]]
```

or

```
conda execute tick_my_feedstocks.py [-h]
                                    [--password <GH_PASSWORD>] [--user <GH_USER>]
                                    [--no-regenerate] [--no-rerender] [--dry-run]
                                    [--targetfile <TARGETFILE>]
                                    [--target-feedstocks <TARGET_FEEDSTOCKS_1> [<TARGET_FEEDSTOCKS_2> …]]
                                    [--limit-feedstocks <LIMIT_FEEDSTOCKS>]
                                    [--limit-outdated <LIMIT_OUTDATED>]
                                    [--skipfile <SKIPFILE>]
                                    [--skip-feedstocks <SKIP_FEEDSTOCKS_1> [<SKIP_FEEDSTOCKS_2> …]]
```

If you use [`conda execute`](https://github.com/pelson/conda-execute) to run the script,`conda` will:

- Use the comment block at the start of the script to define a list of dependencies
- Set up a temporary environment based on those dependencies
- Run the script in the environment
- Destroy the environment

## What the script does:

1. Identify all of the feedstocks maintained by the user
2. Attempt to determine _F_, the subset of feedstocks that need updating
3. Attempt to determine <em>F<sub>i</sub></em>, the subset of _F_ that has no dependencies on other members of _F_.
4. Attempts to patch each feedstock in <em>F<sub>i</sub></em> by:
    1. Creating a new commit containing:
        1. A modified `meta.yaml` with the new version number
        2. A modified `meta.yaml` with the `sha256` checksum for the new version.
        3. A modified `meta.yaml` with the build number reset to `0`.
    2. Creating a fork of the feedstock for the authorized user.
    3. Applying the new commit to the forked feedstock.

5. Regenerating all of the forked feedstocks using the installed version of [conda-smithy](https://github.com/conda-forge/conda-smithy).

6. Submitting pull requests for all of the successfully forked feedstocks.

## Caveats

### Updates are sourced from PyPI.

All version information comes from PyPI right now. If the feedstock isn't based in PyPI, this can't help you.

### Double-check the dependencies!

`tick-my-feedstocks` doesn't do anything to verify whether or not runtime dependencies have changed. Further, since conda-forge tests are very lightweights, you should make sure that run dependencies haven't changed.

## OAuth Token permissions

If you want to use an OAuthToken instead of your GitHub password, you should make sure that the token has these permissions:

- `public_repo`
- `read:org`
- `delete_repo` (This is unnecessary if you have no out-of-date forks of your feedstocks)
