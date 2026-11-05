# Changesets

This folder is managed by [changesets](https://github.com/changesets/changesets).

Every pull request that changes published behaviour must include a changeset:

```bash
npx changeset
```

Pick the bump type (`patch`, `minor`, `major`) and describe the change for the
changelog. The release workflow opens a "Version Packages" pull request that
applies pending changesets to `package.json` and `CHANGELOG.md`; merging that
pull request publishes to npm.
