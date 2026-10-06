# Contributing

Read [the developer and agent guide](docs/AGENT_GUIDE.md) before proposing new-build support. Describe the component version, architecture, sample hash, symbol identity, structural evidence, and validation level. Do not submit Microsoft system binaries, personal logs, or machine-specific paths.

## Verification

- Build with `build.cmd`; output belongs in `bin/`.
- Build test executables with `tests/build.cmd`.
- Run engine tests against known original samples when available; report missing samples explicitly.
- Compare independent Python and production C# analysis for new builds.
- Keep input samples unchanged. Create optional patched copies only in analysis directories.
- Documentation and packaging changes do not require reinstalling the system patch.
- Preserve the Chinese end-user UI; use English for developer documentation and comments.

## Before publishing

1. Review compatibility claims and identify static-only validation.
2. Exclude application binaries, incidental build outputs, symbols, samples, reports, logs, and backups from the developer archive. Include the two intended diagnostic executables in tests/prebuilt/.
3. Build the released executable from the released source. Package it separately with user instructions.
4. Record archive and executable SHA-256 values outside the archives.
5. Choose a project license before presenting the repository as licensed open-source software. This prepared tree does not select a license on the owner's behalf.
6. Publish only when the owner instructs you to do so; preparing an archive does not publish it.
