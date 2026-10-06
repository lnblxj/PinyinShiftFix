# Agent entry point

Read README.md and docs/AGENT_GUIDE.md before changing patch logic. Use CONTRIBUTING.md for scope and release requirements.

Keep developer documentation and code comments in English. The application's existing Simplified Chinese UI may remain Chinese.

Keep samples, symbols, reports, backups, and incidental build outputs outside tracked source. The two intentional test executables in tests/prebuilt/ belong to the developer package; rebuild them after changing their sources. Do not weaken file identity, symbol identity, PE bounds, command, relocation, backup, or restore checks to make a new build pass. Static analysis is not runtime validation.

Do not modify system files or run input-injection tests unless the user has authorized those operations. Editing or building source alone is not authorization to install a patch.
