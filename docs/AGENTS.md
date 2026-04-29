# Agent Conventions

This document contains conventions for AI agents working on this repository.

## Changelog

Always update `CHANGELOG.md` to reflect changes. This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

- Add new entries to the top of the `## [Unreleased]` section.
- Use categories: `### Added`, `### Changed`, `### Fixed`, `### Deprecated`, `### Removed`, `### Security`.
- Never modify existing release sections.
- Be specific: reference methods, files, or issues where relevant.

## Safety

**Never use destructive git commands in scripts or automation.**

Forbidden without explicit user interaction:
- `git reset --hard`
- `git push --force`
- `git clean -fd`

If an operation might lose work, display a clear error and manual recovery steps instead. Let the user decide how to handle git state.

## Notes Maintenance

The `docs/` folder contains project knowledge for agents.

- **Read `docs/index.md` first** to orient yourself.
- Keep notes concise and current. Describe the *present* state, not historical implementation journeys.
- Do not duplicate information found in source files or the spec. Reference them instead.
- Do not create task completion reports, phase reviews, or verbose historical accounts.
- Deduplicate across files. If information about a topic is scattered, consolidate it.
- Keep individual files under ~200 lines where possible. Split by sub-topic if needed.
- Update `docs/index.md` when adding or removing files.

## README Conventions

When editing `README.md` or other readmes:

- Keep it concise, well structured, and human-readable.
- No emojis.
- Start with a one-paragraph summary of the project's purpose.
- Follow with a high-level overview of the repository layout.
- Include URLs to deployed stages and local dev setup instructions.
- Deduplicate: every fact should appear exactly once.
