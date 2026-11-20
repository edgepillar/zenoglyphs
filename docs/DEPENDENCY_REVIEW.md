# Dependency and distribution review

CI actions use full commit pins with readable major-version comments. Weekly
Dependabot proposals cover Actions, the root Go module and the UI npm lock,
limited to two open ordinary version-update pull requests per ecosystem. Review
and qualification are required before accepting a proposal. The configuration
does not establish that the updater has run or that an advisory or distribution
review is complete.

The Linux Go job selects [checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1)
and [setup-go v7.1.0](https://github.com/actions/setup-go/releases/tag/v7.1.0)
at their official release commits. Both actions use the runner's Node 24
runtime. Go remains selected through `go.mod`. Checkout fetches the recorded
submodule with credential persistence disabled. The workflow runs on
`push` and `pull_request` with `contents: read`.

## Resolve the actual source and build inputs

For an action update, resolve the release in its official repository and review
the old-to-new implementation, metadata, bundled dependencies, permissions,
credentials, network destinations and artifact handling. Keep the full commit
and readable version comment together. Matching a tag alone does not review the
implementation.

Review `go.mod` and `go.sum` with the actual Go toolchain and platform.
`github.com/zenon-network/go-zenon` is replaced by `./go-zenon`, whose source is
the exact Git submodule commit at the URL in [`.gitmodules`](../.gitmodules).
Record and review that gitlink separately from module proposals. Hashing, PoW
and key behavior depend on the effective replacement source. Build, vet,
relevant behavior tests and integrity checks must use the accepted submodule
commit; the placeholder module version is not its source identity.

`web/ui/go.mod` is an intentional module boundary that excludes UI files and
`node_modules` from the parent Go traversal. It is not a separately built Go
application and is not a second Go updater root. Review real UI inputs through
`web/ui/package.json` and `web/ui/package-lock.json`. Preserve exact resolved
versions, integrity and install-script decisions. The `nom-ui` dependency comes
from Git: bind the lock's complete commit ID and review its source and transitive
inputs rather than treating the manifest's GitHub shorthand as a pinned release.

The Go job builds with committed `web/dist` bytes. The separate
`embedded-viewer` job compares the checked-in WOFF2 files with the exact
`@fontsource-variable/jetbrains-mono` and
`@fontsource-variable/space-grotesk` archives from the npm lock. It records the
archive member and original notice digests and checks which original notice
bytes appear in the embedded tree. This check reads the two archives with
explicit limits and keeps a compact JSON report.

The viewer source check runs before toolchain setup and installation. The
public snapshot omits `web/ui/src/wallet/abi.ts`, `cbor.ts`, `envelope.ts` and
`useWallet.ts`, which the EVM pages and vector script require. The root
`wallet/` ignore rule matches those paths. A complete rebuild needs the
corresponding distributable source from the original viewer revision.

With those inputs present, the rebuild uses Node 22.23.5 with its bundled
npm 10.9.9. It checks the committed manifests, installs from the lock with
lifecycle scripts disabled, and verifies the installed `nom-ui` source tree,
manifest and original license against the locked Git revision. The registry
dependencies use npm's locked integrity fields. Reviewing a new Git dependency
revision includes updating the verifier's Git and file digests.

The viewer job runs the type, lint and protocol vector commands on one
installation. It builds the viewer and admin pages into a temporary directory
and compares their complete path sets and file bytes with the tracked Go embed
inputs. A difference fails the comparison. The job retains a compact,
commit-bound JSON inventory with both Git tree identifiers and SHA-256 digests.
The existing Go build continues to consume the committed viewer.
[Node release archive](https://nodejs.org/en/download/archive/v22.23.5),
[npm clean install](https://docs.npmjs.com/cli/v10/commands/npm-ci/),
[Locked nom-ui source](https://github.com/digitalSloth/nom-ui/tree/63f755a52cf6ee3665d3755755c506e3aa191bd4)

Triage advisories against exact resolved versions or replacement commits and the
advisory revision. Identify the call site or build step, runtime/build/test role
and affected shipped output. Preserve unknown reachability and failed/skipped
checks. Use the repository's private security channel for sensitive findings
until coordinated disclosure; scanner presence or absence is not a complete
reachability decision.

## Review a particular distribution

Start with [`NOTICE.md`](../NOTICE.md) and [`LICENSE`](../LICENSE). Review the
project/go-zenon GPL material, the separately attributed p5.js test asset and all
UI assets, fonts, linked dependencies and transitive material that reaches the
actual output. Retain original license/notice text, exact source revisions,
resolved input and output digests, build settings and corresponding source
material. Independent distribution/license review remains required; a notice
table or package license field alone is not a completed review.

Bind an SBOM and provenance statement to the exact binary and embedded viewer,
rather than only a manifest dependency list. The `ubuntu-latest` label and
downloaded Go toolchain remain mutable inputs. Record actual runner/toolchain
identities, supported-platform results, output-bound notices and release
signatures separately. These checks do not authorize signing, live inscription
publication, deployment or a production release.

Keep public artifacts in English and omit private paths, personal identity,
credentials, wallet material and raw private diagnostics. Preserve exact source
and run identities, actual exits, completeness and explicit unknowns in
sanitized evidence summaries.

References: [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)
and [Dependabot options](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference).
