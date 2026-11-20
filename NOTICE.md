# Licence and third-party material

Zenoglyphs is licensed under the GNU General Public License, version 3
(LICENSE). `zcribe` links go-zenon (github.com/zenon-network/go-zenon, GPL-3.0)
for block hashing, PoW and keys, so a binary built from this repository is a
work based on go-zenon; licensing the source the same way keeps the two from
disagreeing.

| Path | What | Licence |
|---|---|---|
| `go-zenon/` (submodule) | the Zenon node implementation | GPL-3.0 |
| `testdata/assets/p5.js` | p5.js 1.7.0, test content for composites | LGPL-2.1 (processing/p5.js) |
| [JetBrains Mono original notice](web/dist/notices/fontsource-jetbrains-mono-5.3.0-LICENSE) | JetBrains Mono Variable from Fontsource 5.3.0, embedded WOFF2 assets | OFL-1.1 |
| [Space Grotesk original notice](web/dist/notices/fontsource-space-grotesk-5.3.0-LICENSE) | Space Grotesk Variable from Fontsource 5.3.0, embedded WOFF2 assets | OFL-1.1 |

Original font notices live under `web/dist/notices/` in the embedded viewer
and under `web/ui/public/notices/` for the next viewer build. The font
check compares both copies with the locked npm archives.

The CI artifact `zcribe-go-notices` records original notice files for the
Go packages selected for a particular `zcribe` build. Its manifest identifies
the binary, the source and go-zenon revisions, the Go build profile and the
paths and checksums of the retained notice files. See
[dependency and distribution review](docs/DEPENDENCY_REVIEW.md) for the
remaining distribution checks.
