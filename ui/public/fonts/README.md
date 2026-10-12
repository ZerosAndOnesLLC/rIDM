# Fonts

Self-hosted, subset to latin and latin-ext, variable-weight woff2, all under the
SIL Open Font License 1.1 (each licence is beside its files). Loaded by the
`@font-face` rules in `src/app/globals.css`; the latin files are preloaded by
the root layout.

| Family | Files | Axes | Source |
|---|---|---|---|
| Bricolage Grotesque | `bricolage-grotesque-{latin,latin-ext}.woff2` | wght 500–700, opsz | https://github.com/ateliertriay/bricolage |
| Hanken Grotesk | `hanken-grotesk-{latin,latin-ext}.woff2` | wght 400–600 | https://github.com/marcologous/hanken-grotesk |
| JetBrains Mono | `jetbrains-mono-{latin,latin-ext}.woff2` | wght 400–500 | https://github.com/JetBrains/JetBrainsMono |

The subsets were produced by Google Fonts (`fonts.gstatic.com`, 2026-10) from
the upstream releases; regenerate with `pyftsubset` from the upstream TTFs if a
glyph is missing.
