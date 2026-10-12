# rIDM design reference — "Signal v2"

The visual direction chosen for Phase 15 (2026-10-12) after a review of four mocks
(`mocks/a` Vault, `mocks/b` Registry, `mocks/c` Signal, `mocks/c2` Signal v2). The mocks are
static HTML built with the real acme tenant content; serve them with
`npx serve design/mocks -l 3120` and open <http://localhost:3120>. They are the
reference for 15.2 onwards, not shipped code: the production tokens live in
`ui/src/app/globals.css` and the theme engine in `ui/src/lib/`.

## Tenant theme model

Each tenant chooses, on Settings › Appearance (`mocks/c2/appearance.html`):

| Setting | Values | Default |
|---|---|---|
| `skin` | `signal-v2`, `signal`, `vault`, `registry` | `signal-v2` |
| `primary` | hex | `#3451b2` (Indigo) |
| `contrast` | hex | `#b45309` (amber) |
| `mode` | `system` (follow each person's device), `light`, `dark` | `system` |
| `allow_switch` | people may override the mode on their device | `true` |
| `display_name`, `logo` | as today | |

Presets ship as primary + contrast pairs: Indigo & amber, Ocean & coral, Forest &
ochre, Ember & slate, Plum & lime, Graphite & sky; custom pairs are allowed. The
tenant's choice applies to the admin console, the account console and the
sign-in pages. The sign-in pages keep the tenant's own pair even when an
administrator is viewing another tenant.

## Skins

All four mock directions ship as selectable skins (owner decision, 2026-10-12),
Signal v2 the default. A skin is **not** a separate code base: every page is built
once on the shared primitives, and a skin is

1. a token set (`[data-skin="…"]` on `<html>`): neutrals, bar colours, radii,
   shadows, type faces and scale, ground tint; the tenant colour ramps are shared;
2. a handful of structural switches read by the shell and a few primitives:

| Switch | signal-v2 | signal | vault | registry |
|---|---|---|---|---|
| console chrome | dark command bar + sidebar on ground, page as sheet | light command bar + sidebar | dark rail, top strip | light text-only sidebar, top strip |
| sidebar icons | yes | yes | yes | no |
| detail pages | floating panel over the list | panel | full page | full page |
| list density | 50 px rows, avatars | 38 px rows | 46 px rows | 44 px rows, no box |
| filters | chips | selects | selects | selects |
| status | dot + halo | outlined pill | dot + word | dot + word |
| sign-in | split (brand panel) when a headline is set, else card | card | card | card |
| display face | Bricolage Grotesque | Hanken Grotesk | IBM Plex Sans | Source Serif 4 |

Anything a skin does not override falls through to Signal v2. New pages are
designed for Signal v2 first and must look acceptable in the other three with
tokens alone; a structural switch is added only when tokens cannot do it. The
a11y sweep runs every console page in every skin at least in light mode, and
Signal v2 in light, dark and at 390 px.

## Colour

Two tonal ramps are derived from the two tenant colours (`mocks/shared/theme.js`,
~80 lines, plain hex output so it runs once at tenant load and needs no CSS
relative-colour support). Lightness steps are fixed in OKLCH so every hue lands
on the same rhythm; chroma tapers at both ends and is clamped into sRGB gamut.

| Step | L | chroma × |
|---|---|---|
| 50 | 0.975 | 0.25 |
| 100 | 0.94 | 0.40 |
| 200 | 0.88 | 0.60 |
| 300 | 0.80 | 0.80 |
| 400 | 0.70 | 0.95 |
| 500 | 0.60 | 1 |
| 600 | 0.50 | 1 |
| 700 | 0.43 | 0.95 |
| 800 | 0.36 | 0.85 |
| 900 | 0.28 | 0.70 |

Semantic slots, for both `--accent-*` and `--contrast-*`:

| Slot | Light | Dark |
|---|---|---|
| `soft` | 50 | L 0.23, chroma × 0.3 |
| `soft-2` | 100 | L 0.30, chroma × 0.4 |
| `border` | 300 | 700 |
| `ring` | 500 | 400 |
| `solid` / `solid-hover` | 600 / 700 | 600 / 500 |
| `text` | 700 | 300 |
| `ink` (text on solid) | white | white |

Where each colour goes: **primary** = actions (`solid`), navigation state,
focus ring, links, hover tints, chart series 1. **Contrast** = things that must
read as different from primary: the tenant mark (gradient 500 → contrast 500),
selected rows and the bulk-selection count, "this browser", attention badges,
chart series 2. Status colours are fixed and never come from the tenant:
`ok #2f7a4f / #62c98b`, `warn #9a6200 / #dfa63f`, `danger #b13a2e / #f08c80`
(light / dark), each with a `-soft` fill.

Neutrals (light / dark): `paper #ffffff / #15181f`, `raised #ffffff / #1b1f28`,
`ink #0f1218 / #eaedf2`, `ink-2 #343a46 / #c6ccd6`, `muted #626b7a / #8f99a8`,
`faint #9aa3b2 / #5f6878`, `line #e3e6ec / #262b35`, `line-strong #c9ced8 / #353c49`.
The ground is tinted by the tenant: `color-mix(in oklab, accent-50 55%, #eceef2)`
light and `color-mix(in oklab, accent-soft 45%, #0b0d12)` dark. The command bar is
dark in both modes: `bar #0f1117 / #0a0c10`, `bar-ink #f1f3f7`, `bar-muted #8b93a3`.

The Appearance page checks, and shows, these ratios for the chosen pair in both
modes and flags anything under 4.5:1: primary `text` on paper, white on primary
`solid`, contrast `text` on paper, contrast `text` on contrast `soft`, and the hue
distance between the two colours (≥ 60°). All six presets pass.

## Type

Self-hosted (OFL), latin + latin-ext woff2 subsets under `ui/src/fonts/`:

- **Bricolage Grotesque** 500/600/700 (opsz axis) for page titles, card titles, tile
  numbers, the wordmark. `letter-spacing: -0.02em`, `font-variation-settings: "opsz" 40`.
- **Hanken Grotesk** 400/500/600 for everything else.
- **JetBrains Mono** 400/500 for identifiers, times, counts, shortcut keys.

Scale (console): 12 / 13 / 14 / 16 / 22 / 30, numbers 34; body 14/1.45. Auth and
account pages run one step looser (body 15, inputs 42px). Sentence case
everywhere; no uppercase tracking; no middle-dot meta strings except in mono.

## Shape, depth, motion

Radius: 5 (chips, inputs) / 8 (buttons, cards, table) / 14 (sheet, panel, auth card).
Shadows only on floating layers: the sheet
(`0 1px 2px rgba(15,18,24,.04), 0 12px 32px -16px rgba(15,18,24,.18)`) and
pop-overs/panels/bulk bar (`0 2px 4px …, 0 16px 40px -12px rgba(15,18,24,.3)`).
Primary buttons get a top-to-bottom `solid → solid-hover` gradient and an inner
1px highlight. Motion: the detail panel slides in; nothing else moves on its own;
`prefers-reduced-motion` turns it off.

## Layout

- **Console**: 52px dark command bar (wordmark · tenant switcher · search/command
  field · mode switch · attention bell · avatar) over a 236px sidebar on the tinted
  ground, with the page in an elevated sheet. Sidebar items show counts where a
  list has one, the contrast colour for things waiting on the admin, and the
  `g`+key hint otherwise. Below 860px the sidebar becomes a drawer and the sheet
  loses its inset.
- **Lists**: chip filters (not selects), 50px rows with gradient initials and
  stacked display name/username, sortable headers, hover row actions, checkbox
  selection with a floating bulk bar, "n of total loaded" footer.
- **Detail**: a floating panel over the list (600px) with a tinted header, a
  four-cell stat strip, tabs, auto-save sections, and a footer with the save
  state and destructive actions. Deep links still open the panel.
- **Overview**: greeting, four stat tiles with sparklines and deltas, a bar
  chart (series 1 primary, series 2 contrast), "Needs attention", recent
  activity, most-used clients.
- **Sign-in**: split layout on desktop, brand panel (radial primary gradient
  with a contrast bloom, headline, the apps the account unlocks) left and the
  form right; the form alone on phones. The single-card layout remains for
  tenants that set no headline.
- **Account**: dark header with the tenant mark and tabs, a security-score card,
  then sections as cards.

## Screens in the mocks

`c2/users.html`, `c2/user.html` (panel), `c2/overview.html`, `c2/login.html`,
`c2/account.html`, `c2/appearance.html`. `index.html` compares every direction and
shares the tenant theme, mode policy and the person's switch through localStorage.
