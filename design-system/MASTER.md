# Argus Console Design System

## Product direction

Argus Console is a desktop-first security workbench for developers and application-security reviewers. The interface should feel like a calm, precise instrument: dense enough for investigation, but never visually noisy. The primary experience is scan orchestration, human review, and evidence-backed remediation.

## Visual language

- Style: dark editor-inspired workbench with restrained depth and crisp borders.
- Personality: technical, trustworthy, focused, evidence-first.
- Avoid: neon cyberpunk decoration, glass panels, glowing charts, oversized marketing typography, and color-only status communication.
- Use an 8px spacing rhythm, 10–12px radii, one-pixel borders, and at most two elevation levels.

## Color tokens

### Dark theme

- `canvas`: `#0B0D10`
- `sidebar`: `#0E1116`
- `surface`: `#13171D`
- `surface-raised`: `#181D24`
- `surface-hover`: `#1D232C`
- `border`: `#29313C`
- `border-strong`: `#3A4654`
- `text-primary`: `#F4F6F8`
- `text-secondary`: `#AAB4C0`
- `text-muted`: `#778493`
- `brand`: `#F0A34A`
- `brand-strong`: `#F6B963`
- `brand-subtle`: `#332416`
- `critical`: `#FF6B6B`
- `high`: `#F0A34A`
- `medium`: `#E0C35A`
- `low`: `#69A7D8`
- `success`: `#65C18C`
- `info`: `#7E9FEF`

### Light theme

- `canvas`: `#F3F5F7`
- `sidebar`: `#F8F9FA`
- `surface`: `#FFFFFF`
- `surface-raised`: `#FFFFFF`
- `surface-hover`: `#F1F3F5`
- `border`: `#DCE1E6`
- `border-strong`: `#C3CBD4`
- `text-primary`: `#151A21`
- `text-secondary`: `#4E5968`
- `text-muted`: `#6B7684`
- `brand`: `#A75B12`
- `brand-strong`: `#85450B`
- `brand-subtle`: `#FFF0DF`

## Typography

- UI/body: Inter-style system sans-serif (`Inter`, `SF Pro Text`, `Segoe UI`, sans-serif).
- Code and tabular data: `SFMono-Regular`, `Cascadia Code`, `Roboto Mono`, monospace.
- Scale: 12 / 13 / 14 / 16 / 20 / 28 / 36.
- Body starts at 14px on desktop and 16px for mobile form controls.
- Use tabular figures for metrics, durations, line numbers, and counts.

## Layout

- Desktop sidebar: 232px. Top bar: 64px.
- Main content: fluid with 32px gutters and a 1440px content maximum.
- Primary dashboard grid: 8/4 columns at wide sizes, single column below 960px.
- Tablet/mobile use an off-canvas sidebar; never allow horizontal page scrolling.
- Interactive targets are at least 44×44px.

## Components and states

- Buttons: one primary action per view. Primary uses brand fill with dark text. Secondary uses surface + border.
- Focus: 3px visible focus ring using brand with an offset from the control.
- Status chips: always pair color with text and a small shape/icon.
- Cards: flat surface with border. Hover may change border/surface, never move layout.
- Tables: sticky header only when the table itself scrolls; row actions remain keyboard reachable.
- Drawers/modals: 50% black scrim, focus trapping, Escape close, explicit close label.
- Loading over 300ms: skeleton for page regions; button shows progress and disables duplicate submission.

## Motion

- Micro-interactions: 160–220ms ease-out.
- Drawer/modal entry: 240ms ease-out; exit: 160ms ease-in.
- Animate opacity and transform only.
- Respect `prefers-reduced-motion`.

## Core page hierarchy

1. Overview: active scan, risk summary, review queue, recent findings.
2. Scans: workspace history, state, duration, and resume/continue controls.
3. Review: enrichment and finding checkpoints with approve/focus actions.
4. Findings: filterable evidence table with detail drawer.
5. Reports: generated Markdown artifacts and export actions.
6. Settings: LLM endpoint health, source disclosure defaults, and analyzer presets.

## Accessibility baseline

- Text contrast: WCAG AA minimum.
- Full keyboard navigation with semantic buttons and visible focus.
- Icon-only buttons require accessible names.
- Status cannot rely on color alone.
- Dialogs expose titles/descriptions and restore focus on close.
- Charts include direct labels and an adjacent text summary.
- Reduced motion and 200% text zoom must remain usable.

