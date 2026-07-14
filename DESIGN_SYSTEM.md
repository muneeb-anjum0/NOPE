# NOPE Design System

NOPE uses one theme only: dark graphite. There is no light mode and no theme switcher.

## Tokens

Core tokens live in `apps/web/app/globals.css`.

- Root: `--background-root`
- Sidebar: `--background-sidebar`
- Surfaces: `--background-surface-1`, `--background-surface-2`, `--background-surface-3`, `--background-elevated`
- Borders: `--border-subtle`, `--border-default`, `--border-strong`
- Text: `--text-primary`, `--text-secondary`, `--text-tertiary`, `--text-disabled`
- Brand: `--brand-primary`, `--brand-primary-hover`, `--brand-primary-muted`
- Severity: `--critical`, `--high`, `--medium`, `--low`
- State: `--passed`, `--unknown`

## Typography

- Sans: Geist-first stack with system fallbacks.
- Mono: Geist Mono-first stack with system monospace fallbacks.
- Monospace is used for routes, files, scanners, status metadata, and model settings.
- Dashboard typography stays compact; landing page typography can be large and editorial.

## Components

- `LineSidebar`: route-aware icon navigation with active rail, tooltips, keyboard focus, and mobile dock behavior.
- `AppShell`: top bar, workspace chip, command button, AI status action, scan action.
- `ScanLauncher`: dark upload/URL/depth/authorization controls.
- `FindingTable`: dense evidence table.
- `AttackMapPanel`: dark graph canvas for route/file/data nodes.
- `SeveritySummary`: score, coverage, critical, and high summary panels.

## Motion

Motion is CSS-based and intentionally restrained:

- Hover feedback: 140-160 ms.
- Press feedback: subtle scale.
- Console/stage rows: short rise animation.
- `prefers-reduced-motion` disables nonessential motion.

## Severity Semantics

- Pink-red brand is for product identity and primary action.
- `critical` is only critical risk.
- `high` is high risk.
- `medium` is medium risk.
- `low` is low risk.
- Green is reserved for passed/verified states.

## Responsive Rules

- Desktop is primary.
- Landing hero collapses to one column under 980px.
- App sidebar becomes a bottom icon dock on mobile.
- Dense tables scroll inside panels on mobile.
- Attack maps remain scrollable rather than squashed.

## Accessibility

- Keyboard focus rings use brand red.
- Icon-only navigation includes screen-reader labels and hover/focus labels.
- Color is reinforced with text labels for severity/status.
- Reduced-motion preferences are respected.
