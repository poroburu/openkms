# openKMS brand assets (mirror)

**Canonical source:** `openkms-whitepaper/brand/` in the sibling whitepaper repository.

This folder is a **build-time mirror** for the Astro website (`../website/` imports
`logo.svg` here). Edit the mark and tokens in the whitepaper repo first, then run:

```bash
# from openkms-whitepaper/
./scripts/sync-brand.sh
```

Synced targets:

- `logo.svg` here and `website/public/favicon.svg`
- `openkms-pitch/video/public/logo.svg`
- `website/src/styles/design-tokens.css` (from `brand/tokens.css`)
