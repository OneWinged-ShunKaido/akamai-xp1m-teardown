# Unpacking Akamai Bot Manager

A threat-intelligence teardown of Akamai Bot Manager's browser sensor — analysing its
VM-in-VM JavaScript obfuscation, self-integrity, and timing defenses with **deterministic,
out-of-band analysis** rather than in-browser instrumentation. Security research, written
for an academic and defensive-security audience; not a bypass tool or evasion service.

> 📖 **Read the rendered write-up → https://onewinged-shunkaido.github.io/akamai-xp1m-teardown/**

The source Markdown lives in [`docs/index.md`](docs/index.md); the link above is the same
write-up rendered as a browsable site (MkDocs Material).

## What's inside

- How the sensor is built: two-IIFE skeleton, a stack-based mini-VM, a float/string codec
  (zero plaintext), and a decoder keyed to a hash of the script's own text.
- The sensor pipeline: envelope → an LCG-keyed substitution cipher → the `t7C` object, decoded field by field.
- **Backward provenance slicing** from a single divergent fingerprint character to its root
  cause — an existence probe of `baseURI` / `Node` constants on a *detached* DOM element.
- Reproducing a captured sensor to **zero byte differences**, and showing the approach
  generalises across a daily-rotating build family and back to Akamai's pre-VM ancestors.

## Build / preview locally

```bash
pip install -r requirements.txt
mkdocs serve          # http://127.0.0.1:8000
```

## Publish (GitHub Pages)

1. Create a **new, empty** GitHub repository and push this folder to it.
2. The included workflow (`.github/workflows/deploy.yml`) runs `mkdocs gh-deploy` on every
   push to `main`, which builds the site and pushes it to a `gh-pages` branch.
3. Once that workflow has run, set **Pages → Build and deployment → Source: Deploy from a
   branch → `gh-pages` (root)**, and set `site_url` in `mkdocs.yml` to your Pages URL.

## Scope & disclaimer

This is **research / educational** material. In keeping with a responsible-disclosure posture:

- It describes mechanisms and methodology; it is **not** a bypass recipe and deliberately omits
  exploitation details (exact integrity seeds, key-derivation arithmetic, working evasions).
- It does **not** redistribute Akamai's payloads, any captured sensor data, or the analysis
  engine used. Function/field names belong to one ephemeral build and rotate constantly.
- All identifiers, addresses, and values shown are from a single research capture and are not
  intended to enable abuse of any service.

## License

The write-up text is released under **CC BY-NC-SA 4.0** (see [`LICENSE`](LICENSE)).
