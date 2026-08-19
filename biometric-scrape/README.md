# biometric-scrape

Consent-gated, **targeted** image acquisition for enrolled clients only.
Untargeted mass scraping of the public is refused by the lawful-basis gate.

## Sources

| Source | Mode | Notes |
|---|---|---|
| `mock` | offline | Synthetic face-crop records |
| `web` | live | Read-only GETs against client-supplied URL allowlist |
| `archive` | live | News/image archive connectors (mock by default) |
| `cctv` | live | RTSP/ONVIF — requires LE basis or private-premises consent |

## Quickstart

```bash
python3 -m scrape.cli run --client alice --source mock
python3 -m scrape.cli run --client alice --source mock --format json
python3 -m unittest discover -s tests
```

## License

Apache-2.0
