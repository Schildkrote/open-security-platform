# biometric-categorise

Sensitivity classifier for face/crop metadata. Labels drive lawful-basis
elevation (minors/health/religion → DPiA) and retention clamps.

## Categories

`public_figure | employee | minor | health_context | religion_context | general`

## Quickstart

```bash
python3 -m categorise.cli --age 12 --source school_cctv
python3 -m categorise.cli --tags hospital,ward --format json
python3 -m unittest discover -s tests
```

## License

Apache-2.0
