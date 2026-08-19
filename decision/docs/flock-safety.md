# Flock Safety — research notes & what we build

Sources: public Wikipedia extract (Flock Safety), product positioning, and
US case-law signals (e.g. Norfolk VA 2024 warrant ruling on ALPR location DBs).
Not legal advice.

## How Flock works (public picture)

| Layer | What Flock sells |
|---|---|
| **Hardware** | Falcon/Sparrow fixed ALPR cams; Condor PTZ/people+vehicle; gunshot sensors; drones (Aerodome acq.) |
| **Vision** | Plate OCR + “vehicle fingerprint” (make/model/color, stickers, damage, temp plates) |
| **Network** | Cellular backhaul → central searchable DB; 20B+/mo vehicle scans claimed |
| **Hotlists** | NCIC + state/local lists → instant officer alerts on match |
| **Software** | Search (incl. FreeForm NL), multi-agency share, HOA/private + police customers |
| **Adjacent** | Ring partnership attempts; immigration-use controversies; city opt-outs |

Positioning: “focus on vehicles, not people” for ALPR — but Condor/FreeForm
docs and public records show person-attribute search in practice. Critics
describe mass surveillance; company markets crime solvability.

### Legal friction (US-centric signal)

- **Norfolk VA (2024):** long-term ALPR location collection treated as a
  Fourth Amendment search; warrant needed to use as evidence (Jones-like
  reasoning).
- Patchwork: some states/cities restrict retention, immigration sharing, or
  HOA deployments; others expand contracts.
- **Implication for ODP:** live hotlist hit ≠ free historical pattern-of-life.
  Default policy: `pattern_of_life` / `query_historical` → `require_warrant`.

## What we build (lawful capability modules)

We do **not** build a Flock competitor network for HOAs. We build software
an **authorized LE / regulated operator** runs on **their** sensors:

1. **`connectors/alpr`** — plate events, vehicle attrs, hotlist, live alert objects
2. **`platform/policy`** — patrol_alert allow; historical require warrant/case
3. **Ontology types** — Vehicle, PlateRead, Sensor, Case, Warrant, Alert
4. **Actions** — open_case, issue_alert, request_warrant_package, link_evidence
5. **Retention hooks** — properties on PlateRead (enforced in v1 store policies)
6. Stubs only: gunshot event type, drone tasking action (no hardware)

Private bulk ALPR without statutory basis remains **out of scope**.

## Mapping Flock feature → ODP

| Flock-ish feature | ODP |
|---|---|
| Fixed ALPR ingest | `alpr.Ingest` + Sensor objects |
| Vehicle fingerprint attrs | `PlateEvent.Attrs` → vehicle properties |
| NCIC/local hotlist | `Hotlist` + `matched_hotlist` link + Alert |
| Officer push alert | `actions.IssueAlert` / auto alert on hit |
| Historical search UI | `QueryHistorical` gated by warrant |
| Multi-agency share | future policy pack + redacted export (like OBP graph) |
| FreeForm NL search | future AIP agent on Ontology ContextBundle |
| Gunshot / drone | object type stubs on roadmap |
