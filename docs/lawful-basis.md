# Lawful basis matrix

Purpose × regime × category → outcome. Implemented in `platform/lawful-basis`.

| Purpose | Consent | DPiA | LE | Outcome |
|---|---|---|---|---|
| enrolment / training / targeted_search | yes | — | — | permitted |
| enrolment / training / targeted_search | no | — | — | requires_consent |
| untargeted_mass_id | any | any | any | **prohibited** |
| rbr_public | — | — | no | **prohibited** |
| rbr_public | — | no | yes | requires_dpia |
| rbr_public | — | yes | yes | permitted |
| cross_agency_share | yes | yes | — | permitted |
| cross_agency_share | no | yes | — | requires_consent |
| cross_agency_share | yes | no | — | requires_dpia |
| any + category minor/health/religion | yes | no | — | requires_dpia |
| any + category minor/health/religion | yes | yes | — | permitted (non-LE) |

## Retention clamps

| Category | Max retention |
|---|---|
| general / public_figure / employee | 90 days |
| minor / health_context / religion_context | 7 days |
| prohibited ops | 0 (no storage) |

## Product path (client harm reduction)

1. Client grants explicit consent covering `enrolment`, `training`, `targeted_search`.
2. Client uploads reference images → enrol (basis check).
3. Train / fine-tune on *only* those images.
4. Targeted scrape of public sources for *that* client.
5. Match → alert client; optional person-graph link (pseudonymous).
6. Consent revocation → purge embeddings + model immediately.