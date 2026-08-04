# benefits-radar: static no-direct-provider evidence
The E1 ownership scan (repos/hound/migration/evidence/e1/ownership-scan.json,
2026-08-04) reports zero provider indicators in repos/givecare/gc-benefits
lane code. Cutover commit gc-benefits abffd89 deleted the direct-provider
path; EXA/FIRECRAWL keys are absent from every lane file (verified again in
the E1 matrix row for benefits-radar).
