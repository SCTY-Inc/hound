# benefits-radar: recovery-drill evidence
The consolidated E5 fault matrix + backup-restore drill
(repos/hound/tests/test_e5_fault_matrix.py, inventory at
repos/hound/tests/evidence/e5/matrix-inventory.json) covers the commit
operations this lane uses (ingest.search/ingest.url): crash matrix,
interrupted recovery, hash-drift collision, outage abstention, and restore
from copy serving identical journal results. Production recovery was also
exercised live 2026-08-04 (stuck open pair reconciled to a durable
interrupted outcome on restart; recorded in GOALIE.md M3 narrative).
