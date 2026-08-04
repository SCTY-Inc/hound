# benefits-radar: unix-socket evidence
Acquisition executes in-process over the houndd Unix socket
(gc-benefits src/benefit_engine/houndd_backend.py, commit abffd89; socket
parameterized via GC_BENEFITS_HOUNDD_SOCKET). Live production writes through
the socket: journal entries owner_id=gc-benefits, including the full
scheduled run of 2026-08-04 06:35Z (36 rows total at audit time).
