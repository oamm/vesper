# Repository Guidance

Before substantial Vesper work, read `docs/PRODUCT_STATUS.md` and inspect the implementation relevant to the task. Do not assume PLANNED or DEFERRED capabilities exist.

Preserve the launcher/runner boundary: the .NET launcher owns host filesystem, Docker context, transport, container lifecycle, and exit propagation; the Python runner owns scanners, normalization, remediation grouping, policy, and reports.

After a milestone completes or product state materially changes (architecture, scanner, security finding, acceptance result, readiness, limitation, or deferred scope), update `docs/PRODUCT_STATUS.md` in the same change. Mark work COMPLETE only with concrete verification evidence. Record unverified platform behavior as UNVERIFIED rather than inferring success.
