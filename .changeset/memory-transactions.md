---
'robrac': patch
---

Make memory-store transactions isolate pending writes and roll back failures, including nested transactions. Reject conflicting commits instead of overwriting concurrent writes.
