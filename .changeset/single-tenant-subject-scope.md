---
'robrac': patch
---

Normalize disabled scope before resolving HTTP caller subjects. Single-tenant apps no longer query organization membership tables, and custom subject resolvers receive the same null scope used by the engine.
