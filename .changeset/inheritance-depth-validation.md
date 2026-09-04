---
'robrac': patch
---

Reject negative, fractional, non-finite and unsafe inheritance depth values at engine and plugin construction. This prevents accidental unbounded parent traversal or silently disabled inheritance.
