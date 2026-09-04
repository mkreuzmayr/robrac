---
'robrac': minor
---

**Breaking:** Overrides now short-circuit role resolution, so overridden decisions have empty roles and effectiveRoles arrays. Deny overrides block custom grant-management predicates, and overridden ancestors contribute no inherited roles.
