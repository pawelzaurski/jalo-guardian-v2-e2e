# JALO Guardian 2.0 E2E Sandbox

Disposable isolated GitHub test surface for JALO Guardian 2.0 V2-04.

## Safety boundary

- no production secrets;
- no provider/API credentials;
- no Render/Supabase/tenant integrations;
- no cross-repository write permissions;
- no production source of truth;
- no application runtime or deployment.

The production Guardian remains in `pawelzaurski/jalo`.
Canonical Guardian documentation remains in `pawelzaurski/jalo-doc`.

This repository exists only to prove GitHub-native PR/check/merge/push behavior.
