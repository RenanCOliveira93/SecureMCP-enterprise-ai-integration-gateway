# ADR-0004: RBAC ∩ scopes, evaluated by a declarative deny-by-default policy

## Context
Different people (viewer, support, operations, admin) need different powers, the application acting for them
should only get what it needs, and some actions should be possible only with human approval depending on their
arguments (for example, notifying all contacts by SMS).

## Decision
- Permissions are `<domain>:<action>` strings that are also OAuth scopes.
- **Effective permissions = role permissions ∩ token scopes**, recomputed on every call.
- `config/policy.yaml` lists every operation with its permission, risk, approval conditions, rate-limit class and
  timeout. Operations not listed are denied. Conditions use a closed set of operators (`eq`, `in`, `gt`, `gte`,
  `count_gt`) over named input fields; unknown operators or fields fail at startup.
- The policy `version` is written to every audit event; every decision carries a `policy_id`.

## Alternatives considered
- **OPA/Rego or Cedar**: powerful and battle-tested; adds a sidecar or WASM runtime and a new language. The interface
  (`PolicyEngine.evaluate`) allows replacing the evaluator later.
- **Decorators in code** (`@requires("tickets:write")`): readable, but approval rules and limits would be scattered
  and invisible to auditors.

## Consequences
- Policy changes are configuration changes, reviewed like code, and testable (`tests/unit/test_policy.py`).
- The expressiveness is intentionally limited; complex attribute-based rules would justify moving to Cedar/OPA.
