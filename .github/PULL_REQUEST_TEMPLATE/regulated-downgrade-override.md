# Regulated Downgrade Override Request

> Use this template **only** when requesting a **temporary downgrade** (`input.override.regulated=false`) for a specific release validation case.  
> All fields are **mandatory**. Missing **any** item will be rejected by policies.

## Reason for Override
- **Reason (concise, specific):** <!-- e.g., Emergency patch for P0 incident -->
- **Risk Assessment Link:** <!-- link to formal assessment -->

## Ticket & Approvals
- **Tracking Ticket ID/URL:** <!-- e.g., SEC-1234 -->
- **Approved By (names, roles):** <!-- e.g., Jane Doe (SRE), John Smith (Security) -->
- **Approvals Evidence:** <!-- links/screenshots if applicable -->

## Time-bounded Validity
- **Approved At (RFC3339):** <!-- e.g., 2026-03-10T10:00:00Z -->
- **Expires At (RFC3339):** <!-- MUST be ≤ max_days (7) from Approved At -->

## Required GitHub Label
- Ensure PR has label: **`regulatory-override-approved`**

## Input Snippet (example)
```json
{
  "override": {
    "regulated": false,
    "reason": "Emergency patch for P0 incident",
    "ticket": "SEC-1234",
    "approved_by": "Jane Doe (SRE), John Smith (Security)",
    "approved_at": "2026-03-10T10:00:00Z",
    "expires_at": "2026-03-15T10:00:00Z",
    "approvals": [
      {"role":"SRE","by":"Jane Doe"},
      {"role":"Security","by":"John Smith"}
    ]
  },
  "labels": ["regulatory-override-approved"]
}
