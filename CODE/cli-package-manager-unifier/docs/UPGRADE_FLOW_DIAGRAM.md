# Upgrade Flow Diagram

This diagram shows the runtime flow for:

```bash
unified upgrade <package>
```

```mermaid
flowchart LR
    A[Command\nunified upgrade <package>] --> B[Security Scan\nHash + Provider Checks]
    B --> C{Decision}
    C -->|block| F[Write JSON Report\nEnd]
    C -->|warn| D[Prompt: Download MD Report?\n(y/n)]
    D --> E[Prompt: Proceed Anyway?\n(y/n)]
    E -->|no| F
    E -->|yes| G[Run Upgrade\nvia selected manager]
    C -->|allow| G
    G --> H[Write JSON Report\nShow Result]

    D -.optional.-> I[Write Markdown Report\nsecurity_reports/*.md]
```

## Notes

- `block`: upgrade is stopped immediately.
- `warn`: user can optionally download markdown report, then choose whether to proceed.
- `allow`: upgrade executes directly.
- JSON report is always written for final operation status.
