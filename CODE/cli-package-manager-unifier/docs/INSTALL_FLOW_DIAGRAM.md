# Install Flow Diagram

This diagram shows the runtime flow for:

```bash
unified install <package>
```

```mermaid
flowchart LR
    A[Command\nunified install <package>] --> B[Security Scan\nHash + Provider Checks]
    B --> C{Decision}

    C -->|block| F[Write JSON Report\nEnd]

    C -->|warn| D[Prompt: Download MD Report?\n(y/n)]
    D --> E[Prompt: Proceed Anyway?\n(y/n)]
    E -->|no| F
    E -->|yes| G[Run Install\nvia selected manager]

    C -->|allow| G

    G --> H[Update Package Cache DB\npackage_cache.db]
    H --> I[Write JSON Report\nShow Result]

    D -.optional.-> J[Write Markdown Report\nsecurity_reports/*.md]
```

## Notes

- `block`: install is stopped immediately.
- `warn`: user can optionally download markdown report, then choose whether to proceed.
- `allow`: install executes directly.
- On successful install, local package cache DB is updated.
- JSON report is always written for final operation status.
