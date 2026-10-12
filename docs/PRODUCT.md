# Argus product direction

Argus is an internally deployed API-key-protected white-box scan tool. A project is one repository URL plus one branch. Users select a branch; the first scan reviews its latest full-file contents, and later scans review the cumulative diff from the last complete baseline to the latest commit. Commits are recorded automatically.

Each scan keeps independent findings and JSON, Markdown, and SARIF reports. Project vulnerabilities merge and deduplicate findings; processing states are changed manually and survive later scans. Project reports export the current deduplicated list and manual states.

There is no aggregate token budget. The UI shows basic scan states and failure reasons, not detailed progress. Temporary source and OCR sessions are deleted; a shared execution slot limits concurrent checkouts to one. GitLab read-only credentials are supplied once at startup and matched to the configured host.

Fix verification, fix records, resumable sessions, dynamic target execution, autonomous penetration, and additional scan engines are out of scope. The previous project registry remains retired; new project behavior lives in the current service.
