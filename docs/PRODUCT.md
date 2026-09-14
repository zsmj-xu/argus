# Argus product direction

Argus is an internally deployed API-key-protected white-box scan service. A caller submits a Git URL and optional ref; a disposable worker checkout is scanned by the pinned OpenCodeReview full-file engine. The service returns static findings with source locations and JSON, Markdown, and SARIF reports.

The product has no project registry, dynamic verification, target execution, autonomous penetration workflow, or second LLM scan engine.
