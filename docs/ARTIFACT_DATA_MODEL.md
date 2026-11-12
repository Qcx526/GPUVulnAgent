# Artifact data model

`schema gpuvulnagent-artifact/v1`, appended to `trial/evidence/artifact_index.jsonl`;
`artifact_index.json` is a materialised view.

Fields: artifact_id (`art-` + hash(trial|path|content)[:12]), trial_id, artifact_type
(source/header/script/binary/object/input/data/document/log/dump/file), relative_path,
filename, sha256, size, media_type, language, origin (generated/copied/downloaded/modified/
compiled/UNKNOWN), parent_artifact_ids, producer_tool, producer_evidence_id, producer_turn,
execution_id, created_at, version, status.

`UNKNOWN` is a first-class value: a missing parent is honest, an invented one is a false
provenance claim. Types come from the extension first, ELF magic second, and stay `file`/
`UNKNOWN` when neither applies.

`verify()` re-hashes every declared file and reports missing and changed separately; the
evidence hash chain is independent of it, so one cannot mask the other.
