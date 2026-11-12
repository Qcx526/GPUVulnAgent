# PoC artifact lifecycle

Every produced file becomes an artifact the moment it appears, however it was produced: a
tool write, a shell heredoc, a `sed` derivation, a container compile, a download.

Layout: `runs/trialN/{session,poc,evidence,executions,report}`. Files are stored once, where
they were produced (`session/run/workspace/...`, `session/run/trails/<id>/execs/execNN/outputs/...`);
`poc/manifests/<artifact>.json` and `poc/INDEX.md` hold the provenance view. Copying sources
into `poc/generated` would create a second copy that can drift from the bytes actually
compiled, so the registry points at the original.

Detection does not parse shell strings. After each decision the runtime harvests `workspace/`
and every `trails/*/execs/*/outputs/`, comparing hashes with the previous pass; anything new
or changed is registered with the tool and evidence id that produced it. Files under
`execs/*/outputs/` carry `execution_id = trailN/execNN`, and binaries there are marked
`compiled`.

Versioning: a name is not an identity. Different bytes at an existing name become
`name_v002.ext` with the earlier artifact as parent; identical bytes are deduplicated.
