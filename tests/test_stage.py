# -*- coding: utf-8 -*-
import hashlib
import os
from pathlib import Path

import pytest

from gpuvulnagent.tools.stage import StageError, resolve_source, stage_copy


@pytest.fixture
def roots(tmp_path):
    repo = tmp_path / "repo"
    (repo / "toolchains" / "bin").mkdir(parents=True)
    (repo / "research_archive" / "exp").mkdir(parents=True)
    (repo / "toolchains" / "bin" / "tool.bin").write_bytes(b"\x7fELF" + b"\x00" * 9000)
    (repo / "research_archive" / "exp" / "a.cubin").write_bytes(b"abc")
    wsl = tmp_path / "wsl"
    (wsl / "cuobjdump").mkdir(parents=True)
    (wsl / "cuobjdump" / "cuobjdump").write_bytes(os.urandom(20000))
    return repo, wsl


def test_wsl_ref_and_repo_resolve(roots):
    repo, wsl = roots
    p, origin = resolve_source("wsl-ref:cuobjdump/cuobjdump", repo_root=repo, wsl_root=wsl)
    assert p.is_file() and origin == "wsl-ref:cuobjdump/cuobjdump"
    p2, origin2 = resolve_source("repo:toolchains/bin/tool.bin", repo_root=repo, wsl_root=wsl)
    assert p2.is_file() and origin2 == "repo:toolchains/bin/tool.bin"


@pytest.mark.parametrize("spec", ["wsl-ref:../etc/passwd", "repo:toolchains/../../x",
                                  "repo:/etc/passwd", "repo:docs/a", "nonsense", ""])
def test_unsafe_sources_are_rejected(roots, spec):
    repo, wsl = roots
    with pytest.raises(StageError):
        resolve_source(spec, repo_root=repo, wsl_root=wsl)


def test_symlink_is_rejected(roots, tmp_path):
    repo, wsl = roots
    link = wsl / "link.bin"
    try:
        os.symlink(str(wsl / "cuobjdump" / "cuobjdump"), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("no symlink support")
    with pytest.raises(StageError):
        stage_copy(link, tmp_path / "out.bin")


def test_directory_is_rejected(roots, tmp_path):
    repo, wsl = roots
    with pytest.raises(StageError):
        stage_copy(wsl / "cuobjdump", tmp_path / "out.bin")


def test_copy_is_hash_checked_and_idempotent(roots, tmp_path):
    repo, wsl = roots
    src = wsl / "cuobjdump" / "cuobjdump"
    dest = tmp_path / "t" / "cuobjdump"
    first = stage_copy(src, dest)
    assert first["written"] is True
    assert first["sha256"] == hashlib.sha256(src.read_bytes()).hexdigest()
    second = stage_copy(src, dest)
    assert second["written"] is False and second["sha256"] == first["sha256"]


def test_same_name_different_bytes_is_refused(roots, tmp_path):
    repo, wsl = roots
    src = wsl / "cuobjdump" / "cuobjdump"
    dest = tmp_path / "cuobjdump"
    stage_copy(src, dest)
    src.write_bytes(b"different")
    with pytest.raises(StageError):
        stage_copy(src, dest)


def test_missing_source_is_refused(roots, tmp_path):
    repo, wsl = roots
    with pytest.raises(StageError):
        stage_copy(wsl / "nope", tmp_path / "x")
