from pathlib import Path

from ownkit.modules import ci, docker

ROOT = Path(__file__).resolve().parents[1] / "fixtures"


def test_docker_flags_latest_root_privileged_and_socket():
    ids = {f.id for f in docker.scan(ROOT)}
    assert "docker.from_latest" in ids
    assert "docker.runs_as_root" in ids
    assert "docker.privileged" in ids
    assert "docker.socket_mount" in ids


def test_ci_flags_pull_request_target_and_echoed_secret():
    ids = {f.id for f in ci.scan(ROOT)}
    assert "ci.pull_request_target" in ids
    assert "ci.secret_in_logs" in ids
