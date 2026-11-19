"""sandbox.py against a real Docker daemon. Skipped when no daemon is reachable.

Run on linux-test via scripts/test-sandbox.sh. SANDBOX_TEST_IMAGE picks the image.
SANDBOX_TEST_NO_CGROUP_LIMITS=1 drops memory/cpu limits from *started* containers
for hosts without a delegated memory/cpu cgroup controller (the linux-test VM);
test_limits_are_set_at_create still checks them on a created-only container.
"""

import asyncio
import io
import json
import os
import tarfile

import pytest

docker = pytest.importorskip("docker")

from policy import SandboxPolicy, container_kwargs  # noqa: E402
import sandbox  # noqa: E402

IMAGE = os.environ.get("SANDBOX_TEST_IMAGE", "python:3.13-slim")
OWNER = "pytest-sandbox"
NO_CGROUP_LIMITS = os.environ.get("SANDBOX_TEST_NO_CGROUP_LIMITS") == "1"


@pytest.fixture(autouse=True)
def _cgroup_limits(monkeypatch):
    if NO_CGROUP_LIMITS:
        real = sandbox.container_kwargs

        def without_limits(*args, **kwargs):
            k = real(*args, **kwargs)
            k.pop("mem_limit")
            k.pop("nano_cpus")
            return k

        monkeypatch.setattr(sandbox, "container_kwargs", without_limits)


@pytest.fixture(scope="module")
def client():
    try:
        c = docker.from_env()
        c.ping()
    except Exception:
        pytest.skip("no Docker daemon")
    yield c
    asyncio.run(sandbox.reconcile(c, OWNER))


@pytest.fixture
def sbx(client):
    policy = SandboxPolicy.from_options({"memory_limit_mb": 256})
    s = asyncio.run(
        sandbox.create_sandbox(client, policy, image=IMAGE, owner=OWNER, sid="t1")
    )
    yield s
    asyncio.run(s.destroy())


def test_container_matches_hardening_policy(client, sbx):
    attrs = client.api.inspect_container(sbx.container_id)
    hc, cfg = attrs["HostConfig"], attrs["Config"]
    assert cfg["User"] == "65534:65534"
    assert cfg["Image"].startswith("sha256:")
    assert hc["CapDrop"] == ["ALL"]
    assert hc["SecurityOpt"] == ["no-new-privileges"]
    assert hc["ReadonlyRootfs"] is True
    assert hc["PidsLimit"] == 128
    assert hc["NetworkMode"] == "none"
    assert sorted(hc["Binds"]) == ["ci-repl-t1:/opt/repl:rw", "ci-sbx-t1:/sandbox:rw"]
    assert sorted(m["Destination"] for m in attrs["Mounts"]) == ["/opt/repl", "/sandbox"]
    assert all(m["Type"] == "volume" for m in attrs["Mounts"])


def test_limits_are_set_at_create(client):
    k = container_kwargs(
        SandboxPolicy.from_options({"memory_limit_mb": 256}),
        image_id=sandbox.resolve_image(client, IMAGE),
        name="ci-sbx-limits",
        sid="limits",
        labels={sandbox.LABEL_OWNER: OWNER},
    )
    k.pop("volumes")
    c = client.containers.create(**k)
    try:
        hc = client.api.inspect_container(c.id)["HostConfig"]
        assert hc["Memory"] == 256 * 1024 * 1024
        assert hc["NanoCpus"] == 1_000_000_000
    finally:
        c.remove(force=True)


def test_repl_is_injected_and_answers(sbx):
    code, out, err = asyncio.run(
        sbx.exec(["python3", "/opt/repl/client.py", "--reset"])
    )
    assert code == 0, err
    assert json.loads(out)["error"] is None


def test_binary_file_round_trip(sbx):
    data = bytes(range(256)) * 1000
    asyncio.run(sbx.put_file("/sandbox/sub/blob.bin", data))
    assert asyncio.run(sbx.get_file("/sandbox/sub/blob.bin")) == data
    code, out, _ = asyncio.run(sbx.exec(["stat", "-c", "%u", "/sandbox/sub/blob.bin"]))
    assert out.strip() == "65534"


def test_writes_only_allowed_in_sandbox_and_tmp(sbx):
    for path, ok in [("/sandbox/a", True), ("/tmp/a", True),
                     ("/opt/repl/a", False), ("/usr/a", False), ("/a", False)]:
        code, _, _ = asyncio.run(sbx.exec(["sh", "-c", f"echo x > {path}"]))
        assert (code == 0) is ok, path


def test_destroy_removes_container_and_volumes(client):
    policy = SandboxPolicy.from_options({"memory_limit_mb": 256})
    s = asyncio.run(
        sandbox.create_sandbox(client, policy, image=IMAGE, owner=OWNER, sid="t2")
    )
    asyncio.run(s.destroy())
    flt = {"label": f"{sandbox.LABEL_SESSION}=t2"}
    assert client.containers.list(all=True, filters=flt) == []
    assert client.volumes.list(filters=flt) == []


def test_reconcile_removes_only_owned_resources(client):
    policy = SandboxPolicy.from_options({"memory_limit_mb": 256})
    asyncio.run(sandbox.create_sandbox(client, policy, image=IMAGE, owner=OWNER, sid="t3"))
    bystander = client.containers.create(IMAGE, ["sleep", "60"], name="ci-bystander")
    other_owner = client.containers.create(
        IMAGE, ["sleep", "60"], labels={sandbox.LABEL_OWNER: "someone-else"}
    )
    try:
        removed = asyncio.run(sandbox.reconcile(client, OWNER))
        assert removed["containers"] >= 1 and removed["volumes"] >= 2
        flt = {"label": f"{sandbox.LABEL_OWNER}={OWNER}"}
        assert client.containers.list(all=True, filters=flt) == []
        assert client.volumes.list(filters=flt) == []
        bystander.reload()
        other_owner.reload()  # both still exist
    finally:
        bystander.remove(force=True)
        other_owner.remove(force=True)


def test_tar_helpers_round_trip():
    blob = sandbox.make_tar({"x/y.txt": (b"hello", 0o644)}, uid=0)
    with tarfile.open(fileobj=io.BytesIO(blob)) as tf:
        names = tf.getnames()
    assert names == ["x/y.txt"]
    assert sandbox.first_file(blob) == b"hello"
