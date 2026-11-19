from policy import SandboxPolicy, container_kwargs, volume_specs

LABELS = {"io.hass.code-interpreter.owner": "test"}


def kwargs(policy=None):
    policy = policy or SandboxPolicy.from_options({"memory_limit_mb": 512})
    return container_kwargs(
        policy, image_id="sha256:abc", name="ci-sbx-1", sid="1", labels=LABELS
    )


def test_from_options_maps_memory_limit():
    p = SandboxPolicy.from_options({"memory_limit_mb": 1024})
    assert p.process.memory_mb == 1024


def test_container_runs_by_image_id_with_labels():
    k = kwargs()
    assert k["image"] == "sha256:abc"
    assert k["name"] == "ci-sbx-1"
    assert k["labels"] == LABELS


def test_container_is_hardened():
    k = kwargs()
    assert k["user"] == "65534:65534"
    assert k["cap_drop"] == ["ALL"]
    assert k["security_opt"] == ["no-new-privileges"]
    assert k["read_only"] is True
    assert k["pids_limit"] == 128
    assert k["mem_limit"] == "512m"
    assert k["nano_cpus"] == 1_000_000_000
    assert k["network_mode"] == "none"
    assert k["working_dir"] == "/sandbox"


def test_only_owned_volumes_are_mounted():
    k = kwargs()
    assert k["tmpfs"] == {"/tmp": "size=64m"}
    assert k["volumes"] == {
        "ci-sbx-1": {"bind": "/sandbox", "mode": "rw"},
        "ci-repl-1": {"bind": "/opt/repl", "mode": "rw"},
    }
    assert "privileged" not in k and "devices" not in k


def test_entrypoint_waits_for_injected_repl():
    k = kwargs()
    script = k["entrypoint"][-1]
    assert "/opt/repl/.ready" in script
    assert "exec sh /opt/repl/init.sh" in script


def test_volume_specs_are_tmpfs_with_size_caps():
    p = SandboxPolicy.from_options({"memory_limit_mb": 512})
    specs = {v["name"]: v for v in volume_specs(p, "1", LABELS)}
    sbx = specs["ci-sbx-1"]
    assert sbx["driver"] == "local"
    assert sbx["labels"] == LABELS
    assert sbx["driver_opts"]["type"] == "tmpfs"
    assert "size=256m" in sbx["driver_opts"]["o"]
    assert "uid=65534" in sbx["driver_opts"]["o"]
    assert "nosuid" in sbx["driver_opts"]["o"]
    repl = specs["ci-repl-1"]["driver_opts"]["o"]
    assert "size=4m" in repl and "uid=" not in repl and "noexec" in repl
