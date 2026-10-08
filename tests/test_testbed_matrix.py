from pathlib import Path

import pytest
import yaml
from testbed.render import get_config, swanctl_conf

MATRIX = Path(__file__).resolve().parent.parent / "testbed" / "matrix.yaml"


def test_day2_ids_enabled():
    data = yaml.safe_load(MATRIX.read_text(encoding="utf-8"))
    for cid in ("C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C10"):
        assert data["configs"][cid]["enabled"] is True
    assert data["configs"]["C9"]["enabled"] is False


def test_c1_swanctl_has_tunnel_aes128_dh14():
    _, row = get_config("C1")
    text = swanctl_conf(row, "a")
    assert "version = 2" in text
    assert "mode = tunnel" in text
    assert "aes128-sha256-modp2048" in text
    assert "start_action = none" in text
    assert "10.1.0.0/24" in text
    assert "10.2.0.0/24" in text
    assert "secret = \"" in text
    text_b = swanctl_conf(row, "b")
    assert "local_addrs = 10.10.0.20" in text_b
    assert "remote_addrs = 10.10.0.10" in text_b


def test_c2_aes256_cbc():
    _, row = get_config("C2")
    text = swanctl_conf(row, "a")
    assert "aes256-sha256-modp2048" in text


def test_c3_gcm_ecp256():
    _, row = get_config("C3")
    text = swanctl_conf(row, "a")
    assert "aes128gcm16-prfsha256-ecp256" in text
    assert "aes128gcm16-ecp256" in text
    assert "mode = tunnel" in text


def test_c5_and_c6_request_transport_but_lab_tunnel():
    for cid in ("C5", "C6"):
        _, row = get_config(cid)
        text = swanctl_conf(row, "a")
        assert "mode = tunnel" in text
        assert row["requested_mode"] == "transport"
    _, c6 = get_config("C6")
    assert "modp2048" not in c6["esp_proposal"]


def test_c7_c8_weak_and_c10_ikev1():
    _, c7 = get_config("C7")
    assert "sha1-modp1024" in swanctl_conf(c7, "a")
    assert c7["weak"] is True
    _, c8 = get_config("C8")
    text = swanctl_conf(c8, "a")
    assert "3des-sha1-modp1024" in text
    assert "esp_proposals = 3des-sha1" in text
    _, c10 = get_config("C10")
    text = swanctl_conf(c10, "a")
    assert "version = 1" in text
    assert "aggressive = no" in text
    assert c10["ike_version"] == 1


def test_stretch_c9_refused():
    with pytest.raises(SystemExit, match="not enabled"):
        get_config("C9")


def test_unknown_config_refused():
    with pytest.raises(SystemExit, match="unknown"):
        get_config("C99")


def test_write_runtime_includes_conf_d(tmp_path, monkeypatch):
    import testbed.render as render

    monkeypatch.setattr(render, "RUNTIME", tmp_path)
    _, row = get_config("C1")
    render.write_runtime(row)
    assert (tmp_path / "gw-a" / "swanctl.conf").read_text() == "include conf.d/*.conf\n"
    lab = (tmp_path / "gw-a" / "conf.d" / "lab.conf").read_text()
    assert "connections" in lab
    assert "ike-lab" in lab
