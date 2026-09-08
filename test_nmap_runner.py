import pytest

from nmap_runner import NmapError, parse_nmap_xml, prepare_top_ports_scan, target_host
from scope import ScopeValidator


SAMPLE_XML = '''<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.27"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed" reason="reset"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
'''


def test_target_host_ignores_web_path():
    assert target_host("https://example.com/some/lab/path?id=1") == "example.com"


def test_target_host_rejects_explicit_port():
    with pytest.raises(NmapError, match="explicit ports"):
        target_host("https://example.com:8443")


def test_nmap_xml_is_normalized_to_open_ports():
    ports = parse_nmap_xml(SAMPLE_XML)
    assert len(ports) == 1
    assert ports[0].port == 443
    assert ports[0].protocol == "tcp"
    assert ports[0].service == "https"
    assert ports[0].product == "nginx"
    assert ports[0].version == "1.27"
    assert ports[0].reason == "syn-ack"


def test_nmap_xml_rejects_invalid_output():
    with pytest.raises(NmapError, match="invalid XML"):
        parse_nmap_xml("not xml")


def test_prepare_nmap_command_is_fixed_and_scoped():
    scope = ScopeValidator(("example.com",), allow_private_targets=True)
    command = prepare_top_ports_scan("https://example.com/lab", scope, require_nmap=False)
    assert command[-1] == "example.com"
    assert "--top-ports" in command
    assert "100" in command
    assert "-oX" in command
    assert "-" in command
    assert "--" in command
