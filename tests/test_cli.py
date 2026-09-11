from cli import build_parser


def test_scan_parser_accepts_auth_and_access_control_configs():
    args = build_parser().parse_args([
        "scan",
        "https://example.com",
        "--scope", "example.com",
        "--auth-config", "auth.json",
        "--access-control-config", "access.json",
    ])
    assert args.auth_config == "auth.json"
    assert args.access_control_config == "access.json"
