import sys

import pytest


@pytest.fixture(autouse=True)
def reset_argv():
    original = sys.argv.copy()
    yield
    sys.argv = original


class TestParseArgs:
    def test_shell_subcommand(self):
        sys.argv = ["ssm", "shell", "i-12345"]
        from ssm_manager import _parse_args

        args, _ = _parse_args()
        assert args.command == "shell"
        assert args.target == "i-12345"

    def test_pf_subcommand(self):
        sys.argv = ["ssm", "pf", "app-prod"]
        from ssm_manager import _parse_args

        args, _ = _parse_args()
        assert args.command == "pf"
        assert args.target == "app-prod"

    def test_pfgw_subcommand(self):
        sys.argv = ["ssm", "pfgw", "web-api"]
        from ssm_manager import _parse_args

        args, _ = _parse_args()
        assert args.command == "pfgw"
        assert args.target == "web-api"

    def test_debug_flag(self):
        sys.argv = ["ssm", "--debug", "shell", "i-12345"]
        from ssm_manager import _parse_args

        args, _ = _parse_args()
        assert args.debug is True

    def test_debug_default(self):
        sys.argv = ["ssm", "shell", "i-12345"]
        from ssm_manager import _parse_args

        args, _ = _parse_args()
        assert args.debug is False

    def test_version(self):
        sys.argv = ["ssm", "--version"]
        from ssm_manager import _parse_args

        with pytest.raises(SystemExit) as exc:
            _parse_args()
        assert exc.value.code == 0