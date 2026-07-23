import pytest
from ssm_manager import Config, HostConfig, LocalForwardConfig


class TestLocalForwardConfig:
    def test_parse_valid_host_port(self):
        lf = LocalForwardConfig()
        assert lf.parse_line(1, "localforward", "15432 127.0.0.1:5432")
        assert lf.local_port == 15432
        assert lf.remote_address == "127.0.0.1"
        assert lf.remote_port == 5432

    def test_parse_valid_hostname_port(self):
        lf = LocalForwardConfig()
        assert lf.parse_line(1, "localforward", "18080 localhost:8080")
        assert lf.local_port == 18080
        assert lf.remote_address == "localhost"
        assert lf.remote_port == 8080

    def test_parse_invalid_format(self):
        lf = LocalForwardConfig()
        assert not lf.parse_line(1, "localforward", "invalid")

    def test_parse_invalid_port(self):
        lf = LocalForwardConfig()
        assert not lf.parse_line(1, "localforward", "abc localhost:8080")

    def test_with_random_local_port(self):
        lf = LocalForwardConfig()
        lf.parse_line(1, "localforward", "15432 127.0.0.1:5432")
        updated = lf.with_random_local_port()
        assert updated.local_port == 0
        assert updated.remote_address == "127.0.0.1"
        assert updated.remote_port == 5432
        assert updated is not lf

    def test_str_repr(self):
        lf = LocalForwardConfig()
        lf.parse_line(1, "localforward", "15432 127.0.0.1:5432")
        expected = "LocalForwardConfig(local_port=15432, remote_address=127.0.0.1, remote_port=5432)"
        assert str(lf) == expected
        assert repr(lf) == expected


class TestHostConfig:
    def test_default_config(self):
        host = HostConfig.default_config()
        assert host.target == "default"
        assert host.hostname is None
        assert host.user is None
        assert host.profile is None
        assert host.region is None

    def test_resolve_hostname_with_hostname(self):
        host = HostConfig("app", options={"hostname": "i-12345"})
        assert host.resolve_hostname("anything") == "i-12345"

    def test_resolve_hostname_without_hostname(self):
        host = HostConfig("app")
        assert host.resolve_hostname("app") == "app"

    def test_parse_line_localforward(self):
        host = HostConfig("app")
        host.parse_line(1, "LocalForward", "15432 127.0.0.1:5432")
        assert len(host.local_forward) == 1
        assert host.local_forward[0].local_port == 15432

    def test_parse_line_option(self):
        host = HostConfig("app")
        host.parse_line(1, "User", "ubuntu")
        assert host.user == "ubuntu"

    def test_parse_line_unknown_option(self, caplog):
        host = HostConfig("app")
        host.parse_line(1, "UnknownOption", "value")
        assert "unrecognized option" in caplog.text


class TestConfig:
    def test_read_valid_config(self, sample_config_file):
        config = Config()
        assert config.read_config_file(sample_config_file)
        assert len(config.config["hosts"]) == 3

    def test_find_host_exact_match(self, sample_config_file):
        config = Config()
        config.read_config_file(sample_config_file)
        host = config.find_host_config("app-prod", allow_default=False)
        assert host is not None
        assert host.target == "app-prod"

    def test_find_host_wildcard(self, sample_config_file):
        config = Config()
        config.read_config_file(sample_config_file)
        host = config.find_host_config("web-api", allow_default=False)
        assert host is not None
        assert host.target == "web-*"

    def test_find_host_not_found_returns_default(self, sample_config_file):
        config = Config()
        config.read_config_file(sample_config_file)
        host = config.find_host_config("nonexistent")
        assert host is not None
        assert host.target == "default"

    def test_find_host_not_found_returns_none(self, sample_config_file):
        config = Config()
        config.read_config_file(sample_config_file)
        host = config.find_host_config("nonexistent", allow_default=False)
        assert host is None

    def test_read_config_invalid_first_line(self, invalid_config_file):
        config = Config()
        assert not config.read_config_file(invalid_config_file)

    def test_read_config_option_before_host(self, config_without_host_file):
        config = Config()
        assert not config.read_config_file(config_without_host_file)

    def test_read_config_not_found(self):
        config = Config()
        with pytest.raises(FileNotFoundError):
            config.read_config_file("/nonexistent/.ssm_config")

    def test_host_config_loaded_correctly(self, sample_config_file):
        config = Config()
        config.read_config_file(sample_config_file)
        host = config.find_host_config("app-prod", allow_default=False)
        assert host.hostname == "i-0123456789abcdef0"
        assert host.user == "ubuntu"
        assert host.profile == "prod"
        assert host.region == "us-east-1"
        assert len(host.local_forward) == 2
        assert host.local_forward[0].local_port == 15432
        assert host.local_forward[1].local_port == 18080

    def test_default_config_hostname(self):
        host = HostConfig.default_config()
        assert host.resolve_hostname("i-12345") == "i-12345"