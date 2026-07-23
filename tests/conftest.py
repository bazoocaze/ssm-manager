import pytest


SAMPLE_CONFIG = """# Main server
Host app-prod
    Hostname i-0123456789abcdef0
    User ubuntu
    Profile prod
    Region us-east-1
    LocalForward 15432 127.0.0.1:5432
    LocalForward 18080 localhost:8080

Host app-staging
    Hostname i-0987654321fedcba0
    User ec2-user
    LocalForward 8080 0.0.0.0:80

Host web-*
    Hostname i-55555555555555555
    Profile staging
"""

INVALID_CONFIG = """SomeRandomOption value
"""

CONFIG_WITHOUT_HOST = """Hostname i-0123456789abcdef0
    User ubuntu
"""

SAMPLE_CONFIG_PATH = None


@pytest.fixture
def sample_config_file(tmp_path):
    path = tmp_path / ".ssm_config"
    path.write_text(SAMPLE_CONFIG)
    return str(path)


@pytest.fixture
def invalid_config_file(tmp_path):
    path = tmp_path / ".ssm_config"
    path.write_text(INVALID_CONFIG)
    return str(path)


@pytest.fixture
def config_without_host_file(tmp_path):
    path = tmp_path / ".ssm_config"
    path.write_text(CONFIG_WITHOUT_HOST)
    return str(path)