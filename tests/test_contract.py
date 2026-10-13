"""Pinned contracts: values that are part of the shipped interface."""
import os

from ssm_manager import CONFIG


def test_default_config_file_is_pinned():
    """Shipped as ~/.ssm_config in every release from 1.0.0 through 1.0.9.

    Changing this value is a breaking change: users already have a file with this
    name on disk. It requires explicit approval, a minor version bump and a
    migration note in the changelog.
    """
    assert os.path.basename(CONFIG["default_config_file"]) == ".ssm_config"
