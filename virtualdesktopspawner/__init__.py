# from ._version import version as __version__
from .awsec2 import Ec2SsmInstance
from .kubeec2spawner import Ec2DesktopSpawner

__all__ = [
    # "__version__",
    "Ec2SsmInstance",
    "Ec2DesktopSpawner",
]
