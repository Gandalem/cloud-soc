"""Print actionable compatibility results before certificate preparation."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from cloud_soc.deployment.dependencies import DependencyError, check
from cloud_soc.deployment.host import Docker, DockerCommandError

if __name__ == '__main__':
    try:
        check(Docker())
    except (DependencyError, DockerCommandError) as error:
        sys.exit(str(error) + '\n업데이트 안내: https://docs.docker.com/engine/install/ubuntu/')
