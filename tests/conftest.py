import shutil
from dataclasses import dataclass
from pathlib import Path

import pytest

from bruteforce_demo.database import initialize


@dataclass
class FakeClock:
    now: float = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture(scope="session")
def template_db(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("template") / "demo.db"
    initialize(path)
    return path


@pytest.fixture
def db(tmp_path: Path, template_db: Path) -> Path:
    path = tmp_path / "demo.db"
    shutil.copyfile(template_db, path)
    return path


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()
