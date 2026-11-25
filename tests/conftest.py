from pathlib import Path
from uuid import uuid4

import pytest

from chinescan.core.organizations import OrganizationService
from chinescan.core.storage.sqlite import SQLiteRepository


def authorize_test_operator(repository: SQLiteRepository) -> tuple[str, str]:
    """Explicitly scope a unit workflow to a synthetic local operator principal."""
    identity_id = str(uuid4())
    user, organization = OrganizationService(repository).ensure_operator(
        f"test-operator-{identity_id[:8]}@example.test",
        f"test-auth-epoch-{identity_id}",
        identity_id,
    )
    repository.bind_local_operator_context()
    return user["id"], organization["id"]


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("real scanner integration")
    group.addoption(
        "--run-real-scanners",
        action="store_true",
        default=False,
        help="run opt-in tests against installed real scanner binaries",
    )
    group.addoption(
        "--require-real-scanners",
        action="store_true",
        default=False,
        help="run real scanner tests and fail when required tools/assets are missing",
    )


def pytest_configure(config: pytest.Config) -> None:
    basetemp = config.option.basetemp
    if basetemp is not None:
        repository_root = Path(__file__).resolve().parents[1]
        resolved_basetemp = Path(basetemp).resolve()
        if resolved_basetemp == repository_root or repository_root in resolved_basetemp.parents:
            raise pytest.UsageError(
                "--basetemp must resolve outside the repository; use the OS temp directory"
            )
    config.addinivalue_line(
        "markers", "real_scanner: opt-in integration tests that execute real scanner binaries"
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--run-real-scanners") or config.getoption("--require-real-scanners"):
        return
    deselected = [item for item in items if "real_scanner" in item.keywords]
    items[:] = [item for item in items if "real_scanner" not in item.keywords]
    config.hook.pytest_deselected(items=deselected)


@pytest.fixture(autouse=True)
def isolated_operator_credential_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CHINESCAN_OPERATOR_CREDENTIAL_FILE", raising=False)


@pytest.fixture
def local_operator_credentials(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Give CLI integration tests a verified local principal without relaxing storage defaults."""
    from chinescan.core.accounts import create_operator, ensure_operator_identity_id

    credential_path = tmp_path / "operator.json"
    create_operator(credential_path, "cli-test@example.test", "synthetic-cli-passphrase-77!")
    ensure_operator_identity_id(credential_path, str(uuid4()))
    monkeypatch.setenv("CHINESCAN_OPERATOR_CREDENTIAL_FILE", str(credential_path))
    return credential_path


@pytest.fixture
def authorize_local_repository(local_operator_credentials: Path):
    """Bind an explicitly bootstrapped test operator to a repository instance."""
    from chinescan.core.organizations import OrganizationService
    from chinescan.core.storage.sqlite import SQLiteRepository
    from chinescan.web.auth import operator_auth_epoch, operator_email, operator_identity_id

    def authorize(repository: SQLiteRepository) -> None:
        OrganizationService(repository).ensure_operator(
            operator_email(local_operator_credentials),
            operator_auth_epoch(local_operator_credentials),
            operator_identity_id(local_operator_credentials),
        )
        repository.bind_local_operator_context()

    return authorize


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    return tmp_path / "config.toml"


@pytest.fixture
def repository(tmp_path: Path) -> SQLiteRepository:
    repo = SQLiteRepository(tmp_path / "records.sqlite3")
    identity_id = str(uuid4())
    OrganizationService(repo).ensure_operator(
        f"test-{identity_id[:8]}@example.test", "test-auth-epoch-0001", identity_id
    )
    # Test records use an explicit personal-organization principal. The production
    # repository still denies all generic access when no principal context is active.
    repo.bind_local_operator_context()
    yield repo
    repo.close()


@pytest.fixture(autouse=True)
def isolated_reports_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CHINESCAN_REPORTS_DIR", str(tmp_path / "auto-reports"))
