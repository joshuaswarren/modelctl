import pytest
from pydantic import ValidationError

from modelctl.domain.workload import WorkloadClass


def test_unknown_workload_class_fails_at_parse_time() -> None:
    with pytest.raises(ValidationError):
        WorkloadClass(name="unlisted-role")
