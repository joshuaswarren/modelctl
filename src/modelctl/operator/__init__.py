"""Secure operator action preparation and delivery."""

from modelctl.operator.actions import ACTION_SPECS, ALLOWED_ACTION_ENDPOINTS, ActionSpec
from modelctl.operator.cli import (
    ActionDeliveryError,
    ActionResult,
    load_operator_signer,
    main,
    prepare_signed_action,
    require_mtls_context,
    run_action,
    write_action_receipt,
    write_failure_receipt,
)
from modelctl.operator.sequence import SequenceAllocator

__all__ = [
    "ACTION_SPECS",
    "ALLOWED_ACTION_ENDPOINTS",
    "ActionDeliveryError",
    "ActionResult",
    "ActionSpec",
    "SequenceAllocator",
    "load_operator_signer",
    "main",
    "prepare_signed_action",
    "require_mtls_context",
    "run_action",
    "write_action_receipt",
    "write_failure_receipt",
]
