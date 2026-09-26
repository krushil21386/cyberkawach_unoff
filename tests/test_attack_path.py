"""
Unit tests for Dynamic Attack Path Reconstruction.
"""

import pytest
from backend.models.evidence import IncidentEvidence, UserState
from backend.modules.attack_path import reconstruct_attack_path


def test_reconstruct_attack_path_banking():
    evidence = IncidentEvidence(
        message="SBI Account blocked update KYC",
        fraud_category="banking",
    )
    res = reconstruct_attack_path(evidence, UserState.RECEIVED)

    assert res["category"] == "banking"
    assert res["current_stage_index"] == 0
    assert len(res["stages"]) == 4

    # Stage 1 should be current risk, subsequent should be prevented
    assert res["stages"][0]["status"] == "CURRENT_RISK"
    assert res["stages"][1]["status"] == "PREVENTED"
    assert res["stages"][2]["status"] == "PREVENTED"
    assert res["stages"][3]["status"] == "PREVENTED"
    assert len(res["text_steps"]) == 4


def test_reconstruct_attack_path_electricity_clicked_link():
    evidence = IncidentEvidence(
        message="Bijli bill unpaid connection cut tonight at 9:30 PM",
        fraud_category="electricity",
    )
    res = reconstruct_attack_path(evidence, UserState.CLICKED)

    assert res["category"] == "electricity"
    assert res["current_stage_index"] == 1
    assert res["stages"][0]["status"] == "PASSED"
    assert res["stages"][1]["status"] == "CURRENT_RISK"
    assert res["stages"][2]["status"] == "PREVENTED"
    assert res["stages"][3]["status"] == "PREVENTED"


def test_reconstruct_attack_path_digital_arrest_transferred_funds():
    evidence = IncidentEvidence(
        message="CBI narcotics parcel warrant video call",
        fraud_category="digital_arrest",
    )
    res = reconstruct_attack_path(evidence, UserState.PAID)

    assert res["category"] == "digital_arrest"
    assert res["current_stage_index"] == 3
    assert res["stages"][0]["status"] == "PASSED"
    assert res["stages"][1]["status"] == "PASSED"
    assert res["stages"][2]["status"] == "PASSED"
    assert res["stages"][3]["status"] == "CURRENT_RISK"


def test_reconstruct_attack_path_unknown_category_fallback():
    evidence = IncidentEvidence(
        message="Random unknown message",
        fraud_category="unknown_category_xyz",
    )
    res = reconstruct_attack_path(evidence, UserState.ENTERED_CREDENTIALS)

    assert res["category"] == "generic"
    assert res["current_stage_index"] == 2
    assert res["stages"][0]["status"] == "PASSED"
    assert res["stages"][1]["status"] == "PASSED"
    assert res["stages"][2]["status"] == "CURRENT_RISK"
    assert res["stages"][3]["status"] == "PREVENTED"
