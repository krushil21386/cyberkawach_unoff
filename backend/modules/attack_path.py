"""
Dynamic Attack Path Reconstruction Engine.

Reconstructs the multi-stage cyber fraud kill-chain tailored to the detected
fraud category and correlates it with the victim's current interaction state.

Kill-chain Stages:
1. LURE: Initial social engineering contact (SMS/WhatsApp/Email)
2. TRAP: Deceptive host, typosquatted domain, or spoofed caller
3. HARVEST: Credential collection, OTP theft, fake fee, or malicious APK
4. IMPACT: Unauthorized fund drain, account takeover, or identity extortion
"""

from __future__ import annotations

from typing import Optional
from backend.models.evidence import IncidentEvidence, UserState


_CATEGORY_KILL_CHAINS: dict[str, list[dict[str, str]]] = {
    "banking": [
        {
            "stage": "Lure",
            "title": "Urgent Banking Notification",
            "description": "Victim receives a high-urgency message alleging KYC suspension, account block, or unverified transaction.",
        },
        {
            "stage": "Trap",
            "title": "Spoofed Banking Portal",
            "description": "Victim is directed to a lookalike domain (e.g. .xyz / .top) visually mimicking the bank's login page.",
        },
        {
            "stage": "Harvest",
            "title": "Credential & OTP Harvesting",
            "description": "The fake portal prompts for NetBanking user ID, password, debit card details, and real-time OTP.",
        },
        {
            "stage": "Impact",
            "title": "Unauthorized Account Drain",
            "description": "Attacker immediately adds a beneficiary or initiates IMPS/UPI transfers draining the victim's account.",
        },
    ],
    "electricity": [
        {
            "stage": "Lure",
            "title": "Power Disconnection Threat",
            "description": "SMS warns electricity will be disconnected tonight at 9:30 PM due to unpaid bill; provides a 10-digit mobile number or link.",
        },
        {
            "stage": "Trap",
            "title": "Fake Discom Gateway or Remote Tool",
            "description": "Victim calls the unofficial number or opens a deceptive payment link outside official utility websites.",
        },
        {
            "stage": "Harvest",
            "title": "Token Recharge / Remote Access",
            "description": "Attacker asks for a token ₹10 recharge or instructs victim to install AnyDesk/QuickSupport to 'update the bill'.",
        },
        {
            "stage": "Impact",
            "title": "Device Takeover & UPI Theft",
            "description": "Attacker views the victim entering banking PIN or drains funds using device remote control.",
        },
    ],
    "courier": [
        {
            "stage": "Lure",
            "title": "Failed Parcel Delivery",
            "description": "Victim receives SMS claiming a parcel (India Post / courier) could not be delivered due to incomplete address.",
        },
        {
            "stage": "Trap",
            "title": "Spoofed Logistics Portal",
            "description": "Victim is directed to an unofficial tracking portal demanding address confirmation.",
        },
        {
            "stage": "Harvest",
            "title": "Redelivery Fee & Card Harvest",
            "description": "Page demands a nominal re-delivery fee (₹5 to ₹25) and collects credit/debit card numbers and CVVs.",
        },
        {
            "stage": "Impact",
            "title": "Card Fraud & Recurring Debits",
            "description": "Attacker charges international fraudulent transactions using the intercepted card credentials.",
        },
    ],
    "digital_arrest": [
        {
            "stage": "Lure",
            "title": "Legal Coercion & Intimidation",
            "description": "Scammers impersonate Police, CBI, ED, or Customs alleging a parcel with drugs/passports in the victim's name.",
        },
        {
            "stage": "Trap",
            "title": "Video Call Isolation ('Digital Arrest')",
            "description": "Victim is coerced into a Skype or WhatsApp video call with fake police backdrops and fake warrants.",
        },
        {
            "stage": "Harvest",
            "title": "Asset Verification Demand",
            "description": "Attacker claims funds must be temporarily transferred to an 'RBI Government Verification Account'.",
        },
        {
            "stage": "Impact",
            "title": "Catastrophic Fund Liquidation",
            "description": "Victim transfers fixed deposits and savings to mule accounts; scammers terminate contact.",
        },
    ],
    "lottery_prize": [
        {
            "stage": "Lure",
            "title": "Unsolicited Prize / Lucky Draw",
            "description": "Message claims victim has won a massive cash prize, lottery, or luxury reward (e.g. KBC).",
        },
        {
            "stage": "Trap",
            "title": "Fake Claims Department",
            "description": "Victim contacts the fraudster's WhatsApp or fills an unverified prize claim form.",
        },
        {
            "stage": "Harvest",
            "title": "Processing / GST Fee Demand",
            "description": "Attacker requests advance fees for 'tax clearance', 'registration', or 'file charges'.",
        },
        {
            "stage": "Impact",
            "title": "Advance Fee Loss",
            "description": "Victim pays successive advance fees until realizing no prize exists.",
        },
    ],
    "job_offer": [
        {
            "stage": "Lure",
            "title": "High-Pay Part-Time Task",
            "description": "Unsolicited offer promising ₹3,000–₹10,000 daily for liking videos, reviewing hotels, or typing data.",
        },
        {
            "stage": "Trap",
            "title": "Telegram / WhatsApp Task Group",
            "description": "Victim is added to a staged group where bots pretend to celebrate instant payouts.",
        },
        {
            "stage": "Harvest",
            "title": "Prepaid 'Crypto / Merchant' Tasks",
            "description": "Initial small payouts build trust; victim is then prompted to deposit larger sums for 'VIP high-commission tasks'.",
        },
        {
            "stage": "Impact",
            "title": "Account Freeze & Fund Extortion",
            "description": "Withdrawals are blocked with demands for 'unfreeze penalties' before the scammers disappear.",
        },
    ],
    "generic": [
        {
            "stage": "Lure",
            "title": "Social Engineering Lure",
            "description": "Deceptive message engineered to induce urgency, fear, or reward.",
        },
        {
            "stage": "Trap",
            "title": "Deceptive Channel / Infrastructure",
            "description": "Directs victim to an untrusted domain, personal mobile, or suspicious link.",
        },
        {
            "stage": "Harvest",
            "title": "Data or Payment Harvesting",
            "description": "Attempts to capture sensitive identity, credentials, or upfront payments.",
        },
        {
            "stage": "Impact",
            "title": "Financial or Identity Compromise",
            "description": "Unauthorized access, monetary loss, or unauthorized identity usage.",
        },
    ],
}

# Mapping user interaction state to kill chain stage index (0-3)
_STATE_TO_STAGE_INDEX: dict[UserState, int] = {
    UserState.RECEIVED: 0,
    UserState.CLICKED: 1,
    UserState.ENTERED_CREDENTIALS: 2,
    UserState.PAID: 3,
}


def reconstruct_attack_path(
    evidence: IncidentEvidence,
    user_state: Optional[UserState] = None,
) -> dict:
    """
    Reconstruct the attack path stages based on detected fraud category and current user state.
    Returns:
        dict with:
            - category: str
            - stages: list of {stage, title, description, status}
            - current_stage_index: int (0 to 3)
            - text_steps: list[str] (for backwards compatibility with GeminiExplanation)
    """
    category = (evidence.fraud_category or "generic").lower()
    if category not in _CATEGORY_KILL_CHAINS:
        category = "generic"

    state = user_state or UserState.RECEIVED
    current_index = _STATE_TO_STAGE_INDEX.get(state, 0)

    raw_stages = _CATEGORY_KILL_CHAINS[category]
    stages = []
    text_steps = []

    for i, s in enumerate(raw_stages):
        if i < current_index:
            status = "PASSED"
        elif i == current_index:
            status = "CURRENT_RISK"
        else:
            status = "PREVENTED"

        stages.append({
            "stage": s["stage"],
            "title": s["title"],
            "description": s["description"],
            "status": status,
            "step_number": i + 1,
        })
        text_steps.append(f"Stage {i+1} ({s['stage']}): {s['title']} — {s['description']}")

    return {
        "category": category,
        "stages": stages,
        "current_stage_index": current_index,
        "text_steps": text_steps,
    }
