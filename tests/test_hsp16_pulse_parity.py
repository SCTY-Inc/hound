"""HSP-16: shadow parity superseded by the 2026-08-04 owner replan."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_hsp16_pulse_parity_supersession_is_durably_recorded() -> None:
    vision = (ROOT / "VISION.md").read_text()
    marker = "| HSP-16 | **Superseded by owner decision (2026-08-04 full-cutover replan"
    assert marker in vision, "VISION.md must carry the amended supersession row"
    parity = ROOT / "migration" / "evidence" / "lanes" / "pulse" / "parity.md"
    assert parity.is_file()
    text = parity.read_text().lower()
    assert "superseded" in text and "replan" in text, "parity.md must state the supersession in its own words"
