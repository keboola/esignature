"""The opt-in controls and status labels are visible without leaking service configuration."""

from playwright.sync_api import Page, expect

from tests.e2e.test_editor import blank_pdf, write


def test_online_checks_are_off_by_default_and_report_distinct_statuses(page: Page, base_url, tmp_path):
    page.route("**/api/capabilities", lambda route: route.fulfill(json={
        "trust_configured": True, "revocation_configured": True, "timestamp_configured": True,
    }))
    page.route("**/api/validate", lambda route: route.fulfill(json={
        "signed": True, "signature_count": 1, "signatures": [{
            "field_name": "Alice", "integrity": "valid", "cryptography": "valid", "modifications": "allowed",
            "certificate_trust": {"status": "trusted", "checked_at": "2026-10-30T10:00:00Z"},
            "revocation": {"status": "unknown", "message": "CRL unavailable"},
            "timestamp": {"status": "valid", "time": "2026-10-29T10:00:00Z",
                          "certificate_trust": {"status": "untrusted"},
                          "revocation": {"status": "not_checked"}},
        }],
    }))
    page.goto(base_url)
    page.set_input_files("#pdf-input", write(tmp_path, "doc.pdf", blank_pdf(1)))
    page.get_by_text("Certificate checks & timestamp").click()
    expect(page.locator("#online-revocation")).to_be_enabled()
    expect(page.locator("#online-revocation")).not_to_be_checked()
    expect(page.locator("#opt-timestamp")).to_be_enabled()
    expect(page.locator("#opt-timestamp")).not_to_be_checked()
    page.click("#validate")
    results = page.locator("#validation-results")
    expect(results).to_contain_text("Certificate chain: Trusted")
    expect(results).to_contain_text("Certificate revocation: Unknown")
    expect(results).to_contain_text("CRL unavailable")
    expect(results).to_contain_text("Timestamp certificate chain: Untrusted")
    expect(results).to_contain_text("Timestamp certificate revocation: Not checked")
    page.check("#online-revocation")
    expect(results).to_be_hidden()


def test_timestamp_and_online_checks_explain_missing_configuration(page: Page, base_url):
    page.goto(base_url)
    page.get_by_text("Certificate checks & timestamp").click()
    expect(page.locator("#online-revocation")).to_be_disabled()
    expect(page.locator("#revocation-setup")).to_contain_text("Configure trust roots and CRL services")
    expect(page.locator("#opt-timestamp")).to_be_disabled()
    expect(page.locator("#timestamp-setup")).to_contain_text("Configure a timestamp service and trust roots")
