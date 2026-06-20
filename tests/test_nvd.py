from bot_security_news.collectors.nvd import _parse_vulnerability


def test_parse_vulnerability_accepts_nvd_v2_reference_list():
    item = _parse_vulnerability(
        {
            "cve": {
                "id": "CVE-2026-0001",
                "published": "2026-06-20T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                "references": [{"url": "https://example.test/advisory"}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {"baseScore": 9.8},
                            "baseSeverity": "CRITICAL",
                        }
                    ]
                },
            }
        }
    )

    assert item.url == "https://example.test/advisory"
    assert item.cvss_score == 9.8
    assert item.cvss_severity == "CRITICAL"
