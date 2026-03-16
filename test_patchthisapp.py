"""Tests for patchthisapp CSV output format and data extraction."""

import json
import tempfile
from pathlib import Path

import pandas as pd
import pytest

from patchthisapp import extract_entry_data, main, process_nvd_files

# The canonical column lists for CSV output. If these change, the test
# must be updated intentionally — that's the point.
EXPECTED_COLUMNS_WITH_EPSS = [
    "CVE", "CVSS Score", "CVSS_Vector", "EPSS", "CWE",
    "Description", "Published", "Source", "CPE", "Vendor", "Affected Products",
]
EXPECTED_COLUMNS_WITHOUT_EPSS = [
    "CVE", "CVSS Score", "CVSS_Vector", "CWE",
    "Description", "Published", "Source", "CPE", "Vendor", "Affected Products",
]


def _make_nvd_entry(
    cve_id="CVE-2024-0001",
    base_score=9.8,
    cwe_id="CWE-79",
    description="Test vulnerability",
    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cpe="cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
    published="2024-01-15T00:00:00.000",
):
    """Build a minimal NVD JSON entry for testing."""
    return {
        "cve": {
            "id": cve_id,
            "sourceIdentifier": "test@test.com",
            "published": published,
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": base_score,
                            "baseSeverity": "CRITICAL",
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "NONE",
                            "userInteraction": "NONE",
                            "scope": "UNCHANGED",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "HIGH",
                            "availabilityImpact": "HIGH",
                            "vectorString": vector,
                        }
                    }
                ]
            },
            "weaknesses": [
                {"description": [{"lang": "en", "value": cwe_id}]}
            ],
            "descriptions": [{"lang": "en", "value": description}],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"vulnerable": True, "criteria": cpe}
                            ]
                        }
                    ]
                }
            ],
        }
    }


class TestExtractEntryData:
    """Tests for the extract_entry_data function."""

    def test_cwe_is_extracted(self):
        entry = _make_nvd_entry(cwe_id="CWE-89")
        result = extract_entry_data(entry)
        assert result["cwe"] == "CWE-89"

    def test_cwe_missing_defaults(self):
        entry = _make_nvd_entry()
        entry["cve"]["weaknesses"] = []
        result = extract_entry_data(entry)
        assert result["cwe"] == "Missing_Data"

    def test_all_expected_fields_present(self):
        entry = _make_nvd_entry()
        result = extract_entry_data(entry)
        required_keys = {"cve", "cwe", "description", "base_score", "cvss_vector", "cpe", "vendor", "product", "published_date"}
        assert required_keys.issubset(result.keys())

    def test_cpe_vendor_product_parsed(self):
        entry = _make_nvd_entry(cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        result = extract_entry_data(entry)
        assert result["vendor"] == "Apache"
        assert result["product"] == "Http Server"


class TestCSVOutputFormat:
    """Regression tests to ensure CSV column format doesn't change unexpectedly."""

    @pytest.fixture()
    def workspace(self, tmp_path):
        """Create minimal input files for a full pipeline run."""
        # NVD data
        entries = [_make_nvd_entry(), _make_nvd_entry(cve_id="CVE-2024-0002", cwe_id="CWE-89")]
        nvd_path = tmp_path / "nvd.jsonl"
        nvd_path.write_text(json.dumps(entries))

        # Metasploit
        meta_path = tmp_path / "metasploit.txt"
        meta_path.write_text("CVE-2024-0001\n")

        # Nuclei
        nuclei_path = tmp_path / "nuclei.txt"
        nuclei_path.write_text("CVE-2024-0002\n")

        # CISA
        cisa_path = tmp_path / "cisa.csv"
        cisa_path.write_text("cveID,vendorProject,product,cwes\nCVE-2024-0001,Vendor,Product,CWE-79\n")

        # EPSS
        epss_path = tmp_path / "epss.csv"
        epss_path.write_text(
            "#model_version:v2024.01.01,score_date:2024-01-15\n"
            "cve,epss,percentile\n"
            "CVE-2024-0001,0.97,0.99\n"
            "CVE-2024-0002,0.50,0.80\n"
        )

        output_path = tmp_path / "data" / "data.csv"
        return {
            "tmp_path": tmp_path,
            "nvd": nvd_path,
            "metasploit": meta_path,
            "nuclei": nuclei_path,
            "cisa": cisa_path,
            "epss": epss_path,
            "output": output_path,
        }

    def test_columns_with_epss(self, workspace, monkeypatch):
        """CSV output must contain exactly these columns (with EPSS data)."""
        monkeypatch.chdir(workspace["tmp_path"])
        args = [
            "patchthisapp",
            "--metasploit", str(workspace["metasploit"]),
            "--nuclei", str(workspace["nuclei"]),
            "--cisa", str(workspace["cisa"]),
            "--epss", str(workspace["epss"]),
            "--nvd", str(workspace["nvd"]),
            "--output", str(workspace["output"]),
            "--epss-threshold", "0.5",
        ]
        monkeypatch.setattr("sys.argv", args)
        main()
        df = pd.read_csv(workspace["output"])
        assert list(df.columns) == EXPECTED_COLUMNS_WITH_EPSS

    def test_columns_without_epss(self, workspace, monkeypatch):
        """CSV output must contain exactly these columns (no EPSS data)."""
        # Write an empty EPSS file (header only)
        workspace["epss"].write_text(
            "#model_version:v2024.01.01,score_date:2024-01-15\n"
            "cve,epss,percentile\n"
        )
        monkeypatch.chdir(workspace["tmp_path"])
        args = [
            "patchthisapp",
            "--metasploit", str(workspace["metasploit"]),
            "--nuclei", str(workspace["nuclei"]),
            "--cisa", str(workspace["cisa"]),
            "--epss", str(workspace["epss"]),
            "--nvd", str(workspace["nvd"]),
            "--output", str(workspace["output"]),
        ]
        monkeypatch.setattr("sys.argv", args)
        main()
        df = pd.read_csv(workspace["output"])
        assert list(df.columns) == EXPECTED_COLUMNS_WITHOUT_EPSS

    def test_cwe_values_in_output(self, workspace, monkeypatch):
        """CWE values from NVD must appear in the output CSV."""
        monkeypatch.chdir(workspace["tmp_path"])
        args = [
            "patchthisapp",
            "--metasploit", str(workspace["metasploit"]),
            "--nuclei", str(workspace["nuclei"]),
            "--cisa", str(workspace["cisa"]),
            "--epss", str(workspace["epss"]),
            "--nvd", str(workspace["nvd"]),
            "--output", str(workspace["output"]),
            "--epss-threshold", "0.5",
        ]
        monkeypatch.setattr("sys.argv", args)
        main()
        df = pd.read_csv(workspace["output"])
        cwe_values = set(df["CWE"].values)
        assert "CWE-79" in cwe_values or "CWE-89" in cwe_values
