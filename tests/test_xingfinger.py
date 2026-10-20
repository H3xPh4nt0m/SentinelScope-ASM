"""XingFinger adapter: real CLI contract (-u <url> -j, single JSON object)."""
import json

from app.scanners.crawling import XingFingerTool

DVWA_SAMPLE = {
    "url": "http://192.168.245.131/dvwa/login.php",
    "cms": "php,apache-web-server,mod_dav,apache-http,ubuntu,dvwa,ubuntu-system,apache http server",
    "server": "Apache/2.2.8 (Ubuntu) DAV/2",
    "status_code": 200,
    "length": 1289,
    "title": "Damn Vulnerable Web App (DVWA) - Login",
}


def test_version_is_blank_because_cli_has_no_version_flag():
    assert XingFingerTool().version() == ""


def test_command_uses_documented_json_flag():
    command = XingFingerTool().build_command({"target": "http://192.168.245.131/dvwa/login.php"})
    assert command == ["-u", "http://192.168.245.131/dvwa/login.php", "-j"]


def test_normalize_real_sample_yields_webapp_with_technologies():
    records = XingFingerTool().normalize(json.dumps(DVWA_SAMPLE),
                                         {"target": DVWA_SAMPLE["url"]})
    assert len(records) == 1
    record = records[0]
    assert record["asset_type"] == "webapp"
    assert record["name"] == DVWA_SAMPLE["url"]
    assert record["webapp"]["title"] == "Damn Vulnerable Web App (DVWA) - Login"
    assert record["webapp"]["webserver"] == "Apache/2.2.8 (Ubuntu) DAV/2"
    assert record["webapp"]["status_code"] == 200
    techs = record["webapp"]["technologies"]
    assert "dvwa" in techs and "php" in techs and "apache-web-server" in techs


def test_technologies_are_trimmed_and_deduplicated():
    sample = dict(DVWA_SAMPLE, cms=" php , php, dvwa ,, dvwa")
    techs = XingFingerTool().normalize(json.dumps(sample),
                                       {"target": sample["url"]})[0]["webapp"]["technologies"]
    assert techs == ["php", "dvwa"]


def test_empty_cms_yields_no_records():
    sample = dict(DVWA_SAMPLE, cms="")
    assert XingFingerTool().normalize(json.dumps(sample), {"target": sample["url"]}) == []


def test_malformed_output_yields_no_records():
    assert XingFingerTool().normalize("not json", {"target": "http://x/"}) == []
    assert XingFingerTool().normalize("", {"target": "http://x/"}) == []
