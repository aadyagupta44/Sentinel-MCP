"""Unit tests for threat intelligence tools."""


class TestEnrichIOC:
    async def test_known_malicious_ip(self):
        from sentinel.tools.intel import _execute_enrich_ioc

        result = await _execute_enrich_ioc({"indicator": "185.220.101.34", "indicator_type": "ip"})
        assert result["verdict"] == "malicious"
        assert result["confidence"] >= 0.9
        assert "details" in result
        assert result["indicator"] == "185.220.101.34"

    async def test_clean_ip(self):
        from sentinel.tools.intel import _execute_enrich_ioc

        result = await _execute_enrich_ioc({"indicator": "8.8.8.8", "indicator_type": "ip"})
        assert result["verdict"] == "clean"
        assert result["confidence"] == 1.0

    async def test_known_malicious_hash(self):
        from sentinel.tools.intel import _execute_enrich_ioc

        result = await _execute_enrich_ioc(
            {
                "indicator": "44d88612fea8a8f36de82e1278abb02f",
                "indicator_type": "hash",
            }
        )
        assert result["verdict"] == "malicious"

    async def test_unknown_indicator_returns_unknown(self):
        from sentinel.tools.intel import _execute_enrich_ioc

        result = await _execute_enrich_ioc({"indicator": "1.2.3.4", "indicator_type": "ip"})
        assert result["verdict"] == "unknown"
        assert result["confidence"] == 0.0

    async def test_invalid_type_returns_error(self):
        from sentinel.tools.intel import _execute_enrich_ioc

        result = await _execute_enrich_ioc({"indicator": "1.2.3.4", "indicator_type": "banana"})
        assert result["code"] == "INVALID_PARAMETER"

    async def test_empty_indicator_returns_error(self):
        from sentinel.tools.intel import _execute_enrich_ioc

        result = await _execute_enrich_ioc({"indicator": "", "indicator_type": "ip"})
        assert result["code"] == "MISSING_PARAMETER"

    async def test_all_valid_types_accepted(self):
        from sentinel.tools.intel import _execute_enrich_ioc

        for ioc_type in ("ip", "domain", "hash", "url"):
            result = await _execute_enrich_ioc({"indicator": "test", "indicator_type": ioc_type})
            assert "code" not in result or result.get("code") != "INVALID_PARAMETER"

    async def test_response_always_has_sources_checked(self):
        from sentinel.tools.intel import _execute_enrich_ioc

        result = await _execute_enrich_ioc(
            {"indicator": "anything.example.com", "indicator_type": "domain"}
        )
        assert "sources_checked" in result
        assert isinstance(result["sources_checked"], list)


class TestThreatHunt:
    async def test_finds_indicator_timeline(self):
        from sentinel.tools.intel import _execute_threat_hunt

        result = await _execute_threat_hunt({"indicator": "185.220.101.34", "look_back_days": 30})
        assert result["indicator"] == "185.220.101.34"
        assert result["total_appearances"] == len(result["appearances"])
        assert result["total_appearances"] >= 1
        assert result["first_seen"] is not None
        assert result["last_seen"] is not None
        assert result["first_seen"] <= result["last_seen"]

    async def test_empty_indicator_returns_error(self):
        from sentinel.tools.intel import _execute_threat_hunt

        result = await _execute_threat_hunt({"indicator": ""})
        assert result["code"] == "MISSING_PARAMETER"

    async def test_lookback_is_capped(self):
        from sentinel.tools.intel import _execute_threat_hunt

        result = await _execute_threat_hunt(
            {"indicator": "185.220.101.34", "look_back_days": 99999}
        )
        assert result["look_back_days"] <= 365

    async def test_no_appearances_for_unknown_indicator(self):
        from sentinel.tools.intel import _execute_threat_hunt

        result = await _execute_threat_hunt({"indicator": "zzz-never-seen", "look_back_days": 30})
        assert result["total_appearances"] == 0
        assert result["first_seen"] is None


class TestMitreTechnique:
    async def test_known_technique_returns_details(self):
        from sentinel.tools.intel import _execute_mitre_technique

        result = await _execute_mitre_technique({"technique_id": "T1059.001"})
        assert result["technique_id"] == "T1059.001"
        assert "name" in result
        assert "detection" in result
        assert "mitigation" in result

    async def test_case_insensitive(self):
        from sentinel.tools.intel import _execute_mitre_technique

        result = await _execute_mitre_technique({"technique_id": "t1078"})
        assert "technique_id" in result

    async def test_invalid_id_returns_error(self):
        from sentinel.tools.intel import _execute_mitre_technique

        result = await _execute_mitre_technique({"technique_id": "NOT-A-TECHNIQUE"})
        assert result["code"] == "INVALID_PARAMETER"

    async def test_valid_but_unknown_id_returns_not_found(self):
        from sentinel.tools.intel import _execute_mitre_technique

        result = await _execute_mitre_technique({"technique_id": "T9999.999"})
        assert result["code"] == "NOT_FOUND"
