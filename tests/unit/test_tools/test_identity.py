"""Unit tests for identity tools."""



class TestUserContext:
    async def test_known_user_returns_profile(self):
        from sentinel.tools.identity import _execute_user_context

        result = await _execute_user_context({"email": "alice.hr@acmecorp.com"})
        assert result["email"] == "alice.hr@acmecorp.com"
        assert "department" in result
        assert "mfa_enabled" in result
        assert "registered_devices" in result
        assert "groups" in result

    async def test_case_insensitive_email(self):
        from sentinel.tools.identity import _execute_user_context

        result = await _execute_user_context({"email": "ALICE.HR@ACMECORP.COM"})
        assert "department" in result

    async def test_unknown_user_returns_not_found(self):
        from sentinel.tools.identity import _execute_user_context

        result = await _execute_user_context({"email": "nobody@corp.com"})
        assert result["code"] == "NOT_FOUND"

    async def test_invalid_email_returns_error(self):
        from sentinel.tools.identity import _execute_user_context

        result = await _execute_user_context({"email": "notanemail"})
        assert result["code"] == "INVALID_PARAMETER"

    async def test_empty_email_returns_error(self):
        from sentinel.tools.identity import _execute_user_context

        result = await _execute_user_context({"email": ""})
        assert result["code"] == "INVALID_PARAMETER"


class TestRecentLogins:
    async def test_returns_login_list(self):
        from sentinel.tools.identity import _execute_recent_logins

        result = await _execute_recent_logins({"email": "alice.hr@acmecorp.com", "days": 7})
        assert isinstance(result["logins"], list)
        assert result["total_events"] == len(result["logins"])

    async def test_bob_has_suspicious_login(self):
        from sentinel.tools.identity import _execute_recent_logins

        result = await _execute_recent_logins({"email": "bob.finance@acmecorp.com", "days": 7})
        ips = [login["ip_address"] for login in result["logins"]]
        assert "185.220.101.34" in ips

    async def test_days_capped_at_90(self):
        from sentinel.tools.identity import _execute_recent_logins

        result = await _execute_recent_logins({"email": "alice.hr@acmecorp.com", "days": 9999})
        assert result.get("days", 90) <= 90


class TestRiskScoreUser:
    async def test_returns_score_and_level(self):
        from sentinel.tools.identity import _execute_risk_score_user

        result = await _execute_risk_score_user({"email": "bob.finance@acmecorp.com"})
        assert "score" in result
        assert "level" in result
        assert 0 <= result["score"] <= 100

    async def test_bob_has_high_risk(self):
        from sentinel.tools.identity import _execute_risk_score_user

        result = await _execute_risk_score_user({"email": "bob.finance@acmecorp.com"})
        assert result["level"] in ("high", "critical")
        assert result["score"] >= 60

    async def test_alice_has_low_risk(self):
        from sentinel.tools.identity import _execute_risk_score_user

        result = await _execute_risk_score_user({"email": "alice.hr@acmecorp.com"})
        assert result["score"] < 60
