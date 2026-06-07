"""Unit tests for write tool two-step confirmation framework."""

from sentinel.tools import confirmation as conf


class TestCreateProposal:
    async def test_returns_proposed_action_structure(self):
        proposal = await conf.create_proposal(
            tool_name="isolate_device",
            analyst_id="analyst@test.com",
            target="LAPTOP-001",
            description="Isolate LAPTOP-001",
            warning="This will cut network access",
            parameters={"hostname": "LAPTOP-001", "reason": "malware"},
        )
        assert proposal["action_type"] == "isolate_device"
        assert "confirmation_token" in proposal
        assert "expires_at" in proposal
        assert "instructions" in proposal
        assert len(proposal["confirmation_token"]) > 20

    async def test_tokens_are_unique(self):
        tokens = set()
        for _ in range(5):
            p = await conf.create_proposal(
                tool_name="block_ip",
                analyst_id="analyst@test.com",
                target="1.2.3.4",
                description="Block IP",
                warning="",
                parameters={"ip_address": "1.2.3.4", "reason": "test"},
            )
            tokens.add(p["confirmation_token"])
        assert len(tokens) == 5


class TestExecuteConfirmed:
    async def test_valid_token_executes(self):
        proposal = await conf.create_proposal(
            tool_name="block_ip",
            analyst_id="analyst@test.com",
            target="1.2.3.4",
            description="Block IP",
            warning="",
            parameters={"ip_address": "1.2.3.4", "reason": "test"},
        )
        token = proposal["confirmation_token"]

        async def executor(params):
            return {"blocked": params["ip_address"]}

        result = await conf.execute_confirmed("block_ip", token, "analyst@test.com", executor)
        assert result["action_type"] == "block_ip"
        assert result["result"]["blocked"] == "1.2.3.4"

    async def test_invalid_token_returns_error(self):
        async def executor(params):
            return {}

        result = await conf.execute_confirmed(
            "block_ip", "invalid-token-xyz", "analyst@test.com", executor
        )
        assert result["code"] == "INVALID_TOKEN"

    async def test_token_cannot_be_reused(self):
        proposal = await conf.create_proposal(
            tool_name="disable_user",
            analyst_id="analyst@test.com",
            target="alice@corp.com",
            description="Disable Alice",
            warning="",
            parameters={"email": "alice@corp.com", "reason": "test"},
        )
        token = proposal["confirmation_token"]

        async def executor(params):
            return {"disabled": True}

        # First use — should succeed
        result1 = await conf.execute_confirmed("disable_user", token, "analyst@test.com", executor)
        assert result1.get("code") != "ALREADY_EXECUTED"

        # Second use — should fail
        result2 = await conf.execute_confirmed("disable_user", token, "analyst@test.com", executor)
        assert result2["code"] == "ALREADY_EXECUTED"

    async def test_production_requires_durable_storage(self, monkeypatch):
        # In production with Postgres unavailable, the in-memory fallback must
        # NOT be used silently — creating a proposal fails closed instead.
        from sentinel.config import get_settings

        monkeypatch.setenv("ENVIRONMENT", "production")
        get_settings.cache_clear()
        try:
            result = await conf.create_proposal(
                tool_name="block_ip",
                analyst_id="a@test.com",
                target="1.2.3.4",
                description="Block IP",
                warning="",
                parameters={"ip_address": "1.2.3.4", "reason": "c2"},
            )
            assert result["code"] == "STORAGE_UNAVAILABLE"
        finally:
            get_settings.cache_clear()

    async def test_wrong_tool_name_is_rejected(self):
        proposal = await conf.create_proposal(
            tool_name="isolate_device",
            analyst_id="analyst@test.com",
            target="HOST-001",
            description="Isolate",
            warning="",
            parameters={"hostname": "HOST-001", "reason": "test"},
        )
        token = proposal["confirmation_token"]

        async def executor(params):
            return {}

        # Try to use isolate_device token for block_ip
        result = await conf.execute_confirmed("block_ip", token, "analyst@test.com", executor)
        assert result["code"] == "TOKEN_MISMATCH"


class TestDisableUser:
    async def test_first_call_returns_proposal(self):
        from sentinel.tools.actions import _execute_disable_user

        result = await _execute_disable_user(
            {
                "email": "alice.hr@acmecorp.com",
                "reason": "compromise",
                "confirmed": False,
                "confirmation_token": "",
            }
        )
        assert result["action_type"] == "disable_user"
        assert "confirmation_token" in result

    async def test_invalid_email_returns_error(self):
        from sentinel.tools.actions import _execute_disable_user

        result = await _execute_disable_user(
            {"email": "notanemail", "reason": "test", "confirmed": False, "confirmation_token": ""}
        )
        assert result["code"] == "INVALID_PARAMETER"

    async def test_missing_reason_returns_error(self):
        from sentinel.tools.actions import _execute_disable_user

        result = await _execute_disable_user(
            {
                "email": "alice.hr@acmecorp.com",
                "reason": "",
                "confirmed": False,
                "confirmation_token": "",
            }
        )
        assert result["code"] == "MISSING_PARAMETER"


class TestBlockIP:
    async def test_first_call_returns_proposal(self):
        from sentinel.tools.actions import _execute_block_ip

        result = await _execute_block_ip(
            {
                "ip_address": "185.220.101.34",
                "reason": "c2",
                "confirmed": False,
                "confirmation_token": "",
            }
        )
        assert result["action_type"] == "block_ip"
        assert "confirmation_token" in result

    async def test_missing_ip_returns_error(self):
        from sentinel.tools.actions import _execute_block_ip

        result = await _execute_block_ip(
            {"ip_address": "", "reason": "test", "confirmed": False, "confirmation_token": ""}
        )
        assert result["code"] == "MISSING_PARAMETER"

    async def test_full_two_step_flow_executes(self):
        from sentinel.tools.actions import _execute_block_ip

        step1 = await _execute_block_ip(
            {
                "ip_address": "185.220.101.34",
                "reason": "c2",
                "confirmed": False,
                "confirmation_token": "",
            }
        )
        token = step1["confirmation_token"]
        step2 = await _execute_block_ip(
            {
                "ip_address": "185.220.101.34",
                "reason": "c2",
                "confirmed": True,
                "confirmation_token": token,
            }
        )
        assert step2["action_type"] == "block_ip"
        assert step2["result"]["action"] == "blocked"


class TestKillProcess:
    async def test_first_call_returns_proposal(self):
        from sentinel.tools.actions import _execute_kill_process

        result = await _execute_kill_process(
            {
                "hostname": "LAPTOP-001",
                "pid": 4821,
                "reason": "malware",
                "confirmed": False,
                "confirmation_token": "",
            }
        )
        assert result["action_type"] == "kill_process"
        assert "confirmation_token" in result

    async def test_invalid_pid_returns_error(self):
        from sentinel.tools.actions import _execute_kill_process

        result = await _execute_kill_process(
            {
                "hostname": "LAPTOP-001",
                "pid": -1,
                "reason": "test",
                "confirmed": False,
                "confirmation_token": "",
            }
        )
        assert result["code"] == "INVALID_PARAMETER"

    async def test_missing_hostname_returns_error(self):
        from sentinel.tools.actions import _execute_kill_process

        result = await _execute_kill_process(
            {
                "hostname": "",
                "pid": 1234,
                "reason": "test",
                "confirmed": False,
                "confirmation_token": "",
            }
        )
        assert result["code"] == "MISSING_PARAMETER"

    async def test_full_two_step_flow_executes(self):
        from sentinel.tools.actions import _execute_kill_process

        step1 = await _execute_kill_process(
            {
                "hostname": "LAPTOP-HR-03",
                "pid": 4821,
                "reason": "malware",
                "confirmed": False,
                "confirmation_token": "",
            }
        )
        token = step1["confirmation_token"]
        step2 = await _execute_kill_process(
            {
                "hostname": "LAPTOP-HR-03",
                "pid": 4821,
                "reason": "malware",
                "confirmed": True,
                "confirmation_token": token,
            }
        )
        assert step2["action_type"] == "kill_process"
        assert step2["result"]["action"] == "killed"


class TestIsolateDevice:
    async def test_first_call_returns_proposal(self):
        from sentinel.tools.actions import _execute_isolate_device

        result = await _execute_isolate_device(
            {
                "hostname": "LAPTOP-001",
                "reason": "malware detected",
                "confirmed": False,
                "confirmation_token": "",
            }
        )
        assert result["action_type"] == "isolate_device"
        assert "confirmation_token" in result
        assert "warning" in result

    async def test_missing_hostname_returns_error(self):
        from sentinel.tools.actions import _execute_isolate_device

        result = await _execute_isolate_device(
            {
                "hostname": "",
                "reason": "test",
                "confirmed": False,
                "confirmation_token": "",
            }
        )
        assert result["code"] == "MISSING_PARAMETER"

    async def test_missing_reason_returns_error(self):
        from sentinel.tools.actions import _execute_isolate_device

        result = await _execute_isolate_device(
            {
                "hostname": "LAPTOP-001",
                "reason": "",
                "confirmed": False,
                "confirmation_token": "",
            }
        )
        assert result["code"] == "MISSING_PARAMETER"

    async def test_confirmed_without_valid_token_is_rejected(self):
        from sentinel.tools.actions import _execute_isolate_device

        result = await _execute_isolate_device(
            {
                "hostname": "LAPTOP-001",
                "reason": "test",
                "confirmed": True,
                "confirmation_token": "fake-token",
            }
        )
        assert result["code"] == "INVALID_TOKEN"

    async def test_full_two_step_flow(self):
        from sentinel.tools.actions import _execute_isolate_device

        # Step 1: get proposal
        step1 = await _execute_isolate_device(
            {
                "hostname": "LAPTOP-001",
                "reason": "malware c2 communication confirmed",
                "confirmed": False,
                "confirmation_token": "",
            }
        )
        assert "confirmation_token" in step1
        token = step1["confirmation_token"]

        # Step 2: confirm
        step2 = await _execute_isolate_device(
            {
                "hostname": "LAPTOP-001",
                "reason": "malware c2 communication confirmed",
                "confirmed": True,
                "confirmation_token": token,
            }
        )
        assert step2.get("code") != "INVALID_TOKEN"
        assert "action_type" in step2
