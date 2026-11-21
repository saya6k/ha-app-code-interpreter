import asyncio

import pytest

from sessions import SessionManager, SessionNotFound


class FakeClock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class FakeSandbox:
    def __init__(self, sid: str, uid: int) -> None:
        self.sid = sid
        self.uid = uid
        self.destroyed = False

    async def destroy(self) -> None:
        self.destroyed = True


class Recorder:
    """Sandbox factory + destroy-event recorder."""

    def __init__(self) -> None:
        self.created: list[FakeSandbox] = []
        self.destroyed: list[tuple[str, str]] = []

    async def factory(self, sid: str, uid: int) -> FakeSandbox:
        sb = FakeSandbox(sid, uid)
        self.created.append(sb)
        return sb

    def on_destroy(self, session, reason: str) -> None:
        self.destroyed.append((session.id, reason))


def make(clock=None, idle=60.0, max_sessions=3):
    rec = Recorder()
    mgr = SessionManager(
        rec.factory,
        idle_timeout_s=idle,
        max_sessions=max_sessions,
        clock=clock or FakeClock(),
        on_destroy=rec.on_destroy,
    )
    return mgr, rec


def run(coro):
    return asyncio.run(coro)


def test_create_without_id_makes_new_session_with_hex_id():
    async def go():
        mgr, rec = make()
        async with mgr.acquire(None) as s:
            assert len(s.id) == 16
            int(s.id, 16)
            assert s.sandbox is rec.created[0]
        assert [x.id for x in mgr.list()] == [s.id]

    run(go())


def test_acquire_existing_id_reuses_session():
    async def go():
        mgr, rec = make()
        async with mgr.acquire(None) as s1:
            pass
        async with mgr.acquire(s1.id) as s2:
            assert s2 is s1
        assert len(rec.created) == 1

    run(go())


def test_unknown_id_raises_not_found():
    async def go():
        mgr, _ = make()
        with pytest.raises(SessionNotFound):
            async with mgr.acquire("deadbeefdeadbeef"):
                pass

    run(go())


def test_reap_destroys_only_idle_sessions_with_reason_idle():
    async def go():
        clock = FakeClock()
        mgr, rec = make(clock=clock, idle=60)
        async with mgr.acquire(None) as old:
            pass
        clock.t += 30
        async with mgr.acquire(None) as fresh:
            pass
        clock.t += 31  # old idle 61s, fresh idle 31s
        await mgr.reap()
        assert rec.destroyed == [(old.id, "idle")]
        assert old.sandbox.destroyed and not fresh.sandbox.destroyed
        assert [x.id for x in mgr.list()] == [fresh.id]

    run(go())


def test_access_refreshes_last_used():
    async def go():
        clock = FakeClock()
        mgr, rec = make(clock=clock, idle=60)
        async with mgr.acquire(None) as s:
            pass
        clock.t += 50
        async with mgr.acquire(s.id):
            pass
        clock.t += 50  # 100s since create, 50s since last use
        await mgr.reap()
        assert rec.destroyed == []

    run(go())


def test_reap_skips_session_in_use():
    async def go():
        clock = FakeClock()
        mgr, rec = make(clock=clock, idle=60)
        async with mgr.acquire(None):
            clock.t += 1000  # long-running call
            await mgr.reap()
            assert rec.destroyed == []

    run(go())


def test_max_sessions_evicts_longest_idle():
    async def go():
        clock = FakeClock()
        mgr, rec = make(clock=clock, max_sessions=2)
        async with mgr.acquire(None) as a:
            pass
        clock.t += 1
        async with mgr.acquire(None) as b:
            pass
        clock.t += 1
        async with mgr.acquire(a.id):  # a is now the most recently used
            pass
        clock.t += 1
        async with mgr.acquire(None) as c:
            pass
        assert rec.destroyed == [(b.id, "evicted")]
        assert sorted(x.id for x in mgr.list()) == sorted([a.id, c.id])

    run(go())


def test_concurrent_calls_on_same_session_are_serialized():
    async def go():
        mgr, _ = make()
        async with mgr.acquire(None) as s:
            pass
        active = 0
        peak = 0

        async def call():
            nonlocal active, peak
            async with mgr.acquire(s.id):
                active += 1
                peak = max(peak, active)
                await asyncio.sleep(0.01)
                active -= 1

        await asyncio.gather(*(call() for _ in range(5)))
        assert peak == 1

    run(go())


def test_close_destroys_with_reason_close():
    async def go():
        mgr, rec = make()
        async with mgr.acquire(None) as s:
            pass
        await mgr.close(s.id)
        assert rec.destroyed == [(s.id, "close")]
        assert s.sandbox.destroyed
        assert mgr.list() == []
        with pytest.raises(SessionNotFound):
            await mgr.close(s.id)

    run(go())


def test_close_all_destroys_everything_with_given_reason():
    async def go():
        mgr, rec = make()
        for _ in range(2):
            async with mgr.acquire(None):
                pass
        await mgr.close_all("shutdown")
        assert [r for _, r in rec.destroyed] == ["shutdown", "shutdown"]
        assert mgr.list() == []

    run(go())


def test_destroy_failure_still_removes_session():
    async def go():
        mgr, rec = make()
        async with mgr.acquire(None) as s:
            pass

        async def boom():
            raise RuntimeError("kill failed")

        s.sandbox.destroy = boom
        await mgr.close(s.id)
        assert mgr.list() == []
        assert rec.destroyed == [(s.id, "close")]

    run(go())


def test_expires_in_reports_remaining_idle_time():
    async def go():
        clock = FakeClock()
        mgr, _ = make(clock=clock, idle=60)
        async with mgr.acquire(None) as s:
            pass
        clock.t += 15
        assert mgr.expires_in(s) == 45

    run(go())


def test_expired_session_id_raises_not_found_without_creating():
    async def go():
        clock = FakeClock()
        mgr, rec = make(clock=clock, idle=60)
        async with mgr.acquire(None) as s:
            pass
        clock.t += 61
        await mgr.reap()
        with pytest.raises(SessionNotFound):
            async with mgr.acquire(s.id):
                pass
        assert len(rec.created) == 1 and mgr.list() == []

    run(go())


def test_live_sessions_get_distinct_uids_from_base():
    async def go():
        mgr, rec = make(max_sessions=3)
        for _ in range(3):
            async with mgr.acquire(None):
                pass
        assert sorted(s.uid for s in mgr.list()) == [60000, 60001, 60002]
        assert [sb.uid for sb in rec.created] == [60000, 60001, 60002]

    run(go())


def test_uid_slot_is_reused_after_close():
    async def go():
        mgr, _ = make(max_sessions=3)
        ids = []
        for _ in range(3):
            async with mgr.acquire(None) as s:
                ids.append(s)
        await mgr.close(ids[1].id)
        async with mgr.acquire(None) as s:
            assert s.uid == 60001

    run(go())


def test_eviction_hands_the_slot_to_the_new_session():
    async def go():
        clock = FakeClock()
        mgr, rec = make(clock=clock, max_sessions=2)
        async with mgr.acquire(None) as a:
            pass
        clock.t += 1
        async with mgr.acquire(None):
            pass
        clock.t += 1
        async with mgr.acquire(None) as c:
            assert c.uid == a.uid
        assert rec.destroyed == [(a.id, "evicted")]

    run(go())


def test_failed_destroy_retires_the_uid():
    """A sandbox that could not be destroyed may still run under its uid, so the
    uid must not go to another session."""

    async def go():
        mgr, _ = make(max_sessions=2)
        async with mgr.acquire(None) as a:
            pass

        async def boom():
            raise RuntimeError("kill failed")

        a.sandbox.destroy = boom
        await mgr.close(a.id)
        async with mgr.acquire(None) as b:
            assert b.uid != a.uid
        with pytest.raises(RuntimeError, match="uid"):
            async with mgr.acquire(None):
                pass

    run(go())
