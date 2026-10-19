"""
tests/test_circuit_breaker.py
Comprehensive pytest coverage for circuit_breaker.py (Ara-Hardened)
"""

import asyncio
import pytest
from circuit_breaker import CircuitBreaker, CircuitOpenError, State

@pytest.mark.asyncio
async def test_initial_state_is_closed():
    cb = CircuitBreaker(failure_threshold=3, window_seconds=10, cooldown_seconds=5)
    assert cb.state == State.CLOSED

@pytest.mark.asyncio
async def test_opens_after_threshold_failures():
    cb = CircuitBreaker(failure_threshold=2, window_seconds=60, cooldown_seconds=10)
    
    async def failing():
        raise ValueError("simulated failure")
    
    with pytest.raises(ValueError):
        await cb.call(failing())
    with pytest.raises(ValueError):
        await cb.call(failing())
    
    assert cb.state == State.OPEN

@pytest.mark.asyncio
async def test_half_open_after_cooldown_and_closes_on_success():
    cb = CircuitBreaker(failure_threshold=1, window_seconds=1, cooldown_seconds=0.1, half_open_max_calls=1)
    
    async def failing():
        raise ValueError()
    
    await cb.call(failing())  # opens circuit
    await asyncio.sleep(0.2)  # wait for cooldown
    
    assert cb.state == State.HALF_OPEN
    
    async def success():
        return "ok"
    
    result = await cb.call(success())
    assert result == "ok"
    assert cb.state == State.CLOSED

@pytest.mark.asyncio
async def test_context_manager_protects_and_closes_on_success():
    cb = CircuitBreaker(failure_threshold=1, window_seconds=60, cooldown_seconds=10)
    
    async with cb:
        pass  # success path
    
    assert cb.state == State.CLOSED

@pytest.mark.asyncio
async def test_manual_force_open_and_reset():
    cb = CircuitBreaker(failure_threshold=5, window_seconds=60, cooldown_seconds=10)
    
    await cb.force_open()
    assert cb.state == State.OPEN
    
    await cb.reset()
    assert cb.state == State.CLOSED

@pytest.mark.asyncio
async def test_half_open_exhausts_trial_calls():
    cb = CircuitBreaker(failure_threshold=1, window_seconds=1, cooldown_seconds=0.1, half_open_max_calls=1)
    
    async def failing():
        raise ValueError()
    
    await cb.call(failing())
    await asyncio.sleep(0.2)
    
    assert cb.state == State.HALF_OPEN
    
    with pytest.raises(CircuitOpenError):
        await cb.call(failing())  # second call in half-open should fail
