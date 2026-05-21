# -*- encoding: utf-8 -*-
"""Tests for main Sentinel event handler."""

import pytest

pytest.importorskip("sentinel")


@pytest.mark.asyncio
async def test_handler_initialization(handler, test_config):
    """Test handler initializes correctly."""
    assert handler.config == test_config
    assert handler.kel_handler is not None
    assert handler.tel_handler is not None
    assert handler.cred_handler is not None


@pytest.mark.asyncio
async def test_on_kel_event(handler, mock_kel_event):
    """Test KEL event handling."""
    # Should not raise exception
    await handler.on_kel(mock_kel_event)


@pytest.mark.asyncio
async def test_on_tel_event(handler, mock_tel_event):
    """Test TEL event handling."""
    # Should not raise exception
    await handler.on_tel(mock_tel_event)


@pytest.mark.asyncio
async def test_on_credential_event(handler, mock_cred_event):
    """Test credential event handling."""
    # Should not raise exception
    await handler.on_credential(mock_cred_event)


@pytest.mark.asyncio
async def test_handler_error_isolation(handler, mock_kel_event):
    """Test that handler errors don't crash the framework."""

    # Force an error in the handler
    async def raise_error(e):
        raise RuntimeError("test error")

    handler.kel_handler.process = raise_error

    # Should not raise - error should be logged
    await handler.on_kel(mock_kel_event)
