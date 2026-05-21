# -*- encoding: utf-8 -*-
"""Tests for KEL event handler."""

import pytest
from unittest.mock import Mock

pytest.importorskip("sentinel")

from keriguard.app.sentinel.handlers.kel_handler import KELHandler


@pytest.mark.asyncio
async def test_kel_handler_initialization(test_config):
    """Test KEL handler initializes correctly."""
    handler = KELHandler(test_config)
    assert handler.config == test_config
    assert handler.service is not None


@pytest.mark.asyncio
async def test_kel_handler_no_hby(test_config, mock_kel_event):
    """Test KEL handler handles missing Habery gracefully."""
    handler = KELHandler(test_config)
    mock_kel_event.hby = None

    # Should not raise, just log warning
    await handler.process(mock_kel_event)


@pytest.mark.asyncio
async def test_kel_handler_aid_not_found(test_config, mock_kel_event):
    """Test KEL handler handles unknown AID gracefully."""
    handler = KELHandler(test_config)

    # Create mock hby with empty kevers
    mock_hby = Mock()
    mock_hby.kevers = {}
    mock_kel_event.hby = mock_hby

    # Should not raise, just log info
    await handler.process(mock_kel_event)
