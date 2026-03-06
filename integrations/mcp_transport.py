from __future__ import annotations

import os
from typing import Any, Dict, Optional

import requests


class MCPTransportError(RuntimeError):
    """Raised when MCP transport is requested but not correctly configured."""


class _MCPResponse:
    """Minimal response wrapper to mirror the parts of requests.Response we use."""

    def __init__(self, status_code: int, payload: Any):
        self.status_code = int(status_code)
        self._payload = payload

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code} returned by MCP bridge")


class ExternalAPITransport:
    """
    HTTP transport for external API calls.

    Modes:
    - direct: perform HTTP requests directly with `requests` (default)
    - mcp: route requests through an MCP bridge endpoint
    """

    def __init__(self, mode: str = "direct", mcp_bridge_url: Optional[str] = None):
        self.mode = (mode or "direct").strip().lower()
        self.mcp_bridge_url = mcp_bridge_url

    @classmethod
    def from_env(cls) -> "ExternalAPITransport":
        mode = os.getenv("SOC_EXTERNAL_API_MODE", "direct")
        mcp_bridge_url = os.getenv("SOC_MCP_BRIDGE_URL")
        return cls(mode=mode, mcp_bridge_url=mcp_bridge_url)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json_body: Optional[Any] = None,
        timeout: int = 20,
    ):
        if self.mode == "direct":
            return requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                json=json_body,
                timeout=timeout,
            )

        if self.mode != "mcp":
            raise MCPTransportError(
                f"Unsupported SOC_EXTERNAL_API_MODE='{self.mode}'. Use 'direct' or 'mcp'."
            )

        if not self.mcp_bridge_url:
            raise MCPTransportError(
                "SOC_EXTERNAL_API_MODE is 'mcp' but SOC_MCP_BRIDGE_URL is not configured."
            )

        bridge_payload = {
            "method": method,
            "url": url,
            "headers": headers or {},
            "params": params or {},
            "data": data,
            "json": json_body,
            "timeout": timeout,
        }
        bridge_response = requests.post(
            self.mcp_bridge_url,
            json=bridge_payload,
            timeout=timeout,
        )
        bridge_response.raise_for_status()
        envelope = bridge_response.json()

        return _MCPResponse(
            status_code=envelope.get("status_code", 500),
            payload=envelope.get("body", {}),
        )
