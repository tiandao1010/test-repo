"""Agent-discovery descriptor.

Other agents (and humans browsing) need to know which paid endpoints we
expose, what they cost, and what they return. The `/agent.json`
descriptor follows the de-facto x402 directory shape that Bankr's agent
platform consumes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class EndpointDescriptor:
    name: str
    path: str
    method: str
    summary: str
    asset: str
    price_usd: float
    chain: str = "base"
    request_schema: dict[str, Any] = field(default_factory=dict)
    response_schema: dict[str, Any] = field(default_factory=dict)


def default_descriptor(*, recipient_address: str) -> dict[str, Any]:
    return {
        "name": "The Good Entity",
        "version": "v1.0",
        "owner": "the-good-entity",
        "description": (
            "Defensive AI agent for crypto + Web2 + AI threats. "
            "Three paid endpoints: Elder Sign Threat Scanner, Threat Intel "
            "Feed, and Banishing Ritual."
        ),
        "homepage": "https://goodentity.xyz",
        "x402Version": 1,
        "treasury": {
            "chain": "base",
            "asset": "USDC",
            "address": recipient_address,
        },
        "endpoints": [
            ENDPOINT_SCAN.__dict__,
            ENDPOINT_INTEL.__dict__,
            ENDPOINT_SIMULATE.__dict__,
        ],
    }


ENDPOINT_SCAN = EndpointDescriptor(
    name="Elder Sign Threat Scanner",
    path="/scan",
    method="POST",
    summary="Score a contract or address against Entity's threat detectors.",
    asset="USDC",
    price_usd=0.50,
    request_schema={
        "type": "object",
        "required": ["chain_id", "address"],
        "properties": {
            "chain_id": {"type": "integer", "description": "EIP-155 chain id (8453 = Base)"},
            "address":  {"type": "string", "pattern": "^0x[0-9a-fA-F]{40}$"},
        },
    },
    response_schema={
        "type": "object",
        "properties": {
            "threat_class": {"type": "string"},
            "severity":     {"type": "integer"},
            "confidence":   {"type": "number"},
            "summary":      {"type": "string"},
            "evidence":     {"type": "array", "items": {"type": "string"}},
        },
    },
)

ENDPOINT_INTEL = EndpointDescriptor(
    name="Threat Intel Feed",
    path="/intel",
    method="GET",
    summary="Recent threats Entity has classified, optionally filtered by address or window.",
    asset="USDC",
    price_usd=0.10,
    request_schema={
        "type": "object",
        "properties": {
            "address":      {"type": "string"},
            "since":        {"type": "string", "format": "date-time"},
            "limit":        {"type": "integer", "default": 20, "maximum": 100},
        },
    },
    response_schema={
        "type": "object",
        "properties": {
            "items": {"type": "array"},
            "count": {"type": "integer"},
        },
    },
)

ENDPOINT_SIMULATE = EndpointDescriptor(
    name="Banishing Ritual",
    path="/simulate",
    method="POST",
    summary="Suggest defensive patches or revoke actions for a flagged contract.",
    asset="USDC",
    price_usd=2.00,
    request_schema={
        "type": "object",
        "required": ["chain_id", "address"],
        "properties": {
            "chain_id":         {"type": "integer"},
            "address":          {"type": "string"},
            "context":          {"type": "string", "description": "Optional context."},
        },
    },
    response_schema={
        "type": "object",
        "properties": {
            "advice":     {"type": "string"},
            "actions":    {"type": "array", "items": {"type": "string"}},
            "confidence": {"type": "number"},
        },
    },
)
