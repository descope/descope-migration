# Project: Descope Migration Script

**Type:** CLI migration tool
**Language:** Python 3

## Vision

A multi-provider migration CLI that moves users, roles, tenants, and permissions from various identity providers into Descope. Each provider is a self-contained module following a fetch → transform → write pipeline.

## Current Providers
- Firebase → Descope
- Auth0 → Descope
- AWS Cognito → Descope
- PingOne → Descope

## Principles
- Each provider is a standalone module in `src/`
- Shared infrastructure: `setup.py` (logging + Descope client), `utils.py` (HTTP retry, custom attributes)
- Entry point `main.py` dispatches to provider module via CLI arg
- No persistent state — one-shot migrations per run
