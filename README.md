<div align="center">

# Email Validator Ai MCP

**Email Validator AI MCP Server**

[![PyPI](https://img.shields.io/pypi/v/meok-email-validator-ai-mcp)](https://pypi.org/project/meok-email-validator-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Email Validator AI MCP Server
Email validation and verification tools powered by MEOK AI Labs.

## Tools

| Tool | Description |
|------|-------------|
| `validate_email` | Validate an email address format, structure, and common issues. |
| `check_mx` | Check if a domain has valid MX (mail exchange) records. |
| `detect_disposable` | Detect if an email uses a disposable/temporary email service. |
| `suggest_correction` | Suggest corrections for common email typos (e.g., gmial.com -> gmail.com). |

## Installation

```bash
pip install meok-email-validator-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "email-validator-ai": {
      "command": "python",
      "args": ["-m", "meok_email_validator_ai_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 4 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
