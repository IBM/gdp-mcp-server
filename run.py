"""WXO STDIO entry point for GDP MCP Server."""
import os

# Force STDIO transport
os.environ["MCP_TRANSPORT"] = "stdio"

from src.server import main

if __name__ == "__main__":
    main()
