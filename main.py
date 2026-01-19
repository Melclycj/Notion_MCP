import os
import sys

import uvicorn
from dotenv import load_dotenv

from server import get_app


def main() -> None:
    load_dotenv()
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8443"))
    cert_file = os.getenv("HTTPS_CERT_FILE") or os.getenv("SSL_CERT_FILE")
    key_file = os.getenv("HTTPS_KEY_FILE") or os.getenv("SSL_KEY_FILE")

    if not cert_file or not key_file:
        print("SSL_CERT_FILE and SSL_KEY_FILE must be set for HTTPS.", file=sys.stderr)
        sys.exit(1)

    app = get_app()
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info",
        ssl_certfile=cert_file,
        ssl_keyfile=key_file,
    )
    server = uvicorn.Server(config)
    server.run()


if __name__ == "__main__":
    main()
