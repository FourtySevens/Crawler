"""Run the dashboard and a local assessment target together."""

import threading

from crawler.server import serve
from .demo_site import make_demo_server


def main():
    demo = make_demo_server(8081)
    thread = threading.Thread(target=demo.serve_forever, daemon=True)
    thread.start()
    print("Local demo target: http://127.0.0.1:8081", flush=True)
    try:
        serve()
    finally:
        demo.shutdown()
        demo.server_close()


if __name__ == "__main__":
    main()
