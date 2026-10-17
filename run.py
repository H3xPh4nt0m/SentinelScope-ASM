"""ASM Platform entry point.

Usage:
    python run.py                 # start the web application
    python run.py --init-db       # create tables + seed roles/permissions/admin
    python run.py --demo          # init db + load synthetic demo dataset
    python run.py --test-llm      # test the LLM connection and exit
"""
import argparse
import sys

from app import create_app


def main() -> int:
    parser = argparse.ArgumentParser(description="Attack Surface Management platform")
    parser.add_argument("--init-db", action="store_true", help="create tables and seed base data")
    parser.add_argument("--demo", action="store_true", help="init db and load the synthetic demo dataset")
    parser.add_argument("--test-llm", action="store_true", help="test the LLM connection and exit")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    app = create_app()

    if args.test_llm:
        from app.llm.client import test_connection
        with app.app_context():
            ok, message = test_connection()
        print(("OK: " if ok else "FAILED: ") + message)
        return 0 if ok else 1

    if args.init_db or args.demo:
        from app.services.bootstrap import init_db
        from app.services.demo import load_demo_data
        with app.app_context():
            init_db()
            if args.demo:
                load_demo_data()
        print("Database initialized." + (" Demo data loaded." if args.demo else ""))
        return 0

    app.run(host=args.host, port=args.port, debug=app.config.get("DEBUG", False))


if __name__ == "__main__":
    sys.exit(main())
