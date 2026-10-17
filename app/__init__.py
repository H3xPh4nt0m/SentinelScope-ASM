"""Application factory for the ASM platform."""
import logging

from flask import Flask, g, session

from app.config import Config
from app.extensions import db, login_manager


def create_app(config_object: type[Config] | None = None) -> Flask:
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config.from_object(config_object or Config)

    _configure_logging(app)
    _configure_sqlite_pragmas()

    db.init_app(app)
    login_manager.init_app(app)

    # Import all models so create_all sees them.
    with app.app_context():
        import app.models as _models  # noqa: F401

    _register_blueprints(app)
    _register_hooks(app)
    _register_template_helpers(app)
    _start_background_services(app)

    return app


def _configure_logging(app: Flask) -> None:
    level = getattr(logging, app.config.get("LOG_LEVEL", "INFO"), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
    logging.getLogger("werkzeug").setLevel(max(level, logging.WARNING))


def _configure_sqlite_pragmas() -> None:
    """WAL + busy timeout + FK enforcement on every SQLite connection
    (web requests and background workers share the database)."""
    from sqlalchemy import event, engine

    @event.listens_for(engine.Engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=15000")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def _register_blueprints(app: Flask) -> None:
    from app.auth.views import auth_bp
    from app.routes.main import main_bp
    from app.routes.assets import assets_bp
    from app.routes.scans import scans_bp
    from app.routes.vulns import vulns_bp
    from app.routes.stride import stride_bp
    from app.routes.risk import risk_bp
    from app.routes.metrics import metrics_bp
    from app.routes.monitoring import monitoring_bp
    from app.routes.policy import policy_bp
    from app.routes.llm_ui import llm_bp
    from app.routes.admin import admin_bp
    from app.routes.reports import reports_bp
    from app.routes.audit import audit_bp
    from app.routes.api import api_bp

    for bp in (auth_bp, main_bp, assets_bp, scans_bp, vulns_bp, stride_bp, risk_bp,
               metrics_bp, monitoring_bp, policy_bp, llm_bp, admin_bp, reports_bp,
               audit_bp, api_bp):
        app.register_blueprint(bp)


def _register_hooks(app: Flask) -> None:
    from app.audit.logger import begin_request_id
    from app.auth.utils import csrf_protect

    @app.before_request
    def _before():
        begin_request_id()
        csrf_protect()

    @app.errorhandler(404)
    def not_found(_error):
        from flask import render_template
        if _request_wants_json():
            return {"error": "not found"}, 404
        return render_template("errors/404.html"), 404

    @app.errorhandler(403)
    def forbidden(_error):
        from flask import render_template
        if _request_wants_json():
            return {"error": "forbidden"}, 403
        return render_template("errors/403.html"), 403

    @app.errorhandler(400)
    def bad_request(error):
        # CSRF failures land here; API clients get JSON, browsers get the page.
        if _request_wants_json():
            return {"error": "bad request",
                    "detail": getattr(error, "description", "")}, 400
        from flask import render_template
        return render_template("errors/400.html",
                               detail=getattr(error, "description", "")), 400


def _request_wants_json() -> bool:
    from flask import request
    return (request.path.startswith("/api/")
            or request.accept_mimetypes.best == "application/json")


def _register_template_helpers(app: Flask) -> None:
    from app.auth.utils import csrf_token

    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["app_name"] = "SentinelScope ASM"

    def now_string() -> str:
        from app.utils import utcnow
        return utcnow().strftime("%Y-%m-%d %H:%M UTC")

    app.jinja_env.globals["now_string"] = now_string

    def sev_class(sev: str) -> str:
        return {"critical": "sev-critical", "high": "sev-high", "medium": "sev-medium",
                "low": "sev-low", "info": "sev-info"}.get((sev or "").lower(), "sev-info")

    def score_class(score: int | None) -> str:
        if score is None:
            return ""
        if score >= 70:
            return "sev-critical"
        if score >= 40:
            return "sev-high"
        if score >= 20:
            return "sev-medium"
        return "sev-low"

    app.jinja_env.filters["sev_class"] = sev_class
    app.jinja_env.filters["score_class"] = score_class


def _start_background_services(app: Flask) -> None:
    """Start workers/scheduler once per process; skip under the debug reloader."""
    import os
    if app.config.get("DEBUG") and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return
    if app.config.get("TESTING"):
        return
    with app.app_context():
        from app.services.jobs import requeue_stale_running, start_workers
        from app.monitoring.scheduler import start_scheduler
        try:
            requeue_stale_running()
        except Exception:
            # Fresh database without tables — user should run `python run.py --init-db`.
            logging.getLogger("asm").warning(
                "Database not initialized; background services idle. Run: python run.py --init-db")
            return
        start_workers(app)
        start_scheduler(app)
