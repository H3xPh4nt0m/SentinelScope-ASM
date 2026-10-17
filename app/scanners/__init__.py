"""Scanner registry bootstrap."""
from app.scanners import discovery, network, web
from app.scanners.base import REGISTRY, all_tools, get_tool, register, tool_meta, tool_status


def bootstrap() -> None:
    if not REGISTRY:
        discovery.register_all()
        network.register_all()
        web.register_all()
