import re
from pathlib import Path

from nope_api.models import AttackSurfaceItem, CodeGraph, GraphEdge, GraphNode, Severity


ROUTE_PATTERNS = [
    re.compile(r"app\.(get|post|put|patch|delete)\(['\"]([^'\"]+)['\"].*?(?:async\s+)?(?:function\s+)?([A-Za-z0-9_]*)", re.DOTALL),
    re.compile(r"router\.(get|post|put|patch|delete)\(['\"]([^'\"]+)['\"].*?(?:async\s+)?(?:function\s+)?([A-Za-z0-9_]*)", re.DOTALL),
    re.compile(r"@(app|router)\.(get|post|put|patch|delete)\(['\"]([^'\"]+)['\"]\)\s*\n\s*(?:async\s+)?def\s+([A-Za-z0-9_]+)"),
]


def route_from_file(root: Path, path: Path) -> tuple[str, str] | None:
    rel = path.relative_to(root).as_posix()
    if "app/api/" in rel and path.name in {"route.ts", "route.js"}:
        route = "/" + rel.split("app/api/", 1)[1].rsplit("/", 1)[0]
        route = route.replace("[", ":").replace("]", "")
        return route, "ANY"
    if "pages/api/" in rel:
        route = "/" + rel.split("pages/api/", 1)[1].rsplit(".", 1)[0]
        route = route.replace("[", ":").replace("]", "")
        return route, "ANY"
    return None


def build_attack_surface(root: Path) -> list[AttackSurfaceItem]:
    items: list[AttackSurfaceItem] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".js", ".ts", ".tsx", ".py"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        rel = path.relative_to(root).as_posix()
        file_route = route_from_file(root, path)
        if file_route:
            route, method = file_route
            items.append(_surface_from_text(route, method, rel, text))

        for pattern in ROUTE_PATTERNS:
            for match in pattern.finditer(text):
                if pattern.pattern.startswith("@"):
                    method = match.group(2).upper()
                    route = match.group(3)
                    handler = match.group(4)
                else:
                    method = match.group(1).upper()
                    route = match.group(2)
                    handler = match.group(3) or None
                item = _surface_from_text(route, method, rel, text)
                item.handler = handler
                items.append(item)
    return items


def _surface_from_text(route: str, method: str, file: str, text: str) -> AttackSurfaceItem:
    lower = text.lower()
    auth = "present" if any(token in lower for token in ["auth", "session", "jwt", "currentuser", "user_id"]) else "unknown"
    authorization = "present" if any(token in lower for token in ["owner", "tenant", "policy", "authorize", "role"]) else "unknown"
    validation = "present" if any(token in lower for token in ["zod", "joi", "pydantic", "schema", "validate"]) else "unknown"
    return AttackSurfaceItem(
        route=route,
        method=method,
        file=file,
        authentication=auth,
        authorization=authorization,
        validation=validation,
        input_sources=[source for source in ["params", "query", "body", "cookies", "headers"] if source in lower],
        database_access=[db for db in ["prisma", "supabase", "sql", "findunique", "findfirst", "select"] if db in lower],
        file_access=[op for op in ["readfile", "writefile", "upload", "download"] if op in lower],
        external_calls=[op for op in ["fetch(", "axios", "requests.", "httpx."] if op in lower],
        side_effects=[op for op in ["delete", "update", "insert", "create", "send"] if op in lower],
        sensitive_output=any(token in lower for token in ["password", "token", "secret", "invoice", "email", "ssn"]),
        tenant_scope="present" if "tenant" in lower or "org" in lower else "unknown",
        admin_scope="admin" in lower,
        rate_limiting="present" if "ratelimit" in lower or "rate_limit" in lower else "unknown",
        csrf="present" if "csrf" in lower else "unknown",
        cors="present" if "cors" in lower else "unknown",
    )


def build_code_graph(root: Path, surface: list[AttackSurfaceItem]) -> CodeGraph:
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    seen: set[str] = set()

    def add_node(node: GraphNode) -> None:
        if node.id not in seen:
            seen.add(node.id)
            nodes.append(node)

    for item in surface:
        route_id = f"route:{item.method}:{item.route}"
        add_node(GraphNode(id=route_id, label=f"{item.method} {item.route}", kind="entry point", file=item.file))
        file_id = f"file:{item.file}"
        add_node(GraphNode(id=file_id, label=item.file, kind="file", file=item.file))
        edges.append(GraphEdge(source=route_id, target=file_id, relationship="handled by"))
        if item.authentication == "present":
            login_node = f"login:{item.file}"
            add_node(GraphNode(id=login_node, label="Login check", kind="login", file=item.file))
            edges.append(GraphEdge(source=route_id, target=login_node, relationship="uses login check"))
        if item.authorization != "present" and item.database_access:
            risk_id = f"risk:{item.id}"
            add_node(GraphNode(id=risk_id, label="Missing ownership check risk", kind="authorization", file=item.file, risk=Severity.high))
            edges.append(GraphEdge(source=file_id, target=risk_id, relationship="may reach"))
        for db in item.database_access:
            db_id = f"db:{item.file}:{db}"
            add_node(GraphNode(id=db_id, label=db, kind="database", file=item.file))
            edges.append(GraphEdge(source=file_id, target=db_id, relationship="retrieves data from"))

    return CodeGraph(nodes=nodes, edges=edges)
