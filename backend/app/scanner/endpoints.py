import ast
import re
from pathlib import Path


SENSITIVE_ROUTE_TERMS = (
    "/admin",
    "/users",
    "/user",
    "/account",
    "/profile",
    "/payments",
    "/payment",
    "/orders",
    "/order",
    "/private",
    "/secrets",
    "/credentials",
)


AUTH_INDICATORS = (
    "login_required",
    "auth_required",
    "require_auth",
    "requires_auth",
    "authenticated",
    "authenticate",
    "authorization",
    "authorize",
    "get_current_user",
    "current_user",
    "request.user",
    "Depends(",
)


def is_sensitive_route(route: str) -> bool:
    """
    Determine whether a route appears to expose
    security-sensitive application data.
    """

    normalized_route = route.lower().rstrip("/")

    return any(
        term in normalized_route
        for term in SENSITIVE_ROUTE_TERMS
    )


def has_authentication_indicator(function_node: ast.FunctionDef) -> bool:
    """
    Check whether a route function contains obvious
    authentication/authorization indicators.

    This is static evidence only and does not prove
    that the endpoint is actually protected.
    """

    # Check decorators first.
    for decorator in function_node.decorator_list:

        decorator_text = ast.unparse(decorator).lower()

        if any(
            indicator.lower() in decorator_text
            for indicator in AUTH_INDICATORS
        ):
            return True

    # Check function body.
    try:
        function_source = ast.unparse(function_node).lower()
    except Exception:
        return False

    return any(
        indicator.lower() in function_source
        for indicator in AUTH_INDICATORS
    )


def scan_sensitive_endpoints(
    file_path: str,
    relative_path: str,
) -> list[dict]:
    """
    SEC-006:
    Detect potentially sensitive endpoints that do not
    contain obvious authentication/authorization evidence.

    This detector does NOT execute repository code.
    """

    path = Path(file_path)

    if path.suffix.lower() != ".py":
        return []

    try:
        content = path.read_text(
            encoding="utf-8",
            errors="ignore",
        )
    except OSError:
        return []

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    findings = []

    for node in ast.walk(tree):

        if not isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            continue

        route_info = None

        # ---------------------------------------------
        # Find FastAPI/Flask-style route decorators
        # ---------------------------------------------

        for decorator in node.decorator_list:

            try:
                decorator_text = ast.unparse(
                    decorator
                )
            except Exception:
                continue

            match = re.search(
                r"""
                (?:app|router)
                \.
                (get|post|put|delete|patch)
                \(
                \s*
                ["']
                ([^"']+)
                ["']
                """,
                decorator_text,
                re.IGNORECASE | re.VERBOSE,
            )

            if match:
                route_info = (
                    match.group(1).upper(),
                    match.group(2),
                )
                break

        if route_info is None:
            continue

        method, route = route_info

        # ---------------------------------------------
        # Only inspect sensitive routes
        # ---------------------------------------------

        if not is_sensitive_route(route):
            continue

        # ---------------------------------------------
        # Authentication evidence
        # ---------------------------------------------

        if has_authentication_indicator(node):
            continue

        findings.append(
            {
                "rule_id": "SEC-006",
                "title": "Potentially unprotected sensitive endpoint",
                "category": "Access Control",
                "file": relative_path,
                "line": node.lineno,
                "evidence": (
                    f"{method} {route} has no obvious "
                    "authentication/authorization indicator"
                ),
                "base_severity": "HIGH",
                "confidence": 0.78,
            }
        )

    return findings