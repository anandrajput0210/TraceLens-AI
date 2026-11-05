import networkx as nx


def _normalize_path(path: str) -> str:
    """
    Normalize Windows and Unix path separators so graph
    lookups work consistently across operating systems.
    """
    return path.replace("\\", "/").strip("/")


def _find_file_node(
    graph: nx.DiGraph,
    finding_file: str,
) -> str | None:
    """
    Find the graph file node regardless of whether the
    repository uses Windows or Unix path separators.
    """

    target = _normalize_path(finding_file)

    for node, data in graph.nodes(data=True):

        if data.get("type") != "file":
            continue

        node_path = data.get("path")

        if not node_path:
            continue

        if _normalize_path(node_path) == target:
            return node

    return None


def find_public_risk_path(
    graph: nx.DiGraph,
    finding_file: str,
    max_depth: int = 6,
) -> list[str]:
    """Return a static dependency path to a route, if one is found.

    This is a repository-structure heuristic. It does not prove that a finding
    is data-flow reachable, executed at runtime, exploitable, or publicly exposed.
    """

    start_node = _find_file_node(
        graph,
        finding_file,
    )

    if start_node is None:
        return []

    queue = [
        (start_node, [start_node])
    ]

    visited = {
        start_node
    }

    while queue:

        current, path = queue.pop(0)

        if len(path) > max_depth:
            continue

        node_data = graph.nodes[current]

        # We reached a route.
        if node_data.get("type") == "route":
            return path

        # --------------------------------------------------
        # Forward: file -> public route
        # --------------------------------------------------

        for neighbor in graph.successors(current):

            edge_data = graph.get_edge_data(
                current,
                neighbor,
            )

            if not edge_data:
                continue

            if edge_data.get("relationship") != "EXPOSES":
                continue

            if neighbor in visited:
                continue

            visited.add(neighbor)

            queue.append(
                (
                    neighbor,
                    path + [neighbor],
                )
            )

        # --------------------------------------------------
        # Backward through IMPORTS
        #
        # app
        #   ↓
        # users
        #   ↓
        # database
        #   ↓
        # production config
        #
        # Starting at production config, walk backwards.
        # --------------------------------------------------

        for predecessor in graph.predecessors(current):

            edge_data = graph.get_edge_data(
                predecessor,
                current,
            )

            if not edge_data:
                continue

            if edge_data.get("relationship") != "IMPORTS":
                continue

            if predecessor in visited:
                continue

            visited.add(predecessor)

            queue.append(
                (
                    predecessor,
                    path + [predecessor],
                )
            )

    return []