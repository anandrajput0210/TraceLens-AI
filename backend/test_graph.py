from app.graph.builder import ApplicationGraphBuilder
from app.graph.traversal import find_public_risk_path
from app.services.repository_service import discover_files


def test_application_graph_builds():
    repository_path = "../demo-repo"

    files = discover_files(repository_path)

    builder = ApplicationGraphBuilder()
    graph = builder.build(files)

    assert graph.number_of_nodes() > 0
    assert graph.number_of_edges() > 0


def test_production_config_has_public_risk_path():
    repository_path = "../demo-repo"

    files = discover_files(repository_path)

    builder = ApplicationGraphBuilder()
    graph = builder.build(files)

    path = find_public_risk_path(
        graph,
        "config/production.py",
    )

    assert path is not None
    assert len(path) >= 2


def test_risk_path_reaches_route():
    repository_path = "../demo-repo"

    files = discover_files(repository_path)

    builder = ApplicationGraphBuilder()
    graph = builder.build(files)

    path = find_public_risk_path(
        graph,
        "config/production.py",
    )

    assert path is not None
    assert len(path) >= 2

    assert any(
        node.startswith("route:")
        for node in path
    )