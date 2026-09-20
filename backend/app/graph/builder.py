import ast
import re
from pathlib import Path

import networkx as nx


ROUTE_PATTERNS = [
    re.compile(
        r"@(?:app|router)\."
        r"(get|post|put|delete|patch)\s*"
        r"\(\s*[\"']([^\"']+)[\"']"
    ),
    re.compile(
        r"(?:app|router)\."
        r"(get|post|put|delete|patch)\s*"
        r"\(\s*[\"']([^\"']+)[\"']"
    ),
]


class ApplicationGraphBuilder:
    """
    Builds a lightweight application relationship graph.

    Repository source code is analyzed as text/AST.
    It is never executed.
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self.module_map = {}

    # ---------------------------------------------------------
    # FILE REGISTRATION
    # ---------------------------------------------------------

    def register_files(self, files: list[dict]):
        """
        Build a map from Python module names to repository files.
        """

        for file_info in files:

            if file_info["extension"] != ".py":
                continue

            relative_path = Path(file_info["path"])

            # Remove .py
            module_path = relative_path.with_suffix("")

            # Convert:
            #
            # services/database.py
            #
            # into:
            #
            # services.database

            module_name = ".".join(
                module_path.parts
            )

            self.module_map[module_name] = (
                file_info["path"]
            )

    # ---------------------------------------------------------
    # FILE NODE
    # ---------------------------------------------------------

    def add_file_node(self, relative_path: str):

        self.graph.add_node(
            f"file:{relative_path}",
            type="file",
            path=relative_path,
        )

    # ---------------------------------------------------------
    # IMPORT PARSING
    # ---------------------------------------------------------

    def parse_python_imports(
        self,
        absolute_path: str,
        relative_path: str,
    ):

        try:

            source = Path(absolute_path).read_text(
                encoding="utf-8",
                errors="ignore",
            )

            tree = ast.parse(source)

        except (OSError, SyntaxError):

            return

        source_node = f"file:{relative_path}"

        for node in ast.walk(tree):

            # ---------------------------------------------
            # import services.database
            # ---------------------------------------------

            if isinstance(node, ast.Import):

                for imported in node.names:

                    self._add_import_edge(
                        source_node,
                        imported.name,
                    )

            # ---------------------------------------------
            # from services.database import ...
            # ---------------------------------------------

            elif isinstance(node, ast.ImportFrom):

                if node.module:

                    self._add_import_edge(
                        source_node,
                        node.module,
                    )

    # ---------------------------------------------------------
    # IMPORT EDGE
    # ---------------------------------------------------------

    def _add_import_edge(
        self,
        source_node: str,
        imported_module: str,
    ):

        # Try to resolve the module to an actual
        # repository file.

        resolved_file = self.module_map.get(
            imported_module
        )

        if resolved_file:

            target_node = f"file:{resolved_file}"

            self.graph.add_edge(
                source_node,
                target_node,
                relationship="IMPORTS",
            )

            return

        # External / unresolved module

        module_node = f"module:{imported_module}"

        self.graph.add_node(
            module_node,
            type="module",
            name=imported_module,
        )

        self.graph.add_edge(
            source_node,
            module_node,
            relationship="IMPORTS",
        )

    # ---------------------------------------------------------
    # ROUTE DETECTION
    # ---------------------------------------------------------

    def detect_routes(
        self,
        absolute_path: str,
        relative_path: str,
    ):

        path = Path(absolute_path)

        try:

            source = path.read_text(
                encoding="utf-8",
                errors="ignore",
            )

        except OSError:

            return

        source_node = f"file:{relative_path}"

        for pattern in ROUTE_PATTERNS:

            for match in pattern.finditer(source):

                method = match.group(1).upper()
                route = match.group(2)

                route_node = (
                    f"route:{method}:{route}"
                )

                self.graph.add_node(
                    route_node,
                    type="route",
                    method=method,
                    path=route,
                )

                self.graph.add_edge(
                    source_node,
                    route_node,
                    relationship="EXPOSES",
                )

    # ---------------------------------------------------------
    # BUILD GRAPH
    # ---------------------------------------------------------

    def build(
        self,
        files: list[dict],
    ) -> nx.DiGraph:

        # First register every repository Python file.
        self.register_files(files)

        # Then build relationships.
        for file_info in files:

            absolute_path = file_info["absolute_path"]
            relative_path = file_info["path"]

            self.add_file_node(relative_path)

            if file_info["extension"] == ".py":

                self.parse_python_imports(
                    absolute_path,
                    relative_path,
                )

            self.detect_routes(
                absolute_path,
                relative_path,
            )

        return self.graph