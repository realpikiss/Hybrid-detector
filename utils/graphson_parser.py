"""
GraphSON v3 TinkerPop Parser for Joern CPG (compatible Joern 4.0.398)
- Supports "flat" entries (without @value) and nested ones (@value)
- Recovers node labels via inVLabel/outVLabel if vertices are missing/incomplete
"""

import json
from pathlib import Path
from collections import Counter
from typing import Dict, List, Tuple, Optional, Any, Union


def _peel(x: Any) -> Any:
    """Unwrap a GraphSON envelope (@value) if present."""
    return x.get("@value", x) if isinstance(x, dict) else x


def _is_graphson_v3(doc: Any) -> bool:
    return (
        isinstance(doc, dict)
        and doc.get("@type") == "tinker:graph"
        and isinstance(doc.get("@value"), dict)
        and "vertices" in doc["@value"]
        and "edges" in doc["@value"]
    )


def _label_of_vertex(v: dict) -> str:
    vv = v.get("@value", v)
    return vv.get("label", "UNKNOWN")


def _id_of_vertex(v: dict) -> Any:
    vv = v.get("@value", v)
    return _peel(vv.get("id"))


def _edge_fields(e: dict):
    ev = e.get("@value", e)
    u = _peel(ev.get("outV"))
    v = _peel(ev.get("inV"))
    lab = ev.get("label", "UNKNOWN")
    out_lab = ev.get("outVLabel")
    in_lab = ev.get("inVLabel")
    return u, v, lab, out_lab, in_lab


class GraphSONParser:
    """Parser for GraphSON v3 TinkerPop format (Joern CPG)"""

    # Common Joern node/edge labels (for informative validation)
    EXPECTED_VERTEX_TYPES = [
        "METHOD", "CALL", "IDENTIFIER", "LITERAL", "CONTROL_STRUCTURE", "LOCAL", "BLOCK",
        "METHOD_PARAMETER_IN", "METHOD_PARAMETER_OUT", "METHOD_RETURN",
        "TYPE", "FILE", "BINDING", "NAMESPACE"
    ]

    EXPECTED_EDGE_TYPES = [
        "AST", "CFG", "CDG", "DDG", "REACHING_DEF", "CALL",
        "ARGUMENT", "RECEIVER", "EVAL_TYPE", "CONTAINS", "REF", "DOMINATE", "PDG"
    ]

    def __init__(self, cpg_source: Union[str, Path, dict]):
        """
        cpg_source: GraphSON JSON file path or an already-loaded dict
        """
        self.cpg_source = cpg_source
        self.data: Optional[dict] = None
        self.vertices: List[dict] = []
        self.edges: List[dict] = []
        self._parsed = False
        self.source_code: Optional[str] = None

    def parse(self) -> bool:
        """Load and verify GraphSON v3 structure, extract vertices/edges."""
        try:
            if isinstance(self.cpg_source, (str, Path)):
                with open(self.cpg_source, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
            elif isinstance(self.cpg_source, dict):
                self.data = self.cpg_source
            else:
                raise TypeError("cpg_source must be a str/Path or a dict")

            if not _is_graphson_v3(self.data):
                print("❌ Invalid GraphSON v3: missing @value.vertices/edges")
                return False

            self.vertices = self.data["@value"].get("vertices", []) or []
            self.edges = self.data["@value"].get("edges", []) or []

            # Optional: retrieve a code snippet if included
            self.source_code = None
            for v in self.vertices:
                vv = v.get("@value", v)
                if vv.get("label") == "UNKNOWN":
                    props = self.extract_vertex_properties(v)
                    code_val = props.get("CODE")
                    if isinstance(code_val, str) and code_val.strip():
                        self.source_code = code_val
                        break

            self._parsed = True
            return True

        except Exception as e:
            print(f"❌ Error parsing CPG: {e}")
            return False

    def get_basic_stats(self) -> Dict[str, Any]:
        if not self._parsed:
            return {}
        n_nodes = len({ _id_of_vertex(v) for v in self.vertices })
        # if vertices are empty → infer via edges
        if n_nodes == 0 and self.edges:
            ids = set()
            for e in self.edges:
                u, v, *_ = _edge_fields(e)
                if u is not None: ids.add(u)
                if v is not None: ids.add(v)
            n_nodes = len(ids)

        n_edges = len(self.edges)
        return {
            "vertex_count": n_nodes,
            "edge_count": n_edges,
            "graph_density": (n_edges / n_nodes) if n_nodes else 0.0,
        }

    def get_vertex_types(self) -> Counter:
        if not self._parsed:
            return Counter()
        vt = Counter()
        seen = set()

        # 1) labels from vertices
        for v in self.vertices:
            vid = _id_of_vertex(v)
            lab = _label_of_vertex(v)
            if vid is not None:
                vt[lab] += 1
                seen.add(vid)

        # 2) complete from edges if nodes do not exist in vertices
        for e in self.edges:
            u, v, _, out_lab, in_lab = _edge_fields(e)
            if u is not None and u not in seen:
                vt[out_lab or "UNKNOWN"] += 1; seen.add(u)
            if v is not None and v not in seen:
                vt[in_lab or "UNKNOWN"] += 1; seen.add(v)

        return vt

    def get_edge_types(self) -> Counter:
        if not self._parsed:
            return Counter()
        et = Counter()
        for e in self.edges:
            _, _, lab, _, _ = _edge_fields(e)
            et[lab] += 1
        return et

    def validate_cpg_types(self) -> Dict[str, Any]:
        if not self._parsed:
            return {}
        found_v = set(self.get_vertex_types().keys())
        found_e = set(self.get_edge_types().keys())
        exp_v = set(self.EXPECTED_VERTEX_TYPES)
        exp_e = set(self.EXPECTED_EDGE_TYPES)
        return {
            "vertex_validation": {
                "expected_found": len(found_v & exp_v),
                "total_expected": len(exp_v),
                "additional_types": sorted(found_v - exp_v),
                "missing_types": sorted(exp_v - found_v),
            },
            "edge_validation": {
                "expected_found": len(found_e & exp_e),
                "total_expected": len(exp_e),
                "additional_types": sorted(found_e - exp_e),
                "missing_types": sorted(exp_e - found_e),
            },
        }

    def extract_vertex_properties(self, vertex: Dict[str, Any]) -> Dict[str, Any]:
        """Extract properties of a vertex (handles nested @value)."""
        vv = vertex.get("@value", vertex)
        props_in = vv.get("properties", {}) or {}
        out: Dict[str, Any] = {}
        for name, pdata in props_in.items():
            val = pdata
            # unwrap up to 3 levels if needed
            for _ in range(3):
                if isinstance(val, dict) and "@value" in val:
                    val = val["@value"]
                else:
                    break
            # if list, take the first element
            if isinstance(val, list) and val:
                val = val[0]
            out[name] = val
        return out

    def get_analysis_summary(self) -> Dict[str, Any]:
        if not self._parsed:
            return {"error": "File not parsed successfully"}
        return {
            "basic_stats": self.get_basic_stats(),
            "vertex_types": dict(self.get_vertex_types()),
            "edge_types": dict(self.get_edge_types()),
            "validation": self.validate_cpg_types(),
        }


def analyze_cpg_file(cpg_file: Path) -> Dict[str, Any]:
    p = GraphSONParser(cpg_file)
    if p.parse():
        return p.get_analysis_summary()
    return {"error": f"Failed to parse {cpg_file}"}
