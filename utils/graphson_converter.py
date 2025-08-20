"""
Unified CPG GraphSON v3 → NetworkX MultiDiGraph converter.
Uses GraphSONParser and provides an interface for encoding.

Usage:
    from utils.graphson_converter import load_and_convert_cpg

    # Load a CPG from a file or directory
    G = load_and_convert_cpg("/path/to/cpg.json")

    # The NetworkX graph is ready for encoding
    print(f"Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, List, Optional

import networkx as nx

# Import existing GraphSON parser
from utils.graphson_parser import GraphSONParser


def load_and_convert_cpg(input_path: str) -> nx.MultiDiGraph:
    """
    Convert a SINGLE CPG GraphSON file to NetworkX.
    
    Args:
        input_path: Path to a single GraphSON JSON file
        
    Returns:
        NetworkX MultiDiGraph for this specific CPG
        
    Raises:
        FileNotFoundError: If file does not exist
        ValueError: If not a valid GraphSON v3 file
    """
    path = Path(input_path)
    
    if not path.exists():
        raise FileNotFoundError(f"CPG file not found: {path}")
    
    if not path.is_file():
        raise ValueError(f"Expected a file, got directory: {path}")
    
    # Convert single file only
    return _convert_single_file(path)


def _convert_single_file(cpg_path: Path) -> nx.MultiDiGraph:
    """Convert a single CPG GraphSON file to NetworkX."""
    try:
        # Use GraphSONParser with the correct parameter
        parser = GraphSONParser(cpg_path)
        
        if not parser.parse():
            raise ValueError(f"Parse GraphSON failed: {cpg_path}")
        
        # Convert to NetworkX MultiDiGraph (parser only)
        return _graphson_to_networkx(parser)
        
    except Exception as e:
        raise ValueError(f"Error converting {cpg_path}: {e}")




def _graphson_to_networkx(parser: GraphSONParser) -> nx.MultiDiGraph:
    """
    Convert a GraphSONParser → NetworkX MultiDiGraph.
    
    """
    G = nx.MultiDiGraph()
    
    # Helper to unpack @value
    def peel_value(x):
        if isinstance(x, dict) and "@value" in x:
            return x["@value"]
        return x
    
    # 1) Add vertices (if present)
    for vertex in parser.vertices:
        # Extract ID and label
        vid = None
        vlabel = "UNKNOWN"
        
        # ID from vertex
        if isinstance(vertex, dict):
            if "@value" in vertex:
                vdata = vertex["@value"]
                vid = peel_value(vdata.get("id"))
                vlabel = vdata.get("label", "UNKNOWN")
            else:
                vid = peel_value(vertex.get("id"))
                vlabel = vertex.get("label", "UNKNOWN")
        
        if vid is None:
            continue
            
        # Vertex properties
        props = {"label": vlabel}
        
        # Extract additional properties via GraphSONParser
        vertex_props = parser.extract_vertex_properties(vertex)
        props.update(vertex_props)
        
        G.add_node(vid, **props)
    
    # 2) Add edges
    for edge in parser.edges:
        # Extract edge fields
        u, v, elabel, out_vlabel, in_vlabel = _extract_edge_fields(edge)
        
        if u is None or v is None:
            continue
            
        G.add_edge(u, v, label=elabel)
        
        # Complete missing nodes via *VLabel from edges
        if u not in G:
            G.add_node(u, label=out_vlabel or "UNKNOWN")
        else:
            G.nodes[u].setdefault("label", out_vlabel or "UNKNOWN")
            
        if v not in G:
            G.add_node(v, label=in_vlabel or "UNKNOWN")
        else:
            G.nodes[v].setdefault("label", in_vlabel or "UNKNOWN")
    
    return G


def _extract_edge_fields(edge: Dict[str, Any]) -> tuple:
    """Extract fields from a GraphSON edge."""
    def peel_value(x):
        if isinstance(x, dict) and "@value" in x:
            return x["@value"]
        return x
    
    # Unpack edge
    edata = edge.get("@value", edge)
    
    u = peel_value(edata.get("outV"))
    v = peel_value(edata.get("inV"))
    elabel = edata.get("label", "UNKNOWN")
    out_vlabel = edata.get("outVLabel")
    in_vlabel = edata.get("inVLabel")
    
    return u, v, elabel, out_vlabel, in_vlabel


def _merge_parsers(parsers: List[GraphSONParser]) -> nx.MultiDiGraph:
    """Merge multiple GraphSONParsers into a single NetworkX graph."""
    G = nx.MultiDiGraph()
    
    # Merge all vertices and edges
    all_vertices = []
    all_edges = []
    
    for parser in parsers:
        all_vertices.extend(parser.vertices)
        all_edges.extend(parser.edges)
    
    # Create a temporary parser with merged data
    merged_parser = GraphSONParser()
    merged_parser.vertices = all_vertices
    merged_parser.edges = all_edges
    merged_parser._parsed = True
    
    return _graphson_to_networkx(merged_parser)


def get_graph_stats(G: nx.MultiDiGraph) -> Dict[str, Any]:
    """Quick statistics for a NetworkX graph."""
    # Count node types
    node_types = {}
    for _, data in G.nodes(data=True):
        ntype = data.get("label", "UNKNOWN")
        node_types[ntype] = node_types.get(ntype, 0) + 1
    
    # Count edge types
    edge_types = {}
    for _, _, data in G.edges(data=True):
        etype = data.get("label", "UNKNOWN")
        edge_types[etype] = edge_types.get(etype, 0) + 1
    
    return {
        "nodes": G.number_of_nodes(),
        "edges": G.number_of_edges(),
        "node_types": dict(node_types),
        "edge_types": dict(edge_types),
        "unique_node_types": len(node_types),
        "unique_edge_types": len(edge_types)
    }



