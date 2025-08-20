#!/usr/bin/env python3
"""
Structural Retrieval System for Enhanced structuaral_vulrag

This module provides FAISS-based structural similarity search for vulnerability
detection pre-filtering. It uses the unified signature extraction module to ensure
consistency between build-time and runtime feature extraction.

Usage:
    from utils.structural_retriever import retrieve_structural
    similar_ids = retrieve_structural("path/to/query.cpg.json")  # Uses config STRUCTURAL_TOP_N
"""

import os
import sys
import json
import csv
import time
import numpy as np
from pathlib import Path
from typing import List, Dict, Any
import logging

# Add project root to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Import config
import config

try:
    import faiss
except ImportError:
    print("Error: FAISS not installed. Please install with: pip install faiss-cpu")
    sys.exit(1)

# Import unified signature extraction module
from utils.signature_extraction import UnifiedSignatureExtractor, get_feature_columns


class StructuralRetriever:
    """FAISS-based structural similarity retrieval system"""
    
    def __init__(self, signatures_path: str = None, faiss_index_path: str = None):
        """
        Initialize the structural retriever
        
        Args:
            signatures_path: Path to the vulnerability signatures CSV file
            faiss_index_path: Path to the FAISS index file
        """
        self.signatures_path = signatures_path or str(config.SIGNATURES_PATH)
        self.faiss_index_path = faiss_index_path or str(config.FAISS_INDEX_PATH)
        
        # Use unified signature extractor for consistency
        self.extractor = UnifiedSignatureExtractor()
        
        # Extract feature columns using unified definition (excludes instance_id)
        from utils.signature_extraction import get_feature_columns
        self.feature_columns = [col for col in get_feature_columns() if col != 'instance_id']
        
        # Load signatures (supports CSV or JSON)
        print(f"Loading signatures from: {self.signatures_path}")
        self.signatures = []
        if self.signatures_path and self.signatures_path.lower().endswith('.json'):
            with open(self.signatures_path, 'r') as f:
                self.signatures = json.load(f)
        else:
            # Default to CSV (expected format)
            with open(self.signatures_path, 'r', newline='') as f:
                reader = csv.DictReader(f)
                def _val_to_float(v):
                    if v is None:
                        return 0.0
                    s = str(v).strip()
                    if s == '':
                        return 0.0
                    lower = s.lower()
                    if lower in ('true', 'yes', 'y', 't'):
                        return 1.0
                    if lower in ('false', 'no', 'n', 'f'):
                        return 0.0
                    try:
                        return float(s)
                    except ValueError:
                        # Last resort: 0.0
                        return 0.0
                for row in reader:
                    instance_id = row.get('instance_id') or row.get('id') or row.get('instance') or ''
                    # Build features array in the exact unified order
                    features = [_val_to_float(row.get(col, 0)) for col in self.feature_columns]
                    self.signatures.append({'instance_id': instance_id, 'features': features})
        
        # NumPy matrix of features
        self.X = np.array([s['features'] for s in self.signatures], dtype='float32')
        
        # Load FAISS index
        print(f"Loading FAISS index from: {self.faiss_index_path}")
        self.index = faiss.read_index(self.faiss_index_path)
        
        print(f"Loaded {len(self.signatures)} signatures with {self.index.d} dimensions")
        print(f"Using unified feature columns: {len(self.feature_columns)} features")
    
    def extract_query_signature(self, cpg_path: str) -> np.ndarray:
        """
        Extract structural signature from query CPG using unified extractor
        
        Args:
            cpg_path: Path to the query CPG file
            
        Returns:
            NumPy array of structural features
        """
        signature = self.extractor.extract_signature(cpg_path)
        if not signature:
            # Return zeros if extraction fails
            return np.zeros(len(self.feature_columns), dtype='float32')
        
        # Convert to array in the same order as feature columns
        return np.array([signature.get(col, 0) for col in self.feature_columns], dtype='float32')
    
    def retrieve_structural(self, query_cpg_path: str, top_k: int = None) -> List[str]:
        """
        Retrieve structurally similar vulnerability instances
        
        Args:
            query_cpg_path: Path to query CPG JSON file
            top_k: Number of similar instances to retrieve (defaults to config STRUCTURAL_TOP_N)
            
        Returns:
            List of instance IDs sorted by structural similarity
        """
        if top_k is None:
            top_k = config.STRUCTURAL_TOP_N
        # Extract query signature using unified extractor
        q_vec = self.extract_query_signature(query_cpg_path)
        
        # Search in FAISS index
        distances, indices = self.index.search(q_vec.reshape(1, -1), top_k)
        
        # Return corresponding instance IDs
        return [self.signatures[i]['instance_id'] for i in indices[0]]
    
    def get_signature_stats(self) -> dict:
        """Get statistics about the loaded signatures"""
        if not self.signatures:
            return {'total_signatures': 0, 'feature_count': len(self.feature_columns)}
        
        # Extract features from signatures for stats
        features_dict = {}
        for sig in self.signatures:
            if isinstance(sig, dict) and 'features' in sig:
                # Convert features array back to dict for stats
                for i, col in enumerate(self.feature_columns):
                    if col not in features_dict:
                        features_dict[col] = []
                    if i < len(sig['features']):
                        features_dict[col].append(sig['features'][i])
        
        stats = {
            'total_signatures': len(self.signatures),
            'feature_count': len(self.feature_columns)
        }
        
        # Add feature-specific stats if available
        for feature in ['num_nodes', 'num_edges', 'is_flat_cpg', 'total_dangerous_calls']:
            if feature in features_dict and features_dict[feature]:
                if feature == 'total_dangerous_calls':
                    stats[f'total_{feature}'] = np.sum(features_dict[feature])
                else:
                    stats[f'avg_{feature}'] = np.mean(features_dict[feature])
        
        return stats


# Global retriever instance (lazy loading)
_retriever = None

def get_retriever(signatures_path: str = None, faiss_index_path: str = None) -> StructuralRetriever:
    """Initialize structural retriever with FAISS index and signatures"""
    global _retriever
    if _retriever is None:
        # Use centralized config for paths
        if signatures_path is None:
            signatures_path = str(config.SIGNATURES_PATH)
        if faiss_index_path is None:
            faiss_index_path = str(config.FAISS_INDEX_PATH)
        _retriever = StructuralRetriever(signatures_path, faiss_index_path)
    return _retriever

def retrieve_structural(query_cpg_path: str, top_k: int = None) -> List[str]:
    """
    Convenience function for structural retrieval
    
    Args:
        query_cpg_path: Path to query CPG JSON file
        top_k: Number of similar instances to retrieve (defaults to config STRUCTURAL_TOP_N)
        
    Returns:
        List of instance IDs sorted by structural similarity
    """
    if top_k is None:
        top_k = config.STRUCTURAL_TOP_N
    retriever = get_retriever()
    return retriever.retrieve_structural(query_cpg_path, top_k)


def test_unified_consistency():
    """Test consistency between unified extractor and loaded data"""
    print("🧪 Testing unified extractor consistency...")
    
    retriever = get_retriever()
    
    # Test feature column consistency
    csv_columns = set(retriever.feature_columns)
    unified_columns = set(get_feature_columns()) - {'instance_id'}
    
    if csv_columns == unified_columns:
        print("✅ Feature columns consistent between CSV and unified extractor")
    else:
        print("❌ Feature column mismatch:")
        print(f"  CSV has: {csv_columns - unified_columns}")
        print(f"  Unified has: {unified_columns - csv_columns}")
    
    # Test signature extraction on first entry
    if len(retriever.signatures) > 0:
        first_instance = retriever.signatures[0]['instance_id']
        print(f"Testing signature extraction consistency on: {first_instance}")
        
        # This would require the original CPG file to test properly
        # For now, just verify the extractor can be called
        from utils.signature_extraction import UnifiedSignatureExtractor
        extractor = UnifiedSignatureExtractor()
        print(f"✅ Unified extractor initialized with {len(extractor.feature_columns)} features")
    
    # Display stats
    stats = retriever.get_signature_stats()
    print(f"\n📊 Signature Statistics:")
    for key, value in stats.items():
        if isinstance(value, float):
            print(f"  {key}: {value:.2f}")
        else:
            print(f"  {key}: {value}")


def main():
    """Test the structural retriever with unified extraction"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test structural retrieval system with unified extractor")
    parser.add_argument("cpg_path", nargs='?', help="Path to query CPG file")
    parser.add_argument("--top_k", type=int, default=config.STRUCTURAL_TOP_N, help="Number of results to retrieve")
    parser.add_argument("--test_consistency", action="store_true", help="Test unified extractor consistency")
    parser.add_argument("--time", action="store_true", help="Measure retrieval time")
    
    args = parser.parse_args()
    
    print("="*60)
    print("🔍 STRUCTURAL RETRIEVAL TEST (UNIFIED EXTRACTOR)")
    print("="*60)
    
    if args.test_consistency:
        test_unified_consistency()
        return
    
    if not args.cpg_path:
        # Test with a sample CPG file
        test_cpg = "data/test_cpg.json"
        print(f"No CPG path provided, using test file: {test_cpg}")
    else:
        test_cpg = args.cpg_path
    
    if args.time:
        start_time = time.time()
    
    # Check if test file exists
    if not Path(test_cpg).exists():
        print(f"❌ Test CPG file not found: {test_cpg}")
        return []
    
    # Retrieve similar instances
    similar_ids = retrieve_structural(test_cpg, args.top_k)
    
    if args.time:
        elapsed_time = time.time() - start_time
        print(f"⏱️  Retrieval time: {elapsed_time:.4f} seconds")
    
    print(f"📊 Query: {test_cpg}")
    print(f"📊 Retrieved {len(similar_ids)} similar instances")
    print(f"📊 Top-{min(5, len(similar_ids))} similar IDs: {similar_ids[:5]}")
    
    # Show retriever stats
    retriever = get_retriever()
    stats = retriever.get_signature_stats()
    print(f"\n📈 Database Stats: {stats['total_signatures']} signatures, {stats['feature_count']} features")
    
    return similar_ids


if __name__ == "__main__":
    main()