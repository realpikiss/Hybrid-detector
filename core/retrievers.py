#!/usr/bin/env python3
"""
Unified retrievers - Structural + BM25 (This is a simple implementation, not optimized yet)
"""

import json
import pandas as pd
import numpy as np
from typing import List, Tuple, Dict, Any
from pathlib import Path
import re

try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False

try:
    from rank_bm25 import BM25Okapi
    BM25_AVAILABLE = True
except ImportError:
    BM25_AVAILABLE = False

import config


class StructuralRetriever:
    """Structural retrieval with FAISS - Enhanced version with unified signature extraction"""
    
    def __init__(self):
        self.index = None
        self.signatures = []
        self.loaded = False
        self.feature_columns = []
        self._load()
    
    def _load(self):
        """Load FAISS index and signatures"""
        if not FAISS_AVAILABLE:
            print("❌ FAISS not available")
            return
        
        try:
            # Import unified signature extraction
            from utils.signature_extraction import get_feature_columns
            self.feature_columns = [col for col in get_feature_columns() if col != 'instance_id']
            
            # Load FAISS index
            self.index = faiss.read_index(str(config.FAISS_INDEX_PATH))
            
            # Load signatures CSV
            import csv
            with open(config.SIGNATURES_PATH, 'r', newline='') as f:
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
                        return 0.0
                        
                for row in reader:
                    instance_id = row.get('instance_id') or row.get('id') or row.get('instance') or ''
                    features = [_val_to_float(row.get(col, 0)) for col in self.feature_columns]
                    self.signatures.append({'instance_id': instance_id, 'features': features})
            
            self.loaded = True
            print(f"✅ Structural retriever ready ({len(self.signatures)} entries)")
            
        except Exception as e:
            print(f"❌ Structural retriever error: {e}")
    
    def retrieve(self, query_signature: np.ndarray, top_k: int = 10) -> List[str]:
        """Structural retrieval"""
        if not self.loaded:
            return []
        
        try:
            # FAISS search
            query_vec = query_signature.reshape(1, -1).astype('float32')
            distances, indices = self.index.search(query_vec, top_k)
            
            # Map to instance_ids
            results = []
            for idx in indices[0]:
                if idx < len(self.signatures):
                    instance_id = self.signatures[idx]['instance_id']
                    results.append(instance_id)
            
            return results
            
        except Exception as e:
            print(f"❌ Structural retrieval error: {e}")
            return []


class BM25Retriever:
    """Semantic retrieval with BM25"""
    
    def __init__(self):
        self.kb_data = {}
        self.bm25_code = None
        self.bm25_purpose = None
        self.bm25_behavior = None
        self.instance_ids = []
        self.loaded = False
        self._load()
    
    def _tokenize(self, text: str) -> List[str]:
        """Regex-based tokenizer suitable for code and natural text.
        - Keeps identifiers/keywords/numbers
        - Splits on non-word, also splits camelCase and snake_case lightly
        - Filters very short tokens
        """
        if not text:
            return []
        s = str(text).lower()
        # Basic word tokens (letters, digits, underscore)
        tokens = re.findall(r"[a-zA-Z0-9_]+", s)
        out = []
        for tok in tokens:
            # split camelCase roughly
            subtoks = re.findall(r"[a-z]+|\d+", tok)
            if len(subtoks) > 1:
                out.extend(subtoks)
            else:
                out.append(tok)
        # filter short/noisy tokens
        return [t for t in out if len(t) >= 2]

    def _load(self):
        """Load KB and build BM25 index"""
        if not BM25_AVAILABLE:
            print("❌ BM25 not available")
            return
        
        try:
            # Load KB
            with open(config.KB_PATH, 'r') as f:
                raw_data = json.load(f)
            
            # Convert to flat mapping
            for key, entry in raw_data.items():
                instance_id = entry.get('instance_id', key)
                self.kb_data[instance_id] = entry
            
            self.instance_ids = list(self.kb_data.keys())
            
            # Build BM25 indices for each field
            self._build_bm25_indices()
            
            self.loaded = True
            print(f"✅ BM25 retriever ready ({len(self.kb_data)} entries)")
            
        except Exception as e:
            print(f"❌ BM25 retriever error: {e}")
    
    def _build_bm25_indices(self):
        """Build BM25 indices"""
        code_docs = []
        purpose_docs = []
        behavior_docs = []
        
        for instance_id in self.instance_ids:
            entry = self.kb_data[instance_id]
            
            # Improved tokenization
            code = self._tokenize(entry.get('code_before_change', ''))
            purpose = self._tokenize(entry.get('GPT_purpose', ''))
            behavior = self._tokenize(entry.get('GPT_function', ''))
            
            code_docs.append(code if code else ['empty'])
            purpose_docs.append(purpose if purpose else ['empty'])
            behavior_docs.append(behavior if behavior else ['empty'])
        
        # Build BM25 indices
        self.bm25_code = BM25Okapi(code_docs)
        self.bm25_purpose = BM25Okapi(purpose_docs)
        self.bm25_behavior = BM25Okapi(behavior_docs)
    
    def retrieve(self, query_code: str, query_purpose: str = "", 
                query_behavior: str = "", top_k: int = 3,
                candidate_filter: List[str] | None = None) -> List[Tuple[str, float]]:
        """BM25 retrieval with RRF weighted ranking
        
        Args:
            query_code: code query text
            query_purpose: PURPOSE description
            query_behavior: BEHAVIOR description
            top_k: number of results to return
            candidate_filter: if provided, only rank these instance_ids
        """
        if not self.loaded:
            return []
        
        try:
            # Tokenizer queries (improved)
            code_tokens = self._tokenize(query_code) if query_code else []
            purpose_tokens = self._tokenize(query_purpose) if query_purpose else []
            behavior_tokens = self._tokenize(query_behavior) if query_behavior else []
            
            # Calculer scores BM25 et rankings par champ
            field_rankings: Dict[str, List[str]] = {}
            
            if code_tokens:
                scores = self.bm25_code.get_scores(code_tokens)
                ranked = sorted(enumerate(scores), key=lambda x: x[1], reverse=True)
                field_rankings['code'] = [self.instance_ids[i] for i, _ in ranked]
            
            if purpose_tokens:
                scores = self.bm25_purpose.get_scores(purpose_tokens)
                ranked = sorted(enumerate(scores), key=lambda x: x[1], reverse=True)
                field_rankings['purpose'] = [self.instance_ids[i] for i, _ in ranked]
            
            if behavior_tokens:
                scores = self.bm25_behavior.get_scores(behavior_tokens)
                ranked = sorted(enumerate(scores), key=lambda x: x[1], reverse=True)
                field_rankings['behavior'] = [self.instance_ids[i] for i, _ in ranked]
            
            # RRF (Reciprocal Rank Fusion) pondéré
            weights = getattr(config, 'BM25_FIELD_WEIGHTS', {'code': 0.15, 'purpose': 0.35, 'behavior': 0.5})
            rrf_k = getattr(config, 'RRF_K', 60)
            rrf_scores: Dict[str, float] = {}
            candidate_pool = self.instance_ids if not candidate_filter else [cid for cid in self.instance_ids if cid in set(candidate_filter)]
            for candidate_id in candidate_pool:
                rrf_score = 0.0
                for field, ranking in field_rankings.items():
                    try:
                        rank = ranking.index(candidate_id) + 1
                        w = float(weights.get(field, 0.0))
                        rrf_score += w / (rrf_k + rank)
                    except ValueError:
                        continue
                rrf_scores[candidate_id] = rrf_score
            
            # Sort by RRF score
            sorted_results = sorted(rrf_scores.items(), key=lambda x: x[1], reverse=True)
            
            return sorted_results[:top_k]
            
        except Exception as e:
            print(f"❌ BM25 retrieval error: {e}")
            return []
    
    def get_kb_entry(self, instance_id: str) -> Dict[str, Any]:
        """Retrieve KB entry"""
        # Direct match
        entry = self.kb_data.get(instance_id)
        if entry:
            return entry

        # Normalization heuristics for structural IDs like '..._vuln.cpg'
        cid = instance_id
        # Strip common extensions
        for ext in ('.json', '.cpg', '.cpg.json'):
            if cid.endswith(ext):
                cid = cid[: -len(ext)]
        # Strip trailing markers
        for suf in ('_vuln', '_patch', '_fixed'):
            if cid.endswith(suf):
                cid = cid[: -len(suf)]
        # Try again
        entry = self.kb_data.get(cid)
        if entry:
            return entry

        # As a last resort, replace hyphens with underscores
        alt = cid.replace('-', '_')
        return self.kb_data.get(alt, {})