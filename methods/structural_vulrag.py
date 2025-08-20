#!/usr/bin/env python3
"""
structuaral_vulrag Method - Structural pre-filtering → BM25 reranking → Iterative detection
"""

import time
import numpy as np
from typing import Dict, Any
import hashlib
import re

import config
from core.llm_client import LLMClient
from core.retrievers import StructuralRetriever, BM25Retriever
from core.detector import IterativeDetector
from utils.persistent_cache import PersistentDict


class structuaral_vulragMethod:
    """
    structuaral_vulrag: Structural pre-filtering → BM25 reranking → Iterative detection
    """
    
    def __init__(self):
        self.name = "structuaral_vulrag"
        
        # Initialize components
        self.llm = LLMClient()
        self.structural = StructuralRetriever()
        self.bm25 = BM25Retriever()
        self.detector = IterativeDetector(self.llm, self.bm25)
        
        # Statistics
        self.stats = {
            'analyses': 0,
            'structural_time': 0,
            'bm25_time': 0,
            'detection_time': 0
        }
        
        print(f"✅ {self.name} method initialized")
    
    def analyze(self, code: str, cpg_json_path: str = None, 
                instance_id: str = None) -> Dict[str, Any]:
        """
        Analyze structuaral_vulrag method
        
        Args:
            code: Code source to analyze
            cpg_json_path: Path to CPG JSON file (required for structural)
            instance_id: Instance ID (optional)
            
        Returns:
            Analysis result with verdict
        """
        start_time = time.time()
        
        if not self.llm.available:
            return self._error_result("LLM not available", instance_id)
        
        if cpg_json_path is None:
            return self._error_result("CPG JSON path required for structuaral_vulrag", instance_id)
        
        # Extract signature + structural hotspots from CPG JSON 
        from utils.signature_extraction import extract_signature, extract_hotspots, build_hotspot_tokens, build_structural_summary
        signature_dict = extract_signature(cpg_json_path)
        if not signature_dict:
            return self._error_result("Failed to extract CPG signature", instance_id)
        
        # Convert to numpy array for FAISS
        from utils.signature_extraction import get_feature_columns
        feature_columns = [col for col in get_feature_columns() if col != 'instance_id']
        cpg_signature = np.array([signature_dict.get(col, 0) for col in feature_columns], dtype='float32')
        
        try:
            # Step 1: Structural retrieval (10 candidates)
            struct_start = time.time()
            structural_candidates = self.structural.retrieve(
                cpg_signature, 
                top_k=config.STRUCTURAL_TOP_N
            )
            struct_time = time.time() - struct_start
            self.stats['structural_time'] += struct_time
            
            if not structural_candidates:
                # Fallback: run LLM with hotspot structural summary even without structural pool
                from utils.signature_extraction import extract_hotspots, build_structural_summary
                hotspots = extract_hotspots(cpg_json_path)
                struct_summary = build_structural_summary(hotspots)
                print("  Structural: 0 candidates -> running LLM with hotspot context (no retrieval)")

                detect_start = time.time()
                cause = self.detector._detect_cause(code, struct_summary)
                solution = self.detector._detect_solution(code, struct_summary)
                detect_time = time.time() - detect_start
                self.stats['detection_time'] += detect_time

                iterations = [{
                    'iteration': 1,
                    'instance_id': 'RAW_STRUCT',
                    'similarity_score': 0.0,
                    'cause_detection': cause,
                    'solution_detection': solution
                }]

                vulnerable = cause.get('detected') and not solution.get('present')
                total_time = time.time() - start_time
                result = {
                    'method': self.name,
                    'instance_id': instance_id,
                    'analysis_time': total_time,
                    'structural_candidates': 0,
                    'bm25_candidates': 0,
                    'iterations': len(iterations),
                    'detection_details': iterations,
                    'context': {
                        'type': 'structural_hotspots',
                        'structural_hotspots_used': True,
                        'bm25_biased_with_hotspots': False,
                        'hotspots_nonzero': ('No structural hotspots' not in struct_summary),
                        'note': 'Fallback LLM analysis using only structural hotspot summary (no retrieval)'
                    },
                    'timing': {
                        'structural': struct_time,
                        'bm25': 0.0,
                        'detection': detect_time,
                        'total': total_time
                    }
                }
                if vulnerable:
                    result.update({
                        'verdict': 'VULNERABLE',
                        'confidence': 'MEDIUM',
                        'confidence_score': 0.6,
                        'reason': 'Vulnerability indicated by LLM with hotspot context (no retrieval)'
                    })
                else:
                    result.update({
                        'verdict': 'SAFE',
                        'confidence': 'LOW',
                        'confidence_score': 0.4,
                        'reason': 'No vulnerability indicated by LLM with hotspot context (no retrieval)'
                    })
                self.stats['analyses'] += 1
                return result
            
            print(f"  Structural: {len(structural_candidates)} candidates")
            
            # Step 2: BM25 reranking (3 best)
            bm25_start = time.time()
            
            # Generate semantic descriptions to improve BM25
            query_purpose, query_behavior = self._generate_semantic_descriptions(code)

            # Build structural hotspot tokens & summary
            hotspots = extract_hotspots(cpg_json_path)
            struct_tokens = build_hotspot_tokens(hotspots)
            struct_summary = build_structural_summary(hotspots)

            # Bias BM25 with structural tokens
            biased_purpose = (query_purpose + "\n" + struct_tokens).strip()
            biased_behavior = (query_behavior + "\n" + struct_tokens).strip()
                
            # BM25 reranking strictly within the structural pool    
            filtered_candidates = self.bm25.retrieve(
                query_code=code,
                query_purpose=biased_purpose,
                query_behavior=biased_behavior,
                top_k=config.BM25_TOP_K,
                candidate_filter=structural_candidates
            )
            
            # BM25 global safety-net: trigger only when needed
            use_rescue = getattr(config, 'USE_BM25_RESCUE', True)
            rescue_top_m = getattr(config, 'BM25_RESCUE_TOP_M', max(config.BM25_TOP_K, 6))
            struct_boost = getattr(config, 'BM25_RESCUE_STRUCT_BOOST', 0.2)

            need_rescue = False
            if use_rescue:
                if not filtered_candidates:
                    need_rescue = True
                elif len(filtered_candidates) < config.BM25_TOP_K:
                    need_rescue = True
                else:
                    try:
                        max_score = max(score for _, score in filtered_candidates)
                        need_rescue = (max_score <= 1e-9)
                    except ValueError:
                        need_rescue = True

            if need_rescue:
                print("  BM25 rescue: running global BM25 and merging with structural pool")
                global_results = self.bm25.retrieve(
                    query_code=code,
                    query_purpose=biased_purpose,
                    query_behavior=biased_behavior,
                    top_k=rescue_top_m,
                    candidate_filter=None
                )
                # Merge with a small structural-origin boost
                struct_set = set(structural_candidates)
                merged_scores = {}
                for cid, score in filtered_candidates:
                    merged_scores[cid] = score + struct_boost
                for cid, score in global_results:
                    if cid in merged_scores:
                        merged_scores[cid] = max(merged_scores[cid], score)
                    else:
                        merged_scores[cid] = score
                merged_sorted = sorted(merged_scores.items(), key=lambda x: x[1], reverse=True)
                # If still empty, fall back to top structural
                if not merged_sorted:
                    print("  BM25 rescue still empty -> fallback to top structural candidates")
                    filtered_candidates = [(cid, 0.0) for cid in structural_candidates[:config.BM25_TOP_K]]
                else:
                    filtered_candidates = merged_sorted[:config.BM25_TOP_K]
            
            bm25_time = time.time() - bm25_start
            self.stats['bm25_time'] += bm25_time
            
            print(f"  BM25 (within structural): {len(filtered_candidates)} candidates")
            
            # Step 3: Iterative detection
            detect_start = time.time()
            result = self.detector.detect(code, filtered_candidates, extra_context=struct_summary)
            detect_time = time.time() - detect_start
            self.stats['detection_time'] += detect_time
            
            # Finalize result
            total_time = time.time() - start_time
            result.update({
                'method': self.name,
                'instance_id': instance_id,
                'analysis_time': total_time,
                'structural_candidates': len(structural_candidates),
                'bm25_candidates': len(filtered_candidates),
                # Mark the usage of hotspots and BM25 bias
                'context': {
                    'type': 'structural_hotspots+bias',
                    'structural_hotspots_used': True,
                    'bm25_biased_with_hotspots': bool(struct_tokens),
                    'hotspots_nonzero': ('No structural hotspots' not in struct_summary),
                    'note': 'Structural hotspots injected into detection context and used to bias BM25 queries'
                },
                'timing': {
                    'structural': struct_time,
                    'bm25': bm25_time, 
                    'detection': detect_time,
                    'total': total_time
                }
            })
            
            self.stats['analyses'] += 1
            return result
            
        except Exception as e:
            return self._error_result(f"structuaral_vulrag analysis failed: {e}", instance_id)
    
    def _error_result(self, error_msg: str, instance_id: str = None) -> Dict[str, Any]:
        """Standardized error result"""
        return {
            'verdict': 'ERROR',
            'confidence': 'LOW',
            'confidence_score': 0.0,
            'reason': error_msg,
            'method': self.name,
            'instance_id': instance_id,
            'analysis_time': 0.0
        }
    
    def _no_candidates_result(self, instance_id: str = None, 
                             stage: str = "unknown") -> Dict[str, Any]:
        """Standardized result when no candidates found"""
        return {
            'verdict': 'SAFE',
            'confidence': 'LOW',
            'confidence_score': 0.3,
            'reason': f'No candidates found at {stage} stage - defaulting to safe',
            'method': self.name,
            'instance_id': instance_id,
            'iterations': 0
        }
    
    def _generate_semantic_descriptions(self, code: str) -> tuple[str, str]:
        """Generate semantic descriptions with 2 prompts separated and cached"""
        if not self.llm.available:
            return "", ""
        # Persistent cache (disk-backed)
        if not hasattr(self, '_semantic_pcache'):
            self._semantic_pcache = PersistentDict(config.DATA_DIR / 'semantic_cache.json')
        code_slice = code[:2000]
        sha = hashlib.sha1(code_slice.encode('utf-8')).hexdigest()
        cache_key = f"structuaral_vulrag:{config.OLLAMA_MODEL}:{sha}"
        cached = self._semantic_pcache.get_tuple(cache_key)
        if cached and isinstance(cached, (list, tuple)) and len(cached) == 2:
            return tuple(cached)
        
        # Try with retries; if still empty, use heuristic fallback
        retries = int(getattr(config, 'LLM_SEMANTIC_RETRIES', 2))
        delay = float(getattr(config, 'LLM_RETRY_DELAY', 0.8))
        purpose, behavior = "", ""
        last_err = None
        for t in range(1, retries + 1):
            try:
                # Prompt 1: PURPOSE
                purpose_prompt = f"""Analyze this C/C++ code and describe its PURPOSE in ONE sentence.

CODE:
```c
{code[:1000]}
```

Respond with ONLY the purpose sentence, no extra text."""
                purpose = self.llm.call(purpose_prompt).strip()
                
                # Prompt 2: BEHAVIOR  
                behavior_prompt = f"""Analyze this C/C++ code and describe its BEHAVIOR as a list of key operations.

CODE:
```c
{code[:1000]}
```

Respond with ONLY the behavior description, no extra text."""
                behavior = self.llm.call(behavior_prompt).strip()
                if purpose or behavior:
                    break
            except Exception as e:
                last_err = e
                if t < retries:
                    time.sleep(delay)
                continue

        if not (purpose or behavior):
            print(f"⚠️ Semantic generation failed (structuaral_vulrag), using heuristic fallback: {last_err}")
            # Purpose heuristic: first non-empty line or inferred function name
            first_line = next((ln.strip() for ln in code.splitlines() if ln.strip()), '')
            fx = re.search(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*\)", code)
            fname = fx.group(1) if fx else "function"
            purpose = f"Summarize C/C++ {fname}: {first_line[:120]}" if first_line else f"Summarize C/C++ {fname}"
            # Behavior heuristic: list of risky ops if present
            keywords = [
                'malloc', 'free', 'new', 'delete', 'strcpy', 'strncpy', 'memcpy', 'memmove',
                'scanf', 'gets', 'fgets', 'printf', 'read', 'write', 'open', 'close',
                'socket', 'bind', 'listen', 'accept', 'recv', 'send', 'strcat'
            ]
            present = sorted(set(k for k in keywords if re.search(rf"\b{k}\b", code)))
            behavior = "; ".join(present) if present else "basic control flow and data operations"

        # Cache result persistently (even if heuristic)
        result = (purpose, behavior)
        self._semantic_pcache[cache_key] = list(result)
        return result
    
    def get_stats(self) -> Dict[str, Any]:
        """Statistiques d'usage"""
        analyses = self.stats['analyses']
        return {
            'method': self.name,
            'analyses': analyses,
            'avg_structural_time': self.stats['structural_time'] / max(analyses, 1),
            'avg_bm25_time': self.stats['bm25_time'] / max(analyses, 1),
            'avg_detection_time': self.stats['detection_time'] / max(analyses, 1),
            'llm_stats': self.llm.get_stats()
        }