#!/usr/bin/env python3
"""
vulrag Baseline - BM25 retrieval(3) → Iterative Detection (this mimic the pipeline used by  VulRAG approach of Du et al (2024))
"""

import time
import re
from typing import Dict, Any, Optional
from pathlib import Path
import hashlib

import config
from core.llm_client import LLMClient
from core.retrievers import BM25Retriever
from core.detector import IterativeDetector
from utils.persistent_cache import PersistentDict


class vulragMethod:
    """Baseline: BM25 retrieval → Iterative detection"""
    
    def __init__(self):
        self.name = "vulrag"
        
        # Initialize components
        self.llm = LLMClient()
        self.bm25 = BM25Retriever()
        self.detector = IterativeDetector(self.llm, self.bm25)
        
        # Statistics
        self.stats = {
            'analyses': 0,
            'bm25_time': 0,
            'detection_time': 0
        }
        
        print(f"✅ {self.name} method initialized")
    
    def analyze(self, code: str, cpg_signature = None, 
                instance_id: str = None) -> Dict[str, Any]:
        """
        Analyze BM25 → Iterative
        
        Args:
            code: Code source to analyze
            cpg_signature: Ignored (not used)
            instance_id: Instance ID (optional)
            
        Returns:    
            Analysis result with verdict
        """
        start_time = time.time()
        
        if not self.llm.available:
            return self._error_result("LLM not available", instance_id)
        
        if not self.bm25.loaded:
            return self._error_result("BM25 retriever not loaded", instance_id)
        
        try:
            # Step 1: BM25 retrieval over the entire KB (3 best)
            bm25_start = time.time()
            # Generate semantic descriptions to improve BM25 (same fields as structuaral_vulrag)
            query_purpose, query_behavior = self._generate_semantic_descriptions(code)
            bm25_candidates = self.bm25.retrieve(
                query_code=code,
                query_purpose=query_purpose,
                query_behavior=query_behavior,
                top_k=3  # Directly 3 candidates
            )
            bm25_time = time.time() - bm25_start
            self.stats['bm25_time'] += bm25_time
            
            if not bm25_candidates:
                # Fallback: run raw LLM analysis without context (like raw)
                print("  BM25: 0 candidates -> running raw LLM analysis (no context)")
                detect_start = time.time()
                # Build minimal context (none)
                raw_context = ""
                cause = self.detector._detect_cause(code, raw_context)
                solution = self.detector._detect_solution(code, raw_context)
                detect_time = time.time() - detect_start
                self.stats['detection_time'] += detect_time

                iterations = [{
                    'iteration': 1,
                    'instance_id': 'RAW',
                    'similarity_score': 0.0,
                    'cause_detection': cause,
                    'solution_detection': solution
                }]

                vulnerable = cause.get('detected') and not solution.get('present')
                total_time = time.time() - start_time
                base = {
                    'method': self.name,
                    'instance_id': instance_id,
                    'analysis_time': total_time,
                    'bm25_candidates': 0,
                    'iterations': len(iterations),
                    'detection_details': iterations,
                    'context': {
                        'type': 'none',
                        'structural_hotspots_used': False,
                        'note': 'Raw LLM analysis executed due to no BM25 candidates'
                    },
                    'timing': {
                        'bm25': bm25_time,
                        'detection': detect_time,
                        'total': total_time
                    }
                }
                if vulnerable:
                    base.update({
                        'verdict': 'VULNERABLE',
                        'confidence': 'MEDIUM',
                        'confidence_score': 0.6,
                        'reason': 'Vulnerability indicated by LLM in raw analysis (no retrieval context)'
                    })
                else:
                    base.update({
                        'verdict': 'SAFE',
                        'confidence': 'LOW',
                        'confidence_score': 0.4,
                        'reason': 'No vulnerability indicated by LLM in raw analysis (no retrieval context)'
                    })
                self.stats['analyses'] += 1
                return base
            
            print(f"  BM25: {len(bm25_candidates)} candidates")
            
            # Step 2: Iterative detection
            detect_start = time.time()
            result = self.detector.detect(code, bm25_candidates)
            detect_time = time.time() - detect_start
            self.stats['detection_time'] += detect_time
            
            # Finalize result
            total_time = time.time() - start_time
            result.update({
                'method': self.name,
                'instance_id': instance_id,
                'analysis_time': total_time,
                'bm25_candidates': len(bm25_candidates),
                # Mark explicitly the absence of structural context
                'context': {
                    'type': 'none',
                    'structural_hotspots_used': False,
                    'note': 'Analysis performed without structural context (raw)'
                },
                'timing': {
                    'bm25': bm25_time,
                    'detection': detect_time,
                    'total': total_time
                }
            })
            
            self.stats['analyses'] += 1
            return result
            
        except Exception as e:
            return self._error_result(f"BM25 analysis failed: {e}", instance_id)
    
    def _generate_semantic_descriptions(self, code: str) -> tuple[str, str]:
        """Generate PURPOSE and BEHAVIOR via LLM with in-memory cache."""
        if not self.llm.available:
            return "", ""

        # Persistent cache (disk-backed)
        if not hasattr(self, '_semantic_pcache'):
            self._semantic_pcache = PersistentDict(config.DATA_DIR / 'semantic_cache.json')
        # Stable key: sha1 of full code (limited to 2000 chars to avoid huge keys but deterministic)
        code_slice = code[:2000]
        sha = hashlib.sha1(code_slice.encode('utf-8')).hexdigest()
        cache_key = f"vulrag:{config.OLLAMA_MODEL}:{sha}"
        cached = self._semantic_pcache.get_tuple(cache_key)
        if cached and isinstance(cached, (list, tuple)) and len(cached) == 2:
            return tuple(cached)
        
        # Try LLM with a couple retries; fallback to heuristic if empty/fails
        retries = int(getattr(config, 'LLM_SEMANTIC_RETRIES', 2))
        delay = float(getattr(config, 'LLM_RETRY_DELAY', 0.8))
        purpose, behavior = "", ""
        last_err = None
        for t in range(1, retries + 1):
            try:
                purpose_prompt = f"""Analyze this C/C++ code and describe its PURPOSE in ONE sentence.

CODE:
```c
{code[:1000]}
```

Respond with ONLY the purpose sentence, no extra text."""
                purpose = self.llm.call(purpose_prompt).strip()

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
            # Heuristic fallback
            print(f"⚠️ Semantic generation failed (vulrag), using heuristic fallback: {last_err}")
            # Purpose: derive from first non-empty code line or function signature
            first_line = next((ln.strip() for ln in code.splitlines() if ln.strip()), '')
            fx = re.search(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*\)", code)
            fname = fx.group(1) if fx else "function"
            purpose = f"Summarize C/C++ {fname}: {first_line[:120]}" if first_line else f"Summarize C/C++ {fname}"
            # Behavior: collect key operations keywords
            keywords = [
                'malloc', 'free', 'new', 'delete', 'strcpy', 'strncpy', 'memcpy', 'memmove',
                'scanf', 'gets', 'fgets', 'printf', 'read', 'write', 'open', 'close',
                'socket', 'bind', 'listen', 'accept', 'recv', 'send', 'strcat'
            ]
            present = sorted(set(k for k in keywords if re.search(rf"\b{k}\b", code)))
            behavior = "; ".join(present) if present else "basic control flow and data operations"

        result = (purpose, behavior)
        # Save to persistent cache
        self._semantic_pcache[cache_key] = list(result)
        return result
    
    def _error_result(self, error_msg: str, instance_id: str = None) -> Dict[str, Any]:
        """Résultat d'erreur standardisé"""
        return {
            'verdict': 'ERROR',
            'confidence': 'LOW',
            'confidence_score': 0.0,
            'reason': error_msg,
            'method': self.name,
            'instance_id': instance_id,
            'analysis_time': 0.0
        }
    
    def _no_candidates_result(self, instance_id: str = None) -> Dict[str, Any]:
        """Result when no candidate found"""  
        return {
            'verdict': 'SAFE',
            'confidence': 'LOW',
            'confidence_score': 0.3,
            'reason': 'No BM25 candidates found - defaulting to safe',
            'method': self.name,
            'instance_id': instance_id,
            'iterations': 0
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Statistics"""
        analyses = self.stats['analyses']
        return {
            'method': self.name,
            'analyses': analyses,
            'avg_bm25_time': self.stats['bm25_time'] / max(analyses, 1),
            'avg_detection_time': self.stats['detection_time'] / max(analyses, 1),
            'llm_stats': self.llm.get_stats()
        }