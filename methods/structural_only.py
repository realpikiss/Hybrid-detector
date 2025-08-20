#!/usr/bin/env python3
"""
Structural Only Baseline - Structural retrieval(3) → Iterative Detection
"""

import time
import numpy as np
from typing import Dict, Any, Optional

import config
from core.llm_client import LLMClient
from core.retrievers import StructuralRetriever, BM25Retriever
from core.detector import IterativeDetector


class StructuralOnlyMethod:
    """Baseline: Structural retrieval → Iterative detection"""
    
    def __init__(self):
        self.name = "Structural Only"
        
        # Initialize components
        self.llm = LLMClient()
        self.structural = StructuralRetriever()
        self.bm25 = BM25Retriever()  # Necessary for iterative detection (KB access)
        self.detector = IterativeDetector(self.llm, self.bm25)
        
        # Statistics
        self.stats = {
            'analyses': 0,
            'structural_time': 0,
            'detection_time': 0
        }
        
        print(f"✅ {self.name} method initialized")
    
    def analyze(self, code: str, cpg_json_path: str = None, 
                instance_id: str = None) -> Dict[str, Any]:
        """
        Analyze Structural → Iterative
        
        Args:
            code: Code source to analyze
            cpg_json_path: Path to CPG JSON file (required)
            instance_id: Instance ID (optional)
            
        Returns:
            Analysis result with verdict
        """
        start_time = time.time()
        
        if not self.llm.available:
            return self._error_result("LLM not available", instance_id)
        
        if not self.structural.loaded:
            return self._error_result("Structural retriever not loaded", instance_id)
        
        if cpg_json_path is None:
            return self._error_result("CPG JSON path required for structural retrieval", instance_id)
        
        # Extract signature from CPG JSON
        from utils.signature_extraction import extract_signature, get_feature_columns
        signature_dict = extract_signature(cpg_json_path)
        if not signature_dict:
            return self._error_result("Failed to extract CPG signature", instance_id)
        
        # Convert to numpy array for FAISS
        feature_columns = [col for col in get_feature_columns() if col != 'instance_id']
        cpg_signature = np.array([signature_dict.get(col, 0) for col in feature_columns], dtype='float32')
        
        try:
            # Step 1: Structural retrieval (3 candidates)
            struct_start = time.time()
            structural_candidates = self.structural.retrieve(
                cpg_signature, 
                top_k=3  # Directly 3 candidates
            )
            struct_time = time.time() - struct_start
            self.stats['structural_time'] += struct_time
            
            if not structural_candidates:
                # Fallback: run LLM with hotspot structural summary even without candidates
                from utils.signature_extraction import extract_hotspots, build_structural_summary
                struct_summary = build_structural_summary(extract_hotspots(cpg_json_path))
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
                    'iterations': len(iterations),
                    'detection_details': iterations,
                    'context': {
                        'type': 'structural_hotspots',
                        'structural_hotspots_used': True,
                        'hotspots_nonzero': ('No structural hotspots' not in struct_summary),
                        'note': 'Fallback LLM analysis using only structural hotspot summary (no retrieval)'
                    },
                    'timing': {
                        'structural': struct_time,
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
            
            # Convert to (id, score) format for detector
            # Use uniform scores since FAISS gives distances
            candidates_with_scores = [(cid, 1.0) for cid in structural_candidates]

            # Extract and build structural summary (hotspots)
            from utils.signature_extraction import extract_hotspots, build_structural_summary
            struct_summary = build_structural_summary(extract_hotspots(cpg_json_path))
            
            # Step 2: Iterative detection with structural context
            detect_start = time.time()
            result = self.detector.detect(code, candidates_with_scores, extra_context=struct_summary)
            detect_time = time.time() - detect_start
            self.stats['detection_time'] += detect_time
            
            # Finalize result
            total_time = time.time() - start_time
            result.update({
                'method': self.name,
                'instance_id': instance_id,
                'analysis_time': total_time,
                'structural_candidates': len(structural_candidates),
                # Explicitly mark usage of structural hotspot context
                'context': {
                    'type': 'structural_hotspots',
                    'structural_hotspots_used': True,
                    'hotspots_nonzero': ('No structural hotspots' not in struct_summary),
                    'note': 'Analysis used structural hotspot summary in detection context'
                },
                'timing': {
                    'structural': struct_time,
                    'detection': detect_time,
                    'total': total_time
                }
            })
            
            self.stats['analyses'] += 1
            return result
            
        except Exception as e:
            return self._error_result(f"Structural analysis failed: {e}", instance_id)
    
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
    
    def _no_candidates_result(self, instance_id: str = None) -> Dict[str, Any]:
        """Result when no candidates found"""
        return {
            'verdict': 'SAFE',
            'confidence': 'LOW',
            'confidence_score': 0.3,
            'reason': 'No structural candidates found - defaulting to safe',
            'method': self.name,
            'instance_id': instance_id,
            'iterations': 0
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Usage statistics"""
        analyses = self.stats['analyses']
        return {
            'method': self.name,
            'analyses': analyses,
            'avg_structural_time': self.stats['structural_time'] / max(analyses, 1),
            'avg_detection_time': self.stats['detection_time'] / max(analyses, 1),
            'llm_stats': self.llm.get_stats()
        }