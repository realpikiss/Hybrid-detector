#!/usr/bin/env python3
"""
Iterative vulnerability detector - Improved version with aggregation
"""

from typing import Dict, Any, List, Tuple
import re

import config
from .llm_client import LLMClient
from .retrievers import BM25Retriever


class IterativeDetector:
    """Iterative vulnerability detector with multi-level analysis and weighted aggregation"""
    
    def __init__(self, llm_client: LLMClient, bm25_retriever: BM25Retriever):
        self.llm = llm_client
        self.bm25 = bm25_retriever
    
    def detect(self, code: str, candidates: List[Tuple[str, float]], 
               max_iterations: int = None,
               extra_context: str = "") -> Dict[str, Any]:
        """
        Multi-level detection with weighted aggregation
        
        Args:
            code: Code to analyze
            candidates: List of (instance_id, score)
            max_iterations: Limit of iterations (default: 5)
            extra_context: Additional structural context
            
        Returns:
            Detection result with final verdict
        """
        max_iterations = max_iterations or getattr(config, 'MAX_ITERATIONS', 5)
        iterations = []
        votes = []  # (source, verdict, confidence)

        # Level 1: Direct analysis (baseline)
        try:
            direct = self._direct_vulnerability_analysis(code)
            votes.append(('direct', direct['verdict'], direct.get('confidence', 0.5)))
            iterations.append({
                'iteration': 0, 
                'instance_id': 'DIRECT', 
                'similarity_score': 0.0,
                'direct_analysis': direct
            })
            if getattr(config, 'DETECTION_DEBUG', False):
                print(f"[Detect][Direct] {direct['verdict']} (conf: {direct.get('confidence', 0.5):.3f})")
        except Exception as e:
            if getattr(config, 'DETECTION_DEBUG', False):
                print(f'[Detect][Direct] Failed: {e}')

        # Level 2: Contextual analysis with candidates
        candidates_to_check = candidates[:max_iterations]
        if getattr(config, 'DETECTION_DEBUG', False):
            print(f"[Detect] Candidates to check: {len(candidates_to_check)} (cap {max_iterations})")
        
        for i, (instance_id, score) in enumerate(candidates_to_check, 1):
            print(f"  Iteration {i}/{len(candidates_to_check)}: {instance_id}")
            
            kb_entry = self.bm25.get_kb_entry(instance_id)
            if not kb_entry:
                continue
            
            context = self._build_context(instance_id, kb_entry, score, i, extra_context=extra_context)
            if getattr(config, 'DETECTION_DEBUG', False):
                pur = kb_entry.get('GPT_purpose') or ''
                beh = kb_entry.get('GPT_function') or ''
                print(f"[Detect] KB semantics present -> purpose:{len(pur)>0} behavior:{len(beh)>0} | context_len:{len(context)}")
            
            # Cause and solution detection
            cause_result = self._detect_cause(code, context)
            solution_result = self._detect_solution(code, context) if cause_result.get('detected') else {'present': False, 'reasoning': 'Skipped - no cause detected'}

            iteration_detail = {
                'iteration': i,
                'instance_id': instance_id,
                'similarity_score': score,
                'cause_detection': cause_result,
                'solution_detection': solution_result
            }
            iterations.append(iteration_detail)

            # Convert to weighted vote
            verdict, conf = self._vote_from_cause_solution(cause_result, solution_result)
            votes.append((instance_id, verdict, conf))
            
            if getattr(config, 'DETECTION_DEBUG', False):
                print(f"[Detect][{instance_id}] cause:{cause_result.get('detected')} solution:{solution_result.get('present')} -> vote:{verdict} (conf:{conf:.3f})")

        # Level 3: Final aggregation
        final = self._aggregate_results(votes)
        final.update({
            'iterations': len(iterations),
            'detection_details': iterations,
            'total_votes': len(votes)
        })

        return final
    
    def _detect_cause(self, code: str, context: str) -> Dict[str, Any]:
        """Detect if a vulnerability cause is present"""
        prompt = f"""You are a security expert analyzing C/C++ code for vulnerabilities.

QUERY CODE TO ANALYZE:
```c
{code}
```

VULNERABILITY CONTEXT (from similar patterns):
{context}

TASK: Determine if the query code contains the same vulnerability pattern as described in the context.

Respond on the FIRST LINE with EXACTLY one of:
- CAUSE_DETECTED
- CAUSE_NOT_DETECTED

Then on following lines, provide detailed reasoning explaining your analysis."""
        
        try:
            if getattr(config, 'DETECTION_DEBUG', False):
                print("[Detect][Cause] Calling LLM with context length:", len(context))
            response = self.llm.call(prompt)
            
            # Parsing robuste
            detected = self._parse_cause_response(response)
            
            if getattr(config, 'DETECTION_DEBUG', False):
                first_line = next((ln.strip() for ln in response.split('\n') if ln.strip()), '')
                print(f"[Detect][Cause] First line: {first_line} -> detected: {detected}")

            return {
                'detected': detected,
                'raw_response': response,
                'reasoning': self._extract_reasoning(response)
            }

        except Exception as e:
            if getattr(config, 'DETECTION_DEBUG', False):
                print("[Detect][Cause] LLM call failed:", e)
            return {
                'detected': False,
                'raw_response': f"Error: {e}",
                'reasoning': f"LLM call failed: {e}"
            }
    
    def _detect_solution(self, code: str, context: str) -> Dict[str, Any]:
        """Detect if a solution/mitigation is present"""
        prompt = f"""You are a security expert analyzing C/C++ code for vulnerability mitigations.

QUERY CODE TO ANALYZE:
```c
{code}
```

VULNERABILITY CONTEXT AND SOLUTIONS:
{context}

TASK: Determine if the query code contains proper security mitigations for the vulnerability patterns described.

Respond on the FIRST LINE with EXACTLY one of:
- SOLUTION_PRESENT
- SOLUTION_ABSENT

Then on following lines, provide detailed reasoning explaining what mitigations you found or what's missing."""
        
        try:
            response = self.llm.call(prompt)
            
            # Parsing robuste
            present = self._parse_solution_response(response)
            
            if getattr(config, 'DETECTION_DEBUG', False):
                first_line = next((ln.strip() for ln in response.split('\n') if ln.strip()), '')
                print(f"[Detect][Solution] First line: {first_line} -> present: {present}")

            return {
                'present': present,
                'raw_response': response,
                'reasoning': self._extract_reasoning(response)
            }

        except Exception as e:
            if getattr(config, 'DETECTION_DEBUG', False):
                print("[Detect][Solution] LLM call failed:", e)
            return {
                'present': False,
                'raw_response': f"Error: {e}",
                'reasoning': f"LLM call failed: {e}"
            }
    
    def _build_context(self, instance_id: str, kb_entry: Dict[str, Any], 
                      score: float, rank: int, extra_context: str = "") -> str:
        """Build vulnerability context"""
        # Troncature configurable
        max_chars = getattr(config, 'CONTEXT_MAX_CODE_CHARS', None)
        code_before = str(kb_entry.get('code_before_change', ''))
        code_after = str(kb_entry.get('code_after_change', ''))
        
        if isinstance(max_chars, int) and max_chars > 0:
            if len(code_before) > max_chars:
                code_before = code_before[:max_chars] + "\n/* ...TRUNCATED... */"
            if len(code_after) > max_chars:
                code_after = code_after[:max_chars] + "\n/* ...TRUNCATED... */"

        return f"""### [SIMILAR VULNERABILITY ANALYSIS #{rank}]
- Instance ID: {instance_id}
- CWE: {kb_entry.get('cwe_id', 'N/A')}
- CVE: {kb_entry.get('cve_id', 'N/A')}
- Similarity Score: {score:.3f}

[Structural Context]
{extra_context or 'No additional structural context'}

[Abstract Purpose]
{kb_entry.get('GPT_purpose', 'No purpose description available')}

[Detailed Behavior]
{kb_entry.get('GPT_function', 'No behavior description available')}

[Root Vulnerability Pattern]
{kb_entry.get('vulnerability_type', 'No vulnerability pattern description')}

[Solution Pattern]
{kb_entry.get('solution', 'No solution description available')}

[Code Before Change - Vulnerable Pattern]
```c
{code_before}
```

[Code After Change - Fixed Pattern]
```c
{code_after}
```
"""
    
    def _extract_reasoning(self, response: str) -> str:
        """Extract reasoning from LLM response"""
        lines = [line.strip() for line in response.split('\n') if line.strip()]
        
        # Find first non-header line
        for line in lines:
            up = line.upper()
            if not up.startswith(('CAUSE_', 'SOLUTION_', 'VULNERABLE', 'SAFE')) and len(line) > 10:
                return line[:200] + "..." if len(line) > 200 else line
        
        return lines[0] if lines else "No reasoning provided"

    def _direct_vulnerability_analysis(self, code: str) -> Dict[str, Any]:
        """Direct analysis without context for baseline"""
        prompt = f"""You are a security expert. Analyze the following C/C++ code for security vulnerabilities.
        
CODE:
```c
{code}
```

Respond on the FIRST LINE with EXACTLY one of:
- VULNERABLE
- SAFE

Then provide detailed reasoning. Optionally include 'confidence: <0.0-1.0>' in your response."""

        response = self.llm.call(prompt)
        verdict = self._parse_direct_response(response)
        confidence = self._extract_confidence_score(response)
        
        return {
            'verdict': verdict,
            'confidence': confidence,
            'raw_response': response,
            'reasoning': self._extract_reasoning(response)
        }

    def _vote_from_cause_solution(self, cause: Dict[str, Any], solution: Dict[str, Any]) -> Tuple[str, float]:
        """Heuristic to transform cause/solution into weighted vote"""
        w_vuln = float(getattr(config, 'VOTE_WEIGHT_VULN', 0.75))
        w_safe_sol = float(getattr(config, 'VOTE_WEIGHT_SAFE_SOLUTION', 0.65))
        w_safe_def = float(getattr(config, 'VOTE_WEIGHT_SAFE_DEFAULT', 0.5))
        
        if cause.get('detected') and not solution.get('present', False):
            return 'VULNERABLE', w_vuln
        elif cause.get('detected') and solution.get('present'):
            return 'SAFE', w_safe_sol
        else:
            return 'SAFE', w_safe_def

    def _aggregate_results(self, votes: List[Tuple[str, str, float]]) -> Dict[str, Any]:
        """Weighted voting aggregation"""
        if not votes:
            return {
                'verdict': 'SAFE',
                'confidence': 'LOW',
                'confidence_score': 0.3,
                'reason': 'No analysis results available'
            }
        
        vul_weight = sum(conf for _, v, conf in votes if v == 'VULNERABLE')
        safe_weight = sum(conf for _, v, conf in votes if v != 'VULNERABLE')
        total_weight = max(vul_weight + safe_weight, 1e-6)
        
        vulnerability_score = vul_weight / total_weight
        threshold = float(getattr(config, 'AGG_VOTE_THRESHOLD', 0.55))
        
        verdict = 'VULNERABLE' if vulnerability_score >= threshold else 'SAFE'
        
        # Confidence basée sur la marge
        margin = abs(vulnerability_score - 0.5)
        if margin > 0.3:
            confidence_level = 'HIGH'
        elif margin > 0.15:
            confidence_level = 'MEDIUM'
        else:
            confidence_level = 'LOW'
        
        final_confidence = vulnerability_score if verdict == 'VULNERABLE' else (1 - vulnerability_score)
        
        reason = f'Weighted analysis: {len([v for _, v, _ in votes if v == "VULNERABLE"])}/{len(votes)} indicators suggest vulnerability' if verdict == 'VULNERABLE' else f'Weighted analysis: {len([v for _, v, _ in votes if v != "VULNERABLE"])}/{len(votes)} indicators suggest safety'

        if getattr(config, 'DETECTION_DEBUG', False):
            print("[Detect][Aggregate] votes:")
            for src, v, c in votes:
                print(f"  - source={src:12} vote={v:10} weight={c:.3f}")
            print(f"[Detect][Aggregate] vulnerability_score={vulnerability_score:.3f} threshold={threshold:.3f} -> {verdict}")

        return {
            'verdict': verdict,
            'confidence': confidence_level,
            'confidence_score': final_confidence,
            'reason': reason,
            'vulnerability_score': vulnerability_score,
            'threshold_used': threshold
        }

    def _extract_confidence_score(self, response: str) -> float:
        """Extract confidence [0..1] if present, otherwise 0.5"""
        patterns = [
            r"confidence\s*[:=]\s*([0-9]*\.?[0-9]+)",
            r"conf\s*[:=]\s*([0-9]*\.?[0-9]+)",
            r"certainty\s*[:=]\s*([0-9]*\.?[0-9]+)"
        ]
        
        for pattern in patterns:
            m = re.search(pattern, response, re.IGNORECASE)
            if m:
                try:
                    val = float(m.group(1))
                    if 0 <= val <= 1:
                        return val
                    # Handle percentages
                    elif 1 < val <= 100:
                        return val / 100.0
                except ValueError:
                    continue
        
        return 0.5

    def _parse_cause_response(self, response: str) -> bool:
        """Parse robuste pour CAUSE_DETECTED/CAUSE_NOT_DETECTED"""
        first_line = next((ln.strip() for ln in response.split('\n') if ln.strip()), '').upper()
        
        # Parsing strict d'abord
        if first_line == 'CAUSE_DETECTED':
            return True
        elif first_line == 'CAUSE_NOT_DETECTED':
            return False
        
        # Fallback: pattern-based parsing
        lower_resp = response.lower()
        cause_patterns = getattr(config, 'CAUSE_DETECTED_PATTERNS', [
            'cause detected', 'vulnerability found', 'security issue found', 
            'weakness identified', 'vulnerable pattern', 'exploit detected'
        ])
        
        for pattern in cause_patterns:
            if pattern.lower() in lower_resp:
                return True
        
        return False

    def _parse_solution_response(self, response: str) -> bool:
        """Parse robuste pour SOLUTION_PRESENT/SOLUTION_ABSENT"""
        first_line = next((ln.strip() for ln in response.split('\n') if ln.strip()), '').upper()
        
        # Parsing strict d'abord
        if first_line == 'SOLUTION_PRESENT':
            return True
        elif first_line == 'SOLUTION_ABSENT':
            return False
        
        # Fallback: pattern-based parsing
        lower_resp = response.lower()
        
        present_patterns = getattr(config, 'SOLUTION_PRESENT_PATTERNS', [
            'solution present', 'fix applied', 'patch implemented', 
            'security measure', 'mitigation found', 'protection added',
            'properly validated', 'bounds check', 'input validation'
        ])
        
        absent_patterns = getattr(config, 'SOLUTION_ABSENT_PATTERNS', [
            'solution absent', 'no fix', 'no patch', 'no mitigation', 
            'unpatched', 'no validation', 'missing check', 'insufficient protection'
        ])
        
        # Check for positive indicators
        has_solution = any(pattern.lower() in lower_resp for pattern in present_patterns)
        lacks_solution = any(pattern.lower() in lower_resp for pattern in absent_patterns)
        
        # Solution present if positive indicators and no strong negative indicators
        return has_solution and not lacks_solution

    def _parse_direct_response(self, response: str) -> str:
        """Parse robuste pour VULNERABLE/SAFE"""
        first_line = next((ln.strip() for ln in response.split('\n') if ln.strip()), '').upper()
        
        # Parsing strict d'abord
        if first_line == 'VULNERABLE':
            return 'VULNERABLE'
        elif first_line == 'SAFE':
            return 'SAFE'
        
        # Fallback: pattern-based parsing
        response_upper = response.upper()
        
        vuln_patterns = ['VULNERABLE', 'SECURITY ISSUE', 'VULNERABILITY FOUND', 'EXPLOIT', 'UNSAFE']
        safe_patterns = ['SAFE', 'SECURE', 'NO VULNERABILITY', 'NO SECURITY ISSUE']
        
        if any(pattern in response_upper for pattern in vuln_patterns):
            return 'VULNERABLE'
        elif any(pattern in response_upper for pattern in safe_patterns):
            return 'SAFE'
        
        # Default to SAFE if uncertain
        return 'SAFE'