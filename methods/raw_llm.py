#!/usr/bin/env python3
"""
Raw LLM Baseline 
"""

import time
import json
from typing import Dict, Any

import config
from core.llm_client import LLMClient


class RawLLMMethod:
    """Raw LLM Baseline: Direct analysis by LLM"""
    
    def __init__(self):
        self.name = "Raw LLM"
        self.llm = LLMClient()
        
        # Statistics
        self.stats = {
            'analyses': 0,
            'analysis_time': 0
        }
        
        print(f"✅ {self.name} method initialized")
    
    def analyze(self, code: str, cpg_signature = None, 
                instance_id: str = None) -> Dict[str, Any]:
        """
        Raw LLM analysis
        
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
        
        try:
            # Create analysis prompt
            prompt = self._create_analysis_prompt(code)
            
            # Call LLM
            response = self.llm.call(prompt)
            
            # Parse JSON response
            result = self._parse_response(response)
            
            # Finalize result
            analysis_time = time.time() - start_time
            result.update({
                'method': self.name,
                'instance_id': instance_id,
                'analysis_time': analysis_time,
                'raw_response': response
            })
            
            self.stats['analyses'] += 1
            self.stats['analysis_time'] += analysis_time
            
            return result
            
        except Exception as e:
            return self._error_result(f"Raw LLM analysis failed: {e}", instance_id)
    
    def _create_analysis_prompt(self, code: str) -> str:
        """Create analysis prompt"""
        return f"""You are a cybersecurity expert analyzing C/C++ code for vulnerabilities.

TASK: Determine whether the following code contains security vulnerabilities. If none are present, respond SAFE.

CODE TO ANALYZE:
```c
{code}
```

INSTRUCTIONS:
1. Examine the code for common vulnerability patterns:
   - Buffer overflows (strcpy, gets, sprintf without bounds)
   - Use-after-free (accessing freed memory)
   - Memory leaks (malloc without free)
   - Integer overflows
   - Race conditions
   - Null pointer dereferences
   - Format string vulnerabilities

2. You MUST make a binary decision: SAFE or VULNERABLE
3. If evidence for vulnerability is insufficient, respond SAFE.
4. Be thorough but decisive. Focus on actual security issues, not code style.

RESPONSE FORMAT:
Output JSON only with the following keys and no extra text:
{{
  "verdict": "VULNERABLE" | "SAFE",
  "confidence": 0.0-1.0,
  "reason": "short, evidence-based explanation"
}}

Confidence scale guidance:
  * 0.9-1.0: Very confident in assessment
  * 0.7-0.9: Confident with good evidence  
  * 0.5-0.7: Moderate confidence
  * 0.3-0.5: Low confidence, limited evidence
  * 0.0-0.3: Very low confidence, forced decision"""
    
    def _parse_response(self, response: str) -> Dict[str, Any]:
        """Parse JSON response from LLM"""
        try:
            # Try to parse JSON directly
            if '{' in response and '}' in response:
                start = response.find('{')
                end = response.rfind('}') + 1
                json_str = response[start:end]
                parsed = json.loads(json_str)
                
                verdict = str(parsed.get('verdict', 'SAFE')).upper()
                confidence_score = float(parsed.get('confidence', 0.5))
                reason = str(parsed.get('reason', ''))
                
                # Validate verdict
                if verdict not in ['VULNERABLE', 'SAFE']:
                    verdict = 'SAFE'
                
                # Validate confidence
                confidence_score = max(0.0, min(1.0, confidence_score))
                
                return {
                    'verdict': verdict,
                    'confidence_score': confidence_score,
                    'confidence': self._confidence_level(confidence_score),
                    'reason': reason
                }
        
        except Exception:
            pass
        
        # Fallback parsing
        response_upper = response.upper()
        
        if 'VULNERABLE' in response_upper:
            verdict = 'VULNERABLE'
            confidence_score = 0.6
        else:
            verdict = 'SAFE'
            confidence_score = 0.5
        
        return {
            'verdict': verdict,
            'confidence_score': confidence_score,
            'confidence': self._confidence_level(confidence_score),
            'reason': 'Fallback parsing - see raw response'
        }
    
    def _confidence_level(self, score: float) -> str:
        """Convert score to level"""
        if score >= config.CONFIDENCE_HIGH:
            return "HIGH"
        elif score >= config.CONFIDENCE_MEDIUM:
            return "MEDIUM"
        else:
            return "LOW"
    
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
    
    def get_stats(self) -> Dict[str, Any]:
        """Usage statistics"""
        analyses = self.stats['analyses']
        return {
            'method': self.name,
            'analyses': analyses,
            'avg_analysis_time': self.stats['analysis_time'] / max(analyses, 1),
            'llm_stats': self.llm.get_stats()
        }