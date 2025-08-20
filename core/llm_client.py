#!/usr/bin/env python3
"""
Unified LLM client
"""

import time
from typing import Dict, Any

try:
    from ollama import Client
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

import config


class LLMClient:
    """LLM client for all methods with cache"""
    
    def __init__(self):
        self.model = config.OLLAMA_MODEL
        self.client = None
        self.available = False
        self.stats = {'calls': 0, 'total_time': 0, 'cache_hits': 0}
        self._cache = {}  # Simple cache for repeated calls
        
        self._init_client()
    
    def _init_client(self):
        """Initialize Ollama client"""
        if not OLLAMA_AVAILABLE:
            print("❌ Ollama not available")
            return
        
        try:
            host = getattr(config, 'OLLAMA_HOST', 'http://localhost:11434')
            key = getattr(config, 'OLLAMA_API_KEY', None)
            # For Turbo (cloud) at https://ollama.com, ensure 'Bearer ' prefix
            if key and 'ollama.com' in host and not str(key).lower().startswith('bearer '):
                auth_value = f"Bearer {key}"
            else:
                auth_value = key
            headers = {'Authorization': auth_value} if auth_value else {}
            self.client = Client(host=host, headers=headers)
            
            # Test rapide
            self.client.chat(self.model, messages=[{'role': 'user', 'content': 'ping'}])
            self.available = True
            print(f"✅ LLM client ready ({self.model}) @ {host}")
            
        except Exception as e:
            print(f"❌ LLM client error: {e}")
            if 'ollama.com' in str(getattr(config, 'OLLAMA_HOST', '')):
                print("ℹ️ If you're using Turbo (cloud), ensure OLLAMA_HOST='https://ollama.com' and a valid API key is set in config.OLLAMA_API_KEY or env OLLAMA_API. Header will be sent as 'Bearer <key>'.")
            self.available = False
    
    def call(self, prompt: str) -> str:
        """LLM call with cache"""
        if not self.available:
            raise RuntimeError("LLM not available")
        
        # Check cache first
        cache_key = hash(prompt)
        if cache_key in self._cache:
            self.stats['cache_hits'] += 1
            return self._cache[cache_key]
        
        start = time.time()
        
        max_retries = int(getattr(config, 'LLM_MAX_RETRIES', 3))
        retry_delay = float(getattr(config, 'LLM_RETRY_DELAY', 0.8))
        last_err = None
        for attempt in range(1, max_retries + 1):
            try:
                response = self.client.chat(
                    self.model,
                    messages=[{'role': 'user', 'content': prompt}],
                    options={
                        'temperature': getattr(config, 'LLM_TEMPERATURE', 0.2),
                        'top_p': getattr(config, 'LLM_TOP_P', 0.9),
                        'top_k': getattr(config, 'LLM_TOP_K', 50)
                    }
                )
                result = response['message']['content'].strip()
                if result:
                    # Cache result
                    self._cache[cache_key] = result
                    self.stats['calls'] += 1
                    self.stats['total_time'] += time.time() - start
                    return result
                else:
                    last_err = RuntimeError("Empty LLM response")
                    raise last_err
            except Exception as e:
                last_err = e
                if attempt < max_retries:
                    time.sleep(retry_delay)
                else:
                    break
        raise RuntimeError(f"LLM call failed after {max_retries} attempts: {last_err}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Usage statistics"""
        avg_time = self.stats['total_time'] / max(self.stats['calls'], 1)
        return {
            'model': self.model,
            'calls': self.stats['calls'],
            'cache_hits': self.stats['cache_hits'],
            'total_time': self.stats['total_time'],
            'avg_time': avg_time,
            'available': self.available
        }

    def clear_cache(self) -> None:
        """Clear in-memory LLM response cache and reset timing stats."""
        self._cache.clear()
        self.stats = {'calls': 0, 'total_time': 0, 'cache_hits': 0}