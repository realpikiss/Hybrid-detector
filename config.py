#!/usr/bin/env python3
"""
Configuration simple pour l'évaluation structuaral_vulrag
"""

import os
from pathlib import Path

# Base paths (relative to the structuaral_vulrag-evaluation directory)
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
RESULTS_DIR = BASE_DIR / "results"

# Data files
KB_PATH = DATA_DIR / "kb.json"
SIGNATURES_PATH = DATA_DIR / "signatures.csv" 
FAISS_INDEX_PATH = DATA_DIR / "faiss.index"
EVALUATION_SET_PATH = DATA_DIR / "evaluation_set.csv"

# Configuration LLM
# Use Turbo (cloud) by default; requires valid API key in env OLLAMA_API
OLLAMA_HOST = "https://ollama.com"
OLLAMA_MODEL = "gpt-oss:120b"
OLLAMA_API_KEY = os.getenv('OLLAMA_API', '')
LLM_TEMPERATURE = 0.1
LLM_TOP_P = 0.9
LLM_TOP_K = 40

# Configuration methods
STRUCTURAL_TOP_N = 10  # structuaral_vulrag: structural candidates
BM25_TOP_K = 3         # structuaral_vulrag: semantic reranking
MAX_ITERATIONS = 8     # Iterative detection limit (increased for deeper checks)

# Confidence thresholds
CONFIDENCE_HIGH = 0.8
CONFIDENCE_MEDIUM = 0.5
CONFIDENCE_LOW = 0.3

# Patterns for LLM responses
CAUSE_DETECTED_PATTERNS = ["CAUSE_DETECTED", "cause detected", "vulnerability found"]
SOLUTION_PRESENT_PATTERNS = ["SOLUTION_PRESENT", "solution present", "fix applied"]
SOLUTION_ABSENT_PATTERNS = ["SOLUTION_ABSENT", "solution absent", "no fix"]

# Context and detection limits
# Set to None to disable truncation (models with large context window ~128k)
CONTEXT_MAX_CODE_CHARS = None
DETECTION_DEBUG = True         # Additional logs around LLM calls

# Aggregation and vote weighting
# Aggregation threshold for judging VULNERABLE (score >= threshold => VULNERABLE)
AGG_VOTE_THRESHOLD = 0.55
VOTE_WEIGHT_VULN = 0.75
VOTE_WEIGHT_SAFE_SOLUTION = 0.65
VOTE_WEIGHT_SAFE_DEFAULT = 0.5

def ensure_dirs():
    """Create necessary directories"""
    DATA_DIR.mkdir(exist_ok=True)
    RESULTS_DIR.mkdir(exist_ok=True)

def validate_setup():
    """Validate that all necessary files exist"""
    missing = []
    for file_path in [KB_PATH, SIGNATURES_PATH, FAISS_INDEX_PATH, EVALUATION_SET_PATH]:
        if not file_path.exists():
            missing.append(str(file_path))
    
    if missing:
        print(f"❌ Missing files: {missing}")
        return False
    
    print("✅ Configuration validated")
    return True