# Hybrid Vulnerability Detection System for C/C++ Code

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![Research](https://img.shields.io/badge/status-research-orange.svg)]()

A comprehensive evaluation framework for hybrid vulnerability detection methods that combines structural analysis via Code Property Graphs (CPGs) with semantic analysis using Large Language Models (LLMs) and retrieval-augmented generation (RAG).

## Table of Contents

- [Abstract](#abstract)
- [System Architecture](#system-architecture)
- [Detection Methods](#detection-methods)
- [Feature Extraction](#feature-extraction)
- [Installation &amp; Setup](#installation--setup)
- [Usage](#usage)
- [Evaluation Framework](#evaluation-framework)
- [Results &amp; Analysis](#results--analysis)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [Citation](#citation)

## Abstract

This repository implements and evaluates four distinct vulnerability detection approaches for C/C++ code, with a primary focus on Linux kernel functions. The system integrates:

- **Structural pre-filtering** using FAISS-indexed CPG signatures
- **Semantic re-ranking** via multi-field BM25 with Reciprocal Rank Fusion (RRF)
- **Iterative LLM-based contextual analysis** with weighted vote aggregation

The evaluation framework supports comparative analysis across methods ranging from pure structural approaches to hybrid systems that leverage both graph-based features and semantic understanding.

> **⚠️ Note**: The evaluation datasets (`evaluation_set.csv` and related files) are created in the companion repository [RagKb_internship](https://github.com/realpikiss/RagKb_internship), which contains the pipeline for building the hybrid knowledge base from VulRAG.

## System Architecture

### Core Components

#### 1. Iterative Detector (`core/detector.py`)

The detection engine implements a three-tier analysis pipeline:

- **Level 1**: Direct LLM analysis (baseline)
- **Level 2**: Contextual analysis with retrieved candidates
- **Level 3**: Weighted vote aggregation

**Key Features:**

- Robust parsing with fallback mechanisms
- Configurable aggregation using weighted voting (threshold: 0.55)
- Rich vulnerability context construction including CWE/CVE information

#### 2. Unified Retrievers (`core/retrievers.py`)

**Structural Retriever:**

- FAISS-based similarity search over 25-dimensional CPG signatures
- Efficient nearest neighbor retrieval for structural patterns

**BM25 Retriever:**

- Multi-field semantic retrieval with RRF fusion across:
  - `code`: Raw vulnerable code snippets
  - `purpose`: LLM-generated functional summaries
  - `behavior`: Step-by-step operational descriptions

**Hybrid Integration:**

- Candidate filtering for structural pre-filtering workflows
- Seamless integration between structural and semantic approaches

#### 3. LLM Client (`core/llm_client.py`)

**Features:**

- Ollama integration for both local and cloud-based endpoints
- Persistent disk-based response caching for reproducibility
- Robust error handling with configurable retry mechanisms
- Default model: `gpt-oss:120b` via Ollama cloud API

## Detection Methods

### 1. Structural VulRAG (Hybrid Method)

**Pipeline:** Structural Pre-filtering → BM25 Re-ranking → Iterative Detection

```
1. Extract 25-D CPG signature
2. Retrieve top-10 structural candidates via FAISS
3. Generate semantic descriptions (purpose/behavior)
4. Re-rank using multi-field BM25+RRF (select top-3)
5. Iterative LLM analysis with structural context injection
```

**Fallback:** Direct LLM analysis with structural hotspots when no candidates found.

### 2. VulRAG (BM25-Only Baseline)

**Pipeline:** BM25 Retrieval → Iterative Detection

- Direct BM25 search over entire knowledge base (top-3)
- Semantic description generation for query enhancement
- No structural pre-filtering or context biasing
- Mimics the VulRAG approach of Du et al. (2024)

### 3. Structural Only

**Pipeline:** Structural Retrieval → Iterative Detection

- FAISS-based retrieval using only CPG signatures (top-3)
- Structural hotspot context injection
- No semantic re-ranking

### 4. Raw LLM

**Pipeline:** Direct LLM Analysis

- Zero-shot vulnerability detection
- JSON-structured response parsing
- Confidence scoring with fallback mechanisms

## Feature Extraction

### CPG Signature (25 Features)

The system extracts comprehensive structural signatures from Code Property Graphs:

#### Graph Metrics (4 features)

- `num_nodes`, `num_edges`, `density`, `avg_degree`

#### Control Complexity (3 features)

- `cyclomatic_complexity`, `loop_count`, `conditional_count`

#### CWE-Categorized Dangerous Calls (9 features)

| Category             | CWE         | Examples                           |
| -------------------- | ----------- | ---------------------------------- |
| Buffer Overflow      | CWE-119/787 | strcpy, gets, sprintf              |
| Use After Free       | CWE-416     | free, kfree, put_device            |
| Buffer Underread     | CWE-125     | memchr, strlen, array access       |
| Race Conditions      | CWE-362     | mutex ops, atomic ops, RCU         |
| Info Disclosure      | CWE-200     | kmalloc, copy_to_user, printk      |
| Input Validation     | CWE-20      | scanf, kstrtoul, recv              |
| Privilege Escalation | CWE-264     | capable, setuid, permission checks |
| Resource Leaks       | CWE-401     | allocation without cleanup         |
| Null Dereference     | CWE-476     | functions returning NULL pointers  |

#### Additional Features (6 features)

- **Memory Operations (3):** `malloc_calls`, `free_calls`, `memory_ops`
- **Data Flow Edges (4):** `reaching_def_edges`, `cfg_edges`, `cdg_edges`, `ast_edges`
- **Meta Features (2):** `total_dangerous_calls`, `is_flat_cpg`

### Structural Hotspots

Compact vulnerability signals for prompt injection and BM25 biasing:

- **Risky APIs:** Function call frequencies with counts
- **CWE Categories:** Active vulnerability categories
- **Memory Operations:** Allocation/deallocation balance
- **Danger Metrics:** Total dangerous operation counts

## Installation & Setup

### Prerequisites

```bash
# Python 3.8+ required
pip install -r requirements.txt
```

**Required packages:**

- `ollama` (LLM client)
- `numpy`, `pandas` (data processing)
- `faiss-cpu` (structural retrieval)
- `rank-bm25` (semantic retrieval)
- `networkx` (graph processing)
- `tqdm` (progress tracking)
- `matplotlib` (visualization)

### Environment Setup

```bash
# Set Ollama API key for cloud access
export OLLAMA_API="your_api_key_here"

# Verify data files exist
python -c "import config; config.validate_setup()"
```

### Data Requirements

The system expects the following data files in `data/`:

```
data/
├── kb.json              # Knowledge base with vulnerability patterns
├── signatures.csv       # Pre-computed CPG signatures
├── faiss.index         # FAISS index for structural retrieval
└── evaluation_set.csv  # Evaluation dataset (from RagKb_internship repo)
```

## Usage

### Quick Start

```python
from methods import StructuralVulRAGMethod

# Initialize method
method = StructuralVulRAGMethod()

# Analyze code
result = method.analyze(
    code='your_c_code_here', 
    cpg_json_path='path_to_cpg.json'
)

print(f"Vulnerable: {result['is_vulnerable']}")
print(f"Confidence: {result['confidence']}")
```

### Running Evaluation

```bash
# Quick evaluation (5 samples)
python evaluation.py

# Full dataset evaluation
python evaluation.py --max-samples=None

# Specific method testing
python evaluation.py --method=structural_vulrag
```

### Configuration Parameters

#### Retrieval Configuration

```python
STRUCTURAL_TOP_N = 10      # Structural candidates
BM25_TOP_K = 3             # Semantic re-ranking
MAX_ITERATIONS = 8         # Detection iterations
```

#### Vote Aggregation

```python
AGG_VOTE_THRESHOLD = 0.55        # Vulnerability threshold
VOTE_WEIGHT_VULN = 0.75          # Vulnerable vote weight
VOTE_WEIGHT_SAFE_SOLUTION = 0.65 # Safe with solution weight
VOTE_WEIGHT_SAFE_DEFAULT = 0.5   # Default safe weight
```

#### LLM Configuration

```python
OLLAMA_HOST = "https://ollama.com"
OLLAMA_MODEL = "gpt-oss:120b"
LLM_TEMPERATURE = 0.1
CONTEXT_MAX_CODE_CHARS = None  # No truncation for large context models
```

## Evaluation Framework

### Dataset Structure

The evaluation dataset (`data/evaluation_set.csv`) contains:

- **Instance Metadata:** `pair_id`, `instance_id`, `label` (0=safe, 1=vulnerable)
- **Code Content:** `func` (C/C++ function source)
- **Vulnerability Context:** `cve_id`, `cwe`, `cve_description`
- **File Paths:** `c_file_path`, `cpg_json_path`

### Metrics and Analysis

- **Binary Classification:** Accuracy, Precision, Recall, F1-Score
- **Confusion Matrices:** True/False Positives/Negatives analysis
- **Timing Analysis:** Component-wise performance profiling
- **Error Tracking:** Method-specific failure analysis

### Output Analysis

Results are saved to `results/evaluation_results_<timestamp>.csv` with:

- Per-sample verdicts and confidence scores
- Method-specific timing breakdowns
- Error tracking and debugging information
- Aggregated metrics and confusion matrices

## Results & Analysis

### Key Implementation Details

#### Robust LLM Response Parsing

- **Strict Parsing:** Exact keyword matching (`CAUSE_DETECTED`, `SOLUTION_PRESENT`)
- **Pattern-Based Fallback:** Configurable pattern matching for response variations
- **Confidence Extraction:** Regex-based confidence score extraction with validation

#### Semantic Caching Strategy

- **Persistent Cache:** Disk-based caching using SHA1 hashes of code snippets
- **Cache Keys:** Include model name and method for cache isolation
- **Heuristic Fallbacks:** Automatic fallback to rule-based descriptions when LLM fails

#### BM25 Multi-Field Fusion

- **Field Weights:** Code (0.15), Purpose (0.35), Behavior (0.5)
- **RRF Parameters:** Reciprocal Rank Fusion with k=60
- **Tokenization:** Custom tokenizer handling code identifiers and camelCase splitting

#### Structural Context Integration

- **Hotspot Injection:** Structural signals injected into LLM prompts
- **BM25 Biasing:** Structural tokens appended to semantic queries
- **Fallback Mechanisms:** Graceful degradation when structural data unavailable

## Limitations

### Current Limitations

1. **Dataset Scope:** Primarily Linux kernel functions; generalization needs validation
2. **Binary Classification:** No severity scoring or vulnerability type classification
3. **Static Analysis:** No dynamic analysis or runtime behavior consideration
4. **Context Window:** Limited by LLM context length for very large functions

### Future Directions

- **Multi-Project Evaluation:** Expand to diverse C/C++ codebases
- **Learned Aggregation:** Replace rule-based voting with learned meta-classifiers
- **Active Learning:** Incorporate human feedback for continuous improvement
- **Real-Time Integration:** CI/CD pipeline integration for continuous security assessment

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
git clone https://github.com/realpikiss/Hybrid-detector.git
cd Hybrid-detector
pip install -e .
pre-commit install
```

## Citation

If you use this framework in your research, please cite:

```bibtex
@misc{hybrid_vuldet_2025,
  title={Hybrid Vulnerability Detection System for C/C++ Code},
  author={Vernet Emmanuel Adjobi},
  year={2025},
  url={https://github.com/realpikiss/Hybrid-detector},
  note={Research implementation combining structural and semantic analysis}
}
```

## License

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.

---

**Acknowledgments:** This work builds upon the VulRAG methodology and extends it with hybrid structural-semantic analysis approaches.
