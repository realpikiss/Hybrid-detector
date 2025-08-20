#!/usr/bin/env python3
"""
Unified Signature Extraction Module for structuaral_vulrag

Single source of truth for extracting structural signatures from CPG files.
Used by both build-time tools and runtime retrieval.

Features extracted:
- Graph metrics: nodes, edges, density, average degree 
- Control complexity: loops, conditionals, cyclomatic complexity
- Dangerous calls by CWE category (Buffer Overflow, Use-After-Free, etc.)
- Memory operations, data flow edges
"""

import logging
from typing import Dict, List, Optional, Set, Any
import numpy as np
from pathlib import Path

#!/usr/bin/env python3
"""
Unified Signature Extraction Module for structuaral_vulrag

Single source of truth for extracting structural signatures from CPG files.
Used by both build-time tools and runtime retrieval.

Features extracted:
- Graph metrics: nodes, edges, density, average degree
- Control complexity: loops, conditionals, cyclomatic complexity
- Dangerous calls by CWE category (Buffer Overflow, Use-After-Free, etc.)
- Memory operations, data flow edges
"""

import logging
from typing import Dict, List, Optional, Set, Any
import numpy as np

try:
    from utils.graphson_converter import load_and_convert_cpg
except ImportError:
    print("Warning: Could not import load_and_convert_cpg. Using fallback.")
    def load_and_convert_cpg(path):
        return None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ===== CWE-CATEGORIZED DANGEROUS CALLS (COMPLETE VERSION) =====

BUFFER_OVERFLOW_CALLS = {
    # String manipulation dangereuse
    'strcpy', 'strncpy', 'strcat', 'strncat', 'sprintf', 'vsprintf',
    'snprintf', 'vsnprintf', 'swprintf', 'vswprintf',
    
    # Memory copy dangereuse  
    'memcpy', 'memmove', 'memset', 'wmemcpy', 'wmemmove', 'wmemset',
    'bcopy', 'bzero',
    
    # Input functions dangereuses
    'gets', 'scanf', 'sscanf', 'fscanf', 'vscanf', 'vsscanf', 'vfscanf',
    'getwd', 'realpath',
    
    # Linux Kernel spécifiques
    'copy_from_user', 'copy_to_user', '__copy_from_user', '__copy_to_user',
    'strncpy_from_user', 'strnlen_user', 'get_user', 'put_user',
    'probe_kernel_read', 'probe_kernel_write'
}

USE_AFTER_FREE_CALLS = {
    # Memory deallocation
    'free', 'kfree', 'vfree', 'kvfree', 'kzfree',
    'free_page', '__free_page', '__free_pages', 'free_pages',
    'kmem_cache_free', 'mempool_free',
    
    # Object/Resource cleanup  
    'put_device', 'kobject_put', 'kref_put', 'refcount_dec',
    'module_put', 'fput', 'dput', 'iput', 'mntput',
    
    # Network/Socket cleanup
    'sock_put', 'sk_free', 'dev_put', 'in_dev_put',
    
    # File system cleanup
    'file_free', 'path_put', 'mntput', 'dentry_free',
    
    # Synchronization cleanup
    'mutex_destroy', 'spin_lock_destroy', 'rwlock_destroy'
}

BUFFER_UNDERREAD_CALLS = {
    # Dangerous reads
    'memchr', 'strchr', 'strrchr', 'strstr', 'strpbrk',
    'strlen', 'strnlen', 'wcslen', 'wcsnlen',
    
    # Array/pointer access
    'array_index_nospec', 'get_user', '__get_user',
    'probe_kernel_read', 'copy_from_user',
    
    # Memory access
    'readb', 'readw', 'readl', 'readq',
    'ioread8', 'ioread16', 'ioread32'
}

RACE_CONDITION_CALLS = {
    # Synchronization primitives
    'mutex_lock', 'mutex_unlock', 'mutex_trylock',
    'spin_lock', 'spin_unlock', 'spin_lock_irq', 'spin_unlock_irq',
    'spin_lock_irqsave', 'spin_unlock_irqrestore',
    'raw_spin_lock', 'raw_spin_unlock',
    
    # Read-write locks
    'read_lock', 'read_unlock', 'write_lock', 'write_unlock',
    'rw_lock', 'rw_unlock',
    
    # Atomic operations
    'atomic_read', 'atomic_set', 'atomic_inc', 'atomic_dec',
    'atomic_add', 'atomic_sub', 'atomic_cmpxchg',
    'test_and_set_bit', 'test_and_clear_bit',
    
    # RCU (Read-Copy-Update)
    'rcu_read_lock', 'rcu_read_unlock', 'rcu_dereference',
    'synchronize_rcu', 'call_rcu',
    
    # Scheduling
    'schedule', 'yield', 'msleep', 'usleep_range'
}

INFO_DISCLOSURE_CALLS = {
    # Uninitialized memory
    'kmalloc', 'vmalloc', 'alloc_pages', 'get_free_page',
    'kmem_cache_alloc', 'mempool_alloc',
    
    # Copy to user space
    'copy_to_user', '__copy_to_user', 'put_user', '__put_user',
    
    # Debug/logging functions
    'printk', 'pr_debug', 'pr_info', 'dev_dbg', 'dev_info',
    'seq_printf', 'seq_write',
    
    # Kernel address exposure
    'kallsyms_lookup', 'sprint_symbol', 'print_symbol'
}

INPUT_VALIDATION_CALLS = {
    # User input processing
    'sscanf', 'scanf', 'fscanf', 'simple_strtoul', 'simple_strtol',
    'kstrtoul', 'kstrtol', 'kstrtoull', 'kstrtoll',
    
    # String conversion
    'atoi', 'atol', 'atoll', 'strtol', 'strtoul', 'strtoull',
    
    # Network input
    'recvfrom', 'recv', 'recvmsg', 'read', 'pread',
    
    # File operations
    'read', 'write', 'pread', 'pwrite', 'readv', 'writev'
}

PRIVILEGE_CALLS = {
    # Capability checks
    'capable', 'capable_wrt_inode_uidgid', 'ns_capable',
    'has_capability', 'security_capable',
    
    # User/group operations
    'setuid', 'setgid', 'seteuid', 'setegid',
    'current_uid', 'current_gid', 'current_euid', 'current_egid',
    
    # Permission checks
    'inode_permission', 'may_open', 'security_inode_permission'
}

RESOURCE_LEAK_CALLS = {
    # Memory allocation (potential leaks)
    'kmalloc', 'kzalloc', 'vmalloc', 'vzalloc', 'kcalloc',
    'kmem_cache_alloc', 'alloc_pages', 'get_free_page',
    
    # File handles
    'open', 'fopen', 'filp_open', 'dentry_open',
    
    # Network resources
    'socket', 'accept', 'connect', 'sock_create',
    
    # Timers/work queues
    'init_timer', 'add_timer', 'schedule_work', 'queue_work'
}

NULL_DEREF_CALLS = {
    # Functions that can return NULL
    'kmalloc', 'kzalloc', 'vmalloc', 'kcalloc',
    'find_get_page', 'page_address', 'kmap', 'ioremap',
    'dev_get_by_name', 'dev_get_by_index',
    'alloc_netdev', 'alloc_skb', 'dev_alloc_skb'
}

# Combined dangerous calls by CWE
DANGEROUS_CALLS_BY_CWE = {
    'CWE-119': BUFFER_OVERFLOW_CALLS,
    'CWE-787': BUFFER_OVERFLOW_CALLS,  # Same as CWE-119
    'CWE-125': BUFFER_UNDERREAD_CALLS,
    'CWE-416': USE_AFTER_FREE_CALLS,
    'CWE-362': RACE_CONDITION_CALLS,
    'CWE-200': INFO_DISCLOSURE_CALLS,
    'CWE-20': INPUT_VALIDATION_CALLS,
    'CWE-264': PRIVILEGE_CALLS,
    'CWE-401': RESOURCE_LEAK_CALLS,
    'CWE-476': NULL_DEREF_CALLS
}

ALL_DANGEROUS_CALLS = set().union(*DANGEROUS_CALLS_BY_CWE.values())

# Memory-specific call sets
ALLOC_CALLS = {'kmalloc', 'kzalloc', 'vmalloc', 'vzalloc', 'kcalloc', 'malloc', 'calloc', 'realloc'}
FREE_CALLS = {'kfree', 'vfree', 'kvfree', 'kzfree', 'free'}

# Feature columns in exact order for consistency
FEATURE_COLUMNS = [
    'num_nodes', 'num_edges', 'density', 'avg_degree',
    'cyclomatic_complexity', 'loop_count', 'conditional_count',
    'buffer_overflow_calls', 'use_after_free_calls', 'buffer_underread_calls',
    'race_condition_calls', 'info_disclosure_calls', 'input_validation_calls',
    'privilege_calls', 'resource_leak_calls', 'null_deref_calls',
    'malloc_calls', 'free_calls', 'memory_ops', 'total_dangerous_calls',
    'reaching_def_edges', 'cfg_edges', 'cdg_edges', 'ast_edges', 'is_flat_cpg'
]


class UnifiedSignatureExtractor:
    """Unified signature extractor - single source of truth"""
    
    def __init__(self):
        """Initialize unified signature extractor"""
        self.feature_columns = FEATURE_COLUMNS
        self.dangerous_calls_by_cwe = DANGEROUS_CALLS_BY_CWE
        self.all_dangerous_calls = ALL_DANGEROUS_CALLS
        self.alloc_calls = ALLOC_CALLS
        self.free_calls = FREE_CALLS
        
        logger.info(f"Initialized UnifiedSignatureExtractor with {len(FEATURE_COLUMNS)} features")
    
    def count_calls_in_set(self, cpg, call_set: Set[str]) -> int:
        """Count calls that match any function in the given set"""
        count = 0
        for _, data in cpg.nodes(data=True):
            if data.get('label') == 'CALL':
                # Handle both string and list formats for function names
                call_name = data.get('name', '')
                if isinstance(call_name, list):
                    call_name = call_name[0] if call_name else ''
                call_name = str(call_name).lower()
                
                if any(func in call_name for func in call_set):
                    count += 1
        return count
    
    def count_edge_type(self, cpg, edge_type: str) -> int:
        """Count edges of a specific type"""
        count = 0
        for _, _, data in cpg.edges(data=True):
            if data.get('label') == edge_type:
                count += 1
        return count
    
    def is_flat_cpg(self, cpg) -> bool:
        """Detect if CPG is flat (mostly UNKNOWN nodes)"""
        total_nodes = cpg.number_of_nodes()
        if total_nodes == 0:
            return True
            
        unknown_count = 0
        for _, data in cpg.nodes(data=True):
            if data.get('label') == 'UNKNOWN':
                unknown_count += 1
        
        flatness_ratio = unknown_count / total_nodes
        return flatness_ratio > 0.8  # >80% UNKNOWN nodes = flat CPG
    
    def extract_signature(self, cpg_path: str) -> Optional[Dict[str, Any]]:
        """Extract comprehensive signature from a single CPG"""
        try:
            cpg = load_and_convert_cpg(cpg_path)
            if not cpg:
                return None
            
            # Basic graph metrics
            num_nodes = cpg.number_of_nodes()
            num_edges = cpg.number_of_edges()
            
            if num_nodes == 0:
                return None
            
            # Check if CPG is flat
            is_flat = self.is_flat_cpg(cpg)
            
            # Graph density
            max_edges = num_nodes * (num_nodes - 1)
            density = num_edges / max(max_edges, 1)
            
            # Average degree (handle directed/undirected)
            avg_degree = (2.0 * num_edges) / num_nodes if num_nodes > 0 else 0
            
            # Initialize signature with zeros
            signature = {
                'instance_id': Path(cpg_path).stem,
                'num_nodes': num_nodes,
                'num_edges': num_edges,
                'density': density,
                'avg_degree': avg_degree,
                'is_flat_cpg': is_flat,
                
                # Control structure counts
                'loop_count': 0,
                'conditional_count': 0,
                'cyclomatic_complexity': 1,  # Base complexity
                
                # CWE-categorized dangerous calls
                'buffer_overflow_calls': 0,
                'use_after_free_calls': 0,
                'buffer_underread_calls': 0,
                'race_condition_calls': 0,
                'info_disclosure_calls': 0,
                'input_validation_calls': 0,
                'privilege_calls': 0,
                'resource_leak_calls': 0,
                'null_deref_calls': 0,
                
                # Memory operations
                'malloc_calls': 0,
                'free_calls': 0,
                'memory_ops': 0,
                
                # Data flow edges
                'reaching_def_edges': 0,
                'cfg_edges': 0,
                'cdg_edges': 0,
                'ast_edges': 0,
                
                # Total dangerous calls
                'total_dangerous_calls': 0
            }
            
            # Extract features from nodes
            for _, data in cpg.nodes(data=True):
                label = data.get('label', '')
                
                # Control structures
                if label == 'CONTROL_STRUCTURE':
                    control_type = data.get('CONTROL_STRUCTURE_TYPE', '')
                    if isinstance(control_type, list):
                        control_type = control_type[0] if control_type else ''
                    control_type = str(control_type).upper()
                    
                    if control_type in ['FOR', 'WHILE', 'DO']:
                        signature['loop_count'] += 1
                    elif control_type in ['IF', 'SWITCH']:
                        signature['conditional_count'] += 1
                
                # Dangerous function detection in METHOD nodes
                elif label == 'METHOD':
                    # Get function name from NAME or FULL_NAME property
                    func_name = data.get('NAME', '') or data.get('FULL_NAME', '')
                    if isinstance(func_name, list):
                        func_name = func_name[0] if func_name else ''
                    func_name = str(func_name).lower()
                    
                    # Count by CWE category
                    if any(func in func_name for func in BUFFER_OVERFLOW_CALLS):
                        signature['buffer_overflow_calls'] += 1
                    if any(func in func_name for func in USE_AFTER_FREE_CALLS):
                        signature['use_after_free_calls'] += 1
                    if any(func in func_name for func in BUFFER_UNDERREAD_CALLS):
                        signature['buffer_underread_calls'] += 1
                    if any(func in func_name for func in RACE_CONDITION_CALLS):
                        signature['race_condition_calls'] += 1
                    if any(func in func_name for func in INFO_DISCLOSURE_CALLS):
                        signature['info_disclosure_calls'] += 1
                    if any(func in func_name for func in INPUT_VALIDATION_CALLS):
                        signature['input_validation_calls'] += 1
                    if any(func in func_name for func in PRIVILEGE_CALLS):
                        signature['privilege_calls'] += 1
                    if any(func in func_name for func in RESOURCE_LEAK_CALLS):
                        signature['resource_leak_calls'] += 1
                    if any(func in func_name for func in NULL_DEREF_CALLS):
                        signature['null_deref_calls'] += 1
                    
                    # Memory operations
                    if any(func in func_name for func in ALLOC_CALLS):
                        signature['malloc_calls'] += 1
                        signature['memory_ops'] += 1
                    if any(func in func_name for func in FREE_CALLS):
                        signature['free_calls'] += 1
                        signature['memory_ops'] += 1
                    
                    # Total dangerous calls
                    if any(func in func_name for func in ALL_DANGEROUS_CALLS):
                        signature['total_dangerous_calls'] += 1
            
            # Extract edge features
            signature['reaching_def_edges'] = self.count_edge_type(cpg, 'REACHING_DEF')
            signature['cfg_edges'] = self.count_edge_type(cpg, 'CFG')
            signature['cdg_edges'] = self.count_edge_type(cpg, 'CDG')
            signature['ast_edges'] = self.count_edge_type(cpg, 'AST')
            
            # Calculate cyclomatic complexity
            signature['cyclomatic_complexity'] = (
                signature['loop_count'] + signature['conditional_count'] + 1
            )
            
            return signature
            
        except Exception as e:
            logger.warning(f"Failed to extract signature from {cpg_path}: {e}")
            return None
    
    def get_empty_signature(self) -> Dict[str, Any]:
        """Return empty signature with all zeros"""
        signature = {col: 0 for col in self.feature_columns}
        signature['is_flat_cpg'] = True  # Empty CPG is considered flat
        return signature


# Convenience functions for backward compatibility
def extract_signature(cpg_path: str) -> Optional[Dict[str, Any]]:
    """Convenience function for single signature extraction"""
    extractor = UnifiedSignatureExtractor()
    return extractor.extract_signature(cpg_path)


def get_feature_columns() -> List[str]:
    """Get the standard feature column order"""
    return FEATURE_COLUMNS.copy()


def get_dangerous_calls_by_cwe() -> Dict[str, Set[str]]:
    """Get the complete dangerous calls mapping"""
    return DANGEROUS_CALLS_BY_CWE.copy()


# ===== Structural hotspots extraction (compact signal for prompts/BM25) =====
def _safe_lower(v: Any) -> str:
    try:
        s = v[0] if isinstance(v, list) and v else v
        return str(s).lower()
    except Exception:
        return ""


def extract_hotspots(cpg_path: str) -> Dict[str, Any]:
    """Extract compact structural hotspots from a CPG JSON.
    Returns a dict with:
      - risky_apis: {name -> count}
      - categories: {cwe_code -> count}
      - mem: {alloc: n, free: n}
      - ops: {danger_total: n}
    """
    try:
        cpg = load_and_convert_cpg(cpg_path)
        if not cpg:
            return {}

        risky_apis: Dict[str, int] = {}
        categories: Dict[str, int] = {k: 0 for k in DANGEROUS_CALLS_BY_CWE.keys()}
        alloc_n = 0
        free_n = 0
        danger_total = 0

        for _, data in cpg.nodes(data=True):
            # Many Joern exports encode API names on METHOD nodes; keep CALL too
            if data.get('label') not in ('CALL', 'METHOD'):
                continue
            # Joern/GraphSON commonly uses UPPERCASE keys; ensure we check them first
            candidates = [
                data.get('NAME'),
                data.get('FULL_NAME'),
                data.get('METHOD_FULL_NAME'),
                data.get('METHOD_NAME'),
                data.get('SIGNATURE'),
                data.get('CODE'),
                # fallbacks (some converters might lowercase)
                data.get('name'),
                data.get('full_name'),
                data.get('code'),
            ]
            name = ""
            for cand in candidates:
                name = _safe_lower(cand)
                if name:
                    break
            if not name:
                continue

            # Count risky APIs
            for func in ALL_DANGEROUS_CALLS:
                if func in name:
                    risky_apis[func] = risky_apis.get(func, 0) + 1
                    danger_total += 1

            # Tally by CWE category
            for cwe, callset in DANGEROUS_CALLS_BY_CWE.items():
                if any(func in name for func in callset):
                    categories[cwe] += 1

            # Memory ops
            if any(func in name for func in ALLOC_CALLS):
                alloc_n += 1
            if any(func in name for func in FREE_CALLS):
                free_n += 1

        return {
            'risky_apis': dict(sorted(risky_apis.items(), key=lambda x: (-x[1], x[0]))),
            'categories': categories,
            'mem': {'alloc': alloc_n, 'free': free_n},
            'ops': {'danger_total': danger_total},
        }
    except Exception as e:
        logger.warning(f"Failed to extract hotspots from {cpg_path}: {e}")
        return {}


def build_hotspot_tokens(hotspots: Dict[str, Any], max_items: int = 8) -> str:
    """Build a short token string for BM25 biasing from hotspots."""
    if not hotspots:
        return ""
    apis = list(hotspots.get('risky_apis', {}).items())[:max_items]
    cat = hotspots.get('categories', {})
    mem = hotspots.get('mem', {})
    tokens = []
    if apis:
        tokens.append("apis:" + " ".join(f"{k}:{v}" for k, v in apis))
    if cat:
        # keep only non-zero categories
        nz = [k for k, v in cat.items() if v]
        if nz:
            tokens.append("cwe:" + " ".join(nz[:6]))
    if mem:
        tokens.append(f"mem:alloc:{mem.get('alloc',0)} free:{mem.get('free',0)}")
    return "; ".join(tokens)


def build_structural_summary(hotspots: Dict[str, Any], max_items: int = 8) -> str:
    """Build a compact, human-readable structural summary for prompts."""
    if not hotspots:
        return "[Structural Summary]\nNo structural hotspots extracted from CPG."
    apis = list(hotspots.get('risky_apis', {}).items())[:max_items]
    cat = hotspots.get('categories', {})
    mem = hotspots.get('mem', {})
    lines = ["[Structural Summary]"]
    if apis:
        lines.append("- Risky APIs (top): " + ", ".join(f"{k}×{v}" for k, v in apis))
    nz_cwe = [k for k, v in (cat or {}).items() if v]
    if nz_cwe:
        lines.append("- CWE signals: " + ", ".join(nz_cwe[:8]))
    lines.append(f"- Memory ops: alloc={mem.get('alloc',0)}, free={mem.get('free',0)}")
    lines.append(f"- Total dangerous ops: {hotspots.get('ops',{}).get('danger_total',0)}")
    return "\n".join(lines)