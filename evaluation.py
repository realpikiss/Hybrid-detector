#!/usr/bin/env python3
"""
Évaluation complète des méthodes structuaral_vulrag avec CPG JSON paths
"""

import time
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Any
from tqdm import tqdm

import config
from methods import structuaral_vulragMethod, RawLLMMethod, vulragMethod, StructuralOnlyMethod

class structuaral_vulragEvaluator:
    """Evaluator for all methods with CPG JSON paths"""
    
    def __init__(self):
        self.methods = {
            'structuaral_vulrag': structuaral_vulragMethod(),
            'vulrag': vulragMethod(),
            'Raw_LLM': RawLLMMethod(),
            'Structural_Only': StructuralOnlyMethod()
        }
        self.results = []
    
    def evaluate_dataset(self, dataset_path: str, max_samples: int = None) -> pd.DataFrame:
        """
        Evaluate all methods on the dataset
        
        Args:
            dataset_path: Path to the evaluation CSV
            max_samples: Limit samples (for quick tests)
        """
        # Charger dataset
        df = pd.read_csv(dataset_path)
        
        if max_samples:
            df = df.head(max_samples)
        
        print(f"📊 Evaluating {len(df)} samples...")
        
        # Evaluate each sample
        for idx, row in tqdm(df.iterrows(), total=len(df), desc="Evaluating"):
            sample_results = self._evaluate_sample(row)
            self.results.extend(sample_results)
        
        # Convert to DataFrame
        results_df = pd.DataFrame(self.results)
        
        # Save results
        timestamp = int(time.time())
        output_path = config.RESULTS_DIR / f"evaluation_results_{timestamp}.csv"
        results_df.to_csv(output_path, index=False)
        
        print(f"✅ Results saved to: {output_path}")
        return results_df
    
    def _evaluate_sample(self, row: pd.Series) -> List[Dict[str, Any]]:
        """Evaluate a sample with all methods"""
        instance_id = row['instance_id']
        code = row['func']  # Dataset uses 'func' column
        cpg_json_path = row.get('cpg_json_path')
        true_label = row['label']
        
        sample_results = []
        
        for method_name, method in self.methods.items():
            try:
                # Analyze based on method type
                if method_name in ['structuaral_vulrag', 'Structural_Only']:
                    # Verify that the CPG path exists
                    if not cpg_json_path or not Path(cpg_json_path).exists():
                        # Simulate with a default CPG path for testing
                        result = {
                            'verdict': 'ERROR',
                            'confidence': 'LOW',
                            'confidence_score': 0.0,
                            'reason': f'CPG file not found: {cpg_json_path}',
                            'method': method_name,
                            'instance_id': instance_id
                        }
                    else:
                        result = method.analyze(
                            code=code,
                            cpg_json_path=cpg_json_path,
                            instance_id=instance_id
                        )
                else:
                    # vulrag et Raw LLM
                    result = method.analyze(
                        code=code,
                        instance_id=instance_id
                    )
                
                # Add evaluation metadata
                result.update({
                    'true_label': true_label,
                    'predicted_label': 1 if result.get('verdict') == 'VULNERABLE' else 0,
                    'correct': (result.get('verdict') == 'VULNERABLE') == bool(true_label)
                })
                
                sample_results.append(result)
                
            except Exception as e:
                # Error result
                error_result = {
                    'verdict': 'ERROR',
                    'confidence': 'LOW',
                    'confidence_score': 0.0,
                    'reason': str(e),
                    'method': method_name,
                    'instance_id': instance_id,
                    'true_label': true_label,
                    'predicted_label': 0,
                    'correct': False
                }
                sample_results.append(error_result)
        
        return sample_results
    
    def calculate_metrics(self, results_df: pd.DataFrame) -> Dict[str, Dict[str, float]]:
        """Calculate evaluation metrics per method"""
        metrics = {}
        
        for method in results_df['method'].unique():
            method_results = results_df[results_df['method'] == method]
            
            # Exclude errors for metric calculation
            valid_results = method_results[method_results['verdict'] != 'ERROR']
            
            if len(valid_results) == 0:
                metrics[method] = {
                    'accuracy': 0.0,
                    'precision': 0.0,
                    'recall': 0.0,
                    'f1': 0.0,
                    'samples': 0,
                    'errors': len(method_results)
                }
                continue
            
            # Binary metrics
            tp = len(valid_results[(valid_results['true_label'] == 1) & (valid_results['predicted_label'] == 1)])
            fp = len(valid_results[(valid_results['true_label'] == 0) & (valid_results['predicted_label'] == 1)])
            tn = len(valid_results[(valid_results['true_label'] == 0) & (valid_results['predicted_label'] == 0)])
            fn = len(valid_results[(valid_results['true_label'] == 1) & (valid_results['predicted_label'] == 0)])
            
            accuracy = (tp + tn) / len(valid_results) if len(valid_results) > 0 else 0
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            
            metrics[method] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'samples': len(valid_results),
                'errors': len(method_results) - len(valid_results)
            }
        
        return metrics
    
    def print_summary(self, metrics: Dict[str, Dict[str, float]]):
        """Print evaluation summary"""
        print("\n" + "="*60)
        print("📊 EVALUATION SUMMARY")
        print("="*60)
        
        for method, scores in metrics.items():
            print(f"\n{method}:")
            print(f"  Accuracy:  {scores['accuracy']:.3f}")
            print(f"  Precision: {scores['precision']:.3f}")
            print(f"  Recall:    {scores['recall']:.3f}")
            print(f"  F1-Score:  {scores['f1']:.3f}")
            print(f"  Samples:   {scores['samples']}")
            if scores['errors'] > 0:
                print(f"  Errors:    {scores['errors']}")

def main():
    """Main evaluation function"""
    
    # Validate setup
    if not config.validate_setup():
        print("❌ Setup validation failed")
        return
    
    # Create evaluator
    evaluator = structuaral_vulragEvaluator()
    
    # Evaluate on dataset
    try:
        results_df = evaluator.evaluate_dataset(
            str(config.EVALUATION_SET_PATH),
            max_samples=5  # Limit to 5 samples for quick audit
        )
        
        # Calculate metrics
        metrics = evaluator.calculate_metrics(results_df)
        
        # Print summary
        evaluator.print_summary(metrics)
        
        # Method statistics
        print("\n" + "="*60)
        print("📈 METHOD STATISTICS")
        print("="*60)
        
        for method_name, method in evaluator.methods.items():
            if hasattr(method, 'get_stats'):
                stats = method.get_stats()
                print(f"\n{method_name}:")
                for key, value in stats.items():
                    if isinstance(value, dict):
                        print(f"  {key}:")
                        for k, v in value.items():
                            print(f"    {k}: {v}")
                    else:
                        print(f"  {key}: {value}")
        
    except Exception as e:
        print(f"❌ Evaluation failed: {e}")

if __name__ == "__main__":
    main()
