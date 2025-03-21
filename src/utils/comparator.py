"""
Comparator Tool

Provides tools for comparing CVSS and IVSS vulnerability scoring systems.
"""

import json
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.scoring.cvss_calculator import CVSSv4Calculator
from src.scoring.ivss_extension import IVSSCalculator


class VulnerabilityComparator:
    
    def __init__(self):
        self.cvss_calculator = CVSSv4Calculator()
        self.ivss_calculator = IVSSCalculator()
        self.results = []
    
    def assess_vulnerability(self, vuln_id, description, cvss_params, ivss_params):
        """
        Assess vulnerability using both methodologies.
        
        Parameters:
        - vuln_id: ID of vulnerability (e.g., CVE number)
        - description: Description of vulnerability
        - cvss_params: Dictionary of CVSS parameters or initialized CVSSv4Calculator
        - ivss_params: Dictionary of IVSS parameters or initialized IVSSCalculator
        
        Returns:
        - Dictionary with assessment results
        """
        # Handle different types of inputs for CVSS
        if isinstance(cvss_params, CVSSv4Calculator):
            # Use the provided calculator directly
            self.cvss_calculator = cvss_params
        else:
            # Handle dictionary of parameters
            self.cvss_calculator = CVSSv4Calculator()
            if 'base_metrics' in cvss_params:
                self.cvss_calculator.set_base_metrics(**cvss_params.get('base_metrics', {}))
            if 'threat_metrics' in cvss_params:
                self.cvss_calculator.set_threat_metrics(**cvss_params.get('threat_metrics', {}))
            if 'environmental_metrics' in cvss_params:
                self.cvss_calculator.set_environmental_metrics(**cvss_params.get('environmental_metrics', {}))
            
        # Calculate CVSS score
        cvss_score = self.cvss_calculator.calculate_base_score()
        cvss_vector = self.cvss_calculator.to_vector_string()
        
        # Handle different types of inputs for IVSS
        if isinstance(ivss_params, IVSSCalculator):
            # Use the provided calculator directly
            self.ivss_calculator = ivss_params
        else:
            # Handle dictionary of parameters
            self.ivss_calculator = IVSSCalculator()
            # Option 1: Use CVSS score as base for IVSS
            if ivss_params.get('use_cvss_base', False):
                self.ivss_calculator.set_cvss_base_score(cvss_score)
            # Option 2: Calculate IVSS independently
            else:
                if 'base_metrics' in ivss_params:
                    self.ivss_calculator.set_base_metrics(**ivss_params.get('base_metrics', {}))
            
            # Set IVSS-specific parameters
            if 'local_environment' in ivss_params:
                self.ivss_calculator.set_local_environment_metrics(**ivss_params.get('local_environment', {}))
            if 'process_consequences' in ivss_params:
                self.ivss_calculator.set_process_consequence_metrics(**ivss_params.get('process_consequences', {}))
            if 'impact_metrics' in ivss_params:
                self.ivss_calculator.set_impact_metrics(**ivss_params.get('impact_metrics', {}))
        
        # Calculate IVSS score
        ivss_score = self.ivss_calculator.calculate_final_score()
        ivss_vector = self.ivss_calculator.to_vector_string()
        
        # Create result with all calculated scores
        result = {
            'id': vuln_id,
            'description': description,
            'cvss': {
                'score': cvss_score,
                'vector': cvss_vector,
            },
            'ivss': {
                'score': ivss_score,
                'vector': ivss_vector,
                'detailed_scores': self.ivss_calculator.scores
            },
            'comparison': {
                'absolute_difference': abs(cvss_score - ivss_score),
                'percentage_difference': abs(cvss_score - ivss_score) / max(cvss_score, ivss_score) * 100 if max(cvss_score, ivss_score) > 0 else 0,
                'severity_shift': self._determine_severity_shift(cvss_score, ivss_score),
            }
        }
        
        self.results.append(result)
        return result
    
    def _determine_severity_shift(self, cvss_score, ivss_score):
        """
        Determine if severity category shifts between CVSS and IVSS scores.
        
        CVSS v4.0 severity ratings:
        - 0.0-0.1: None
        - 0.1-3.9: Low
        - 4.0-6.9: Medium
        - 7.0-8.9: High
        - 9.0-10.0: Critical
        """
        cvss_severity = self._get_severity_category(cvss_score)
        ivss_severity = self._get_severity_category(ivss_score)
        
        if cvss_severity == ivss_severity:
            return "No change"
        else:
            return f"{cvss_severity} → {ivss_severity}"
    
    def _get_severity_category(self, score):
        """Get severity category based on score."""
        if score < 0.1:
            return "None"
        elif score < 4.0:
            return "Low"
        elif score < 7.0:
            return "Medium"
        elif score < 9.0:
            return "High"
        else:
            return "Critical"
    
    def analyse_results(self):
        """
        Analyse comparison results and generate statistics.
        
        Returns:
        - Dictionary with analysis results
        """
        if not self.results:
            return {"error": "No vulnerabilities assessed yet"}
        
        # Count severity shifts
        severity_shifts = {}
        for result in self.results:
            shift = result['comparison']['severity_shift']
            severity_shifts[shift] = severity_shifts.get(shift, 0) + 1
        
        # Calculate averages
        avg_cvss = sum(r['cvss']['score'] for r in self.results) / len(self.results)
        avg_ivss = sum(r['ivss']['score'] for r in self.results) / len(self.results)
        avg_diff = sum(r['comparison']['absolute_difference'] for r in self.results) / len(self.results)
        avg_pct_diff = sum(r['comparison']['percentage_difference'] for r in self.results) / len(self.results)
        
        # Find vulnerabilities with largest differences
        sorted_by_diff = sorted(self.results, key=lambda r: r['comparison']['absolute_difference'], reverse=True)
        largest_differences = sorted_by_diff[:5] if len(sorted_by_diff) >= 5 else sorted_by_diff
        
        return {
            "total_vulnerabilities": len(self.results),
            "average_scores": {
                "cvss": avg_cvss,
                "ivss": avg_ivss,
                "difference": avg_diff,
                "percentage_difference": avg_pct_diff
            },
            "severity_shifts": severity_shifts,
            "largest_differences": [
                {
                    "id": r['id'],
                    "description": r['description'],
                    "cvss_score": r['cvss']['score'],
                    "ivss_score": r['ivss']['score'],
                    "difference": r['comparison']['absolute_difference']
                }
                for r in largest_differences
            ]
        }
    
    def export_results_to_json(self, filename):
        """
        Export comparison results to JSON file.
        
        Parameters:
        - filename: Name of JSON file to create
        """
        if not self.results:
            return False
            
        with open(filename, 'w') as jsonfile:
            json.dump(self.results, jsonfile, indent=2)
                
        return True
    
    def load_from_json(self, filename):
        """
        Load previously saved results from JSON file.
        
        Parameters:
        - filename: Name of JSON file to load
        """
        try:
            with open(filename, 'r') as jsonfile:
                self.results = json.load(jsonfile)
            return True
        except (FileNotFoundError, json.JSONDecodeError):
            return False