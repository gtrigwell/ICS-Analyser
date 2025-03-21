"""
Comparison Script

Script for comparing CVSS and IVSS vulnerability scoring systems.
"""

import sys
import os
import matplotlib.pyplot as plt
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.scoring.cvss_calculator import CVSSv4Calculator
from src.scoring.ivss_extension import IVSSCalculator
from src.utils.comparator import VulnerabilityComparator
from src.utils.visualiser import VulnerabilityVisualisation


def main():
    """Run comparison of CVSS and IVSS on sample vulnerabilities."""
    print("Running Vulnerability Scoring System Comparison...")
    
    # Create comparator
    comparator = VulnerabilityComparator()
    
    # Load sample vulnerabilities and assess
    for vuln in get_sample_vulnerabilities():
        result = comparator.assess_vulnerability(
            vuln['id'], 
            vuln['description'], 
            vuln['cvss_params'], 
            vuln['ivss_params']
        )
        print(f"Assessed: {vuln['id']} - CVSS: {result['cvss']['score']:.1f}, IVSS: {result['ivss']['score']:.1f}")
    
    # Analyse results
    analysis = comparator.analyse_results()
    print("\nAnalysis:")
    print(f"Total vulnerabilities: {analysis['total_vulnerabilities']}")
    print(f"Average CVSS score: {analysis['average_scores']['cvss']:.2f}")
    print(f"Average IVSS score: {analysis['average_scores']['ivss']:.2f}")
    print(f"Average difference: {analysis['average_scores']['difference']:.2f}")
    print(f"Severity shifts: {analysis['severity_shifts']}")
    
    # Export results
    comparator.export_results_to_json("vulnerability_comparison_results.json")
    print("\nResults exported to JSON file.")
    
    # Create visualisations
    print("\nCreating visualisations...")
    visualiser = VulnerabilityVisualisation(comparator)
    fig1, ax1 = visualiser.plot_score_comparison("score_comparison.png")
    fig2, ax2 = visualiser.plot_score_distribution("score_distribution.png")
    fig3, ax3 = visualiser.plot_severity_shifts("severity_shifts.png")
    fig4, ax4 = visualiser.plot_scatter_correlation("score_correlation.png")
    fig5 = visualiser.create_dashboard("dashboard.png")
    print("Visualisation images saved.")
    
    # Show dashboard (optional commenting)
    plt.figure(fig5.number)
    plt.show()
    
    print("\nAll tasks completed successfully.")

def get_sample_vulnerabilities():
    """
    Get list of sample vulnerabilities for testing comparison framework.
    These examples represent realistic industrial control system vulnerabilities.
    """
    return [
        # 1. PLC Firmware Buffer Overflow
        {
            'id': 'ICS-001',
            'description': 'Buffer overflow vulnerability in PLC firmware allowing remote code execution',
            'cvss_params': CVSSv4Calculator.from_vector_string(
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            ),
            'ivss_params': IVSSCalculator.from_vector_string(
                "IVSS:1.0/RC:C/BC:C/RL:W/EC:L/EX:F/AU:N/UI:N/AV:AR/LA:LN/CP:P/VI:P/MI:P/CI:P/PI:H/RI:H/SI:H/CD:H"
            )
        },
        
        # 2. HMI Authentication Bypass
        {
            'id': 'ICS-002',
            'description': 'Authentication bypass vulnerability in HMI software allowing unauthorised access',
            'cvss_params': CVSSv4Calculator.from_vector_string(
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N"
            ),
            'ivss_params': IVSSCalculator.from_vector_string(
                "IVSS:1.0/RC:C/BC:C/RL:OF/EC:L/EX:POC/AU:N/UI:N/AV:LN/LA:LN/CP:D/VI:C/MI:P/CI:P/PI:M/RI:M/SI:L/CD:MH"
            )
        },
        
        # 3. Historian Database Information Disclosure
        {
            'id': 'ICS-003',
            'description': 'Information disclosure vulnerability in historian database exposing sensitive process data',
            'cvss_params': CVSSv4Calculator.from_vector_string(
                "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
            ),
            'ivss_params': IVSSCalculator.from_vector_string(
                "IVSS:1.0/RC:C/BC:DM/RL:OF/EC:H/EX:POC/AU:U/UI:N/AV:LN/LA:LN/CP:C/VI:P/MI:P/CI:N/PI:L/RI:L/SI:N/CD:LM"
            )
        },
        
        # 4. RTU Denial of Service
        {
            'id': 'ICS-004',
            'description': 'Denial of service vulnerability in RTU communication module causing major system unavailability',
            'cvss_params': CVSSv4Calculator.from_vector_string(
                "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L"
            ),
            'ivss_params': IVSSCalculator.from_vector_string(
                "IVSS:1.0/RC:C/BC:SD/RL:TF/EC:L/EX:F/AU:N/UI:N/AV:LN/LA:AR/CP:P/VI:P/MI:P/CI:P/PI:H/RI:H/SI:H/CD:H"
            )
        },
        
        # 5. SCADA Protocol Man in the Middle
        {
            'id': 'ICS-005',
            'description': 'Man in the middle vulnerability over SCADA protocol allowing command injection',
            'cvss_params': CVSSv4Calculator.from_vector_string(
                "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:H/VA:L/SC:N/SI:L/SA:N"
            ),
            'ivss_params': IVSSCalculator.from_vector_string(
                "IVSS:1.0/RC:C/BC:DM/RL:U/EC:H/EX:POC/AU:N/UI:N/AV:AR/LA:AR/CP:C/VI:P/MI:P/CI:P/PI:H/RI:H/SI:H/CD:H"
            )
        },
        
        # 6. Safety Instrumented System Firmware Vulnerability
        {
            'id': 'ICS-006',
            'description': 'Critical vulnerability in safety instrumented system firmware affecting safety functions',
            'cvss_params': CVSSv4Calculator.from_vector_string(
                "CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N"
            ),
            'ivss_params': IVSSCalculator.from_vector_string(
                "IVSS:1.0/RC:C/BC:C/RL:W/EC:H/EX:POC/AU:AR/UI:N/AV:LH/LA:LH/CP:C/VI:P/MI:P/CI:P/PI:H/RI:H/SI:H/CD:H"
            )
        },
        
        # 7. Engineering Workstation Credential Theft
        {
            'id': 'ICS-007',
            'description': 'Credentials theft vulnerability in engineering workstation software',
            'cvss_params': CVSSv4Calculator.from_vector_string(
                "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N"
            ),
            'ivss_params': IVSSCalculator.from_vector_string(
                "IVSS:1.0/RC:C/BC:DM/RL:OF/EC:L/EX:F/AU:U/UI:Y/AV:LH/LA:LH/CP:P/VI:P/MI:P/CI:P/PI:M/RI:M/SI:L/CD:H"
            )
        },
         # 8. Max Severity Test
        {
            'id': 'MAX-TEST',
            'description': 'Test cases to evaluate maximum possible scores',
            'cvss_params': CVSSv4Calculator.from_vector_string(
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:S/SA:S/E:A/CR:H/IR:H/AR:H"
            ),
            'ivss_params': IVSSCalculator.from_vector_string(
                "IVSS:1.0/RC:C/BC:C/RL:U/EC:L/EX:F/AU:N/UI:N/AV:AR/LA:AR/CP:N/VI:C/MI:C/CI:C/PI:H/RI:H/SI:H/CD:H"
            )
        }
    ]

if __name__ == "__main__":
    main()