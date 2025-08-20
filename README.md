Vulnerability Scoring System Comparison - Initial Prototype (Full implementation pending publication clearance)

* This tool compares the Common Vulnerability Scoring System (CVSS) v4.0 with the Industrial Vulnerability Scoring System (IVSS) using a set of sample industrial control system vulnerabilities.

#######################################################################################
Usage

Navigate to the test directory:
* cd ivss-assessment
* cd tests

Run the comparison script:
* python comparison_script.py

This will:

* Load the sample vulnerabilities from the script
* Calculate both CVSS and IVSS scores
* Generate comparison analysis
* Create visualisation charts
* Display the results dashboard

#######################################################################################
Sample Vulnerabilities

The script includes these representative industrial control system scenarios:

* ICS-001: PLC Firmware Buffer Overflow
* ICS-002: HMI Authentication Bypass
* ICS-003: Historian Database Information Disclosure
* ICS-004: RTU Denial of Service
* ICS-005: SCADA Protocol Man in the Middle
* ICS-006: Safety Instrumented System Firmware Vulnerability
* ICS-007: Engineering Workstation Credential Theft
* MAX-TEST: Maximum severity test case

#######################################################################################
Output

The script generates several visualisation files:

* score_comparison.png - Bar chart comparing CVSS vs IVSS scores
* score_distribution.png - Histogram showing score distribution
* severity_shifts.png - Pie chart of severity category shifts
* score_correlation.png - Scatter plot showing correlation between scores
* dashboard.png - Comprehensive dashboard with all visualisations

It also exports complete results to vulnerability_comparison_results.json.

#######################################################################################
Requirements

The tool requires Python 3.10.11 with the following packages:

* numpy
* matplotlib
