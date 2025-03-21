"""
Industrial Vulnerability Scoring System

This module implements the IVSS calculation system based on the specification
provided by the ThreatGEN study. IVSS extends traditional vulnerability scoring
with metrics specific to industrial control systems (ICS) environments.
"""

class IVSSCalculator:

    # Base metrics
    REPORT_CONFIDENCE_UNCONFIRMED = 0.25
    REPORT_CONFIDENCE_UNCORROBORATED = 0.5
    REPORT_CONFIDENCE_CONFIRMED = 1.0
    REPORT_CONFIDENCE_NOT_DEFINED = 1.0
    
    CONSEQUENCE_TEMPORARY_DENIAL = 0.25
    CONSEQUENCE_DATA_MODIFICATION = 0.5
    CONSEQUENCE_SUSTAINED_DENIAL = 0.75
    CONSEQUENCE_CONTROL = 1.0
    
    REMEDIATION_LEVEL_OFFICIAL_FIX = 0.0
    REMEDIATION_LEVEL_WORKAROUND = 0.75
    REMEDIATION_LEVEL_TEMPORARY_FIX = 0.9
    REMEDIATION_LEVEL_UNAVAILABLE = 1.0
    REMEDIATION_LEVEL_NOT_DEFINED = 1.0
    
    EXPLOIT_DIFFICULTY_HIGH = 0.2
    EXPLOIT_DIFFICULTY_MODERATE = 0.5
    EXPLOIT_DIFFICULTY_LOW = 1.0
    
    EXPLOIT_MATURITY_UNPROVEN = 0.5
    EXPLOIT_MATURITY_POC = 0.75
    EXPLOIT_MATURITY_FUNCTIONAL = 1.0
    EXPLOIT_MATURITY_NOT_DEFINED = 1.0
    
    PRIVILEGE_LEVEL_ADMIN_ROOT = 0.2
    PRIVILEGE_LEVEL_USER = 0.56
    PRIVILEGE_LEVEL_NONE = 1.0
    
    USER_INTERACTION_YES = 0.3
    USER_INTERACTION_NO = 1.0
    
    THREAT_VECTOR_LOCAL_HOST = 0.1
    THREAT_VECTOR_LOCAL_NETWORK = 0.5
    THREAT_VECTOR_ADJACENT_REMOTE = 1.0
    THREAT_VECTOR_UNDEFINED = 1.0
    
    ASSET_ACCESS_LOCAL_HOST = 0.25
    ASSET_ACCESS_LOCAL_NETWORK = 0.5
    ASSET_ACCESS_ADJACENT_REMOTE = 1.0
    
    NETWORK_SEGMENTATION_COMPLIANT = 0.2
    NETWORK_SEGMENTATION_PARTIAL = 0.75
    NETWORK_SEGMENTATION_DMZ_ONLY = 0.85
    NETWORK_SEGMENTATION_NONE = 1.0
    
    # Local ICS Environment metrics
    PROCESS_VISIBILITY_NONE = 0.0
    PROCESS_VISIBILITY_PARTIAL = 0.5
    PROCESS_VISIBILITY_COMPLETE = 1.0
    
    PROCESS_MONITORING_NONE = 0.0
    PROCESS_MONITORING_PARTIAL = 0.5
    PROCESS_MONITORING_COMPLETE = 1.0
    
    PROCESS_CONTROL_NONE = 0.0
    PROCESS_CONTROL_PARTIAL = 0.5 
    PROCESS_CONTROL_COMPLETE = 1.0
    
    # Impact metrics 
    SYSTEM_PRODUCTION_IMPACT_NONE = 0.0
    SYSTEM_PRODUCTION_IMPACT_LOW = 0.4
    SYSTEM_PRODUCTION_IMPACT_MEDIUM = 0.7
    SYSTEM_PRODUCTION_IMPACT_HIGH = 1.0
    SYSTEM_PRODUCTION_IMPACT_NOT_DEFINED = 1.0
    
    SYSTEM_RELIABILITY_IMPACT_NONE = 0.0
    SYSTEM_RELIABILITY_IMPACT_LOW = 0.33
    SYSTEM_RELIABILITY_IMPACT_MEDIUM = 0.66
    SYSTEM_RELIABILITY_IMPACT_HIGH = 1.0
    SYSTEM_RELIABILITY_IMPACT_NOT_DEFINED = 1.0
    
    SYSTEM_SAFETY_IMPACT_NONE = 0.0
    SYSTEM_SAFETY_IMPACT_LOW = 0.5
    SYSTEM_SAFETY_IMPACT_MEDIUM = 0.8
    SYSTEM_SAFETY_IMPACT_HIGH = 1.0
    SYSTEM_SAFETY_IMPACT_NOT_DEFINED = 1.0
    
    FINANCIAL_LOSS_IMPACT_NONE = 0.0 
    FINANCIAL_LOSS_IMPACT_LOW = 0.5 
    FINANCIAL_LOSS_IMPACT_LOW_MEDIUM = 0.75
    FINANCIAL_LOSS_IMPACT_MEDIUM_HIGH = 0.9
    FINANCIAL_LOSS_IMPACT_HIGH = 1.0
    FINANCIAL_LOSS_IMPACT_NOT_DEFINED = 1.0
    
    def __init__(self):
        """Initialise IVSS calculator with empty metrics."""
        self.metrics = {
            # Base severity & exploitability
            'RC': None,  # Report Confidence
            'BC': None,  # Consequence
            'RL': None,  # Remediation Level
            
            'EC': None,  # Exploit Difficulty/Incident Complexity
            'EX': None,  # Exploit Maturity
            'AU': None,  # Privilege Level Required
            'UI': None,  # User Interaction Required
            
            'AV': None,  # Threat Vector Required
            
            # Local ICS environment
            'LA': None,  # Asset Access
            'CP': None,  # Network Segmentation Level
            
            'VI': None,  # Process Visibility Consequence
            'MI': None,  # Process Monitoring Consequence
            'CI': None,  # Process Control Consequences
            
            'PI': None,  # System Production Impact
            'RI': None,  # System Reliability Impact
            'SI': None,  # System Safety Impact
            'CD': None,  # Financial Loss Impact
        }
        
        # Scores
        self.scores = {
            'BS': None,   # Base Severity
            'BEX': None,  # Base Exploitability
            'ACC': None,  # Local Accessibility
            'CON': None,  # Consequences
            'IMP': None,  # Impact
            'ADJACC': None,  # Adjusted Accessibility
            'ADJIMP': None,  # Adjusted Criticality
            'FINAL': None,  # Final Score
        }
        
        self.use_external_cvss = False
        self.external_cvss_score = None

    def set_base_metrics(self, rc, bc, rl, ec, ex, au, ui, av):
        """Set all base metrics at once."""
        self.metrics['RC'] = rc
        self.metrics['BC'] = bc
        self.metrics['RL'] = rl
        self.metrics['EC'] = ec
        self.metrics['EX'] = ex
        self.metrics['AU'] = au
        self.metrics['UI'] = ui
        self.metrics['AV'] = av
        return self

    def set_local_environment_metrics(self, la, cp):
        """Set local environment metrics."""
        self.metrics['LA'] = la
        self.metrics['CP'] = cp
        return self

    def set_process_consequence_metrics(self, vi, mi, ci):
        """Set process consequence metrics."""
        self.metrics['VI'] = vi
        self.metrics['MI'] = mi
        self.metrics['CI'] = ci
        return self

    def set_impact_metrics(self, pi, ri, si, cd):
        """Set impact metrics."""
        self.metrics['PI'] = pi
        self.metrics['RI'] = ri
        self.metrics['SI'] = si
        self.metrics['CD'] = cd
        return self
        
    def set_cvss_base_score(self, cvss_score):
        """
        Set base score from external CVSS score.
        Allows using existing CVSS scores with IVSS environmental modifiers.
        """
        self.use_external_cvss = True
        self.external_cvss_score = cvss_score
        return self

    def calculate_base_severity_score(self):
        """Calculate Base Severity (BS) score."""
        # If using external CVSS score, return it
        if self.use_external_cvss:
            self.scores['BS'] = self.external_cvss_score
            return self.external_cvss_score
            
        rc = self.metrics['RC']
        bc = self.metrics['BC']
        rl = self.metrics['RL']
        
        if any(m is None for m in [rc, bc, rl]):
            raise ValueError("All base severity metrics must be set")
        
        # Formula: ((RC+BC*3+RL)/4)*10
        score = ((rc + bc * 3 + rl) / 4) * 10
        self.scores['BS'] = score
        return score

    def calculate_base_exploitability_score(self):
        """Calculate Base Exploitability (BEX) score."""
        ec = self.metrics['EC']
        ex = self.metrics['EX']
        au = self.metrics['AU']
        ui = self.metrics['UI']
        
        if any(m is None for m in [ec, ex, au, ui]):
            raise ValueError("All exploitability metrics must be set")
        
        # Formula: ((EC+EX+AU+UI)/4)*10
        score = ((ec + ex + au + ui) / 4) * 10
        self.scores['BEX'] = score
        return score
        
    def calculate_base_accessibility_score(self):
        """Calculate Base Accessibility Score based on Threat Vector Required."""
        av = self.metrics['AV']
        
        if av is None:
            raise ValueError("Threat Vector Required metric must be set")
            
        # Formula: AV*10
        score = av * 10
        return score
        
    def calculate_total_base_score(self):
        """Calculate Total Base Score."""
        # If using external CVSS score, return it
        if self.use_external_cvss:
            return self.external_cvss_score
            
        bs = self.calculate_base_severity_score()
        bex = self.calculate_base_exploitability_score()
        av = self.metrics['AV']
        
        if av is None:
            raise ValueError("Threat Vector Required metric must be set")
            
        # Formula: ((BS+BEX+(AV*2))/4)
        score = (bs + bex + (av * 10 * 2)) / 4
        return score

    def calculate_local_accessibility(self):
        """Calculate Local Accessibility (ACC) score."""
        la = self.metrics['LA']
        cp = self.metrics['CP']
        
        if any(m is None for m in [la, cp]):
            raise ValueError("All local accessibility metrics must be set")
        
        # Formula: (LA*CP)*10
        score = (la * cp) * 10
        self.scores['ACC'] = score
        return score

    def calculate_consequences(self):
        """Calculate Consequences (CON) score."""
        vi = self.metrics['VI']
        mi = self.metrics['MI']
        ci = self.metrics['CI']
        
        if any(m is None for m in [vi, mi, ci]):
            raise ValueError("All process consequence metrics must be set")
        
        # Formula: ((VI+MI+CI*3)/5)*10
        score = ((vi + mi + ci * 3) / 5) * 10
        self.scores['CON'] = score
        return score

    def calculate_impact(self):
        """Calculate Impact (IMP) score."""
        pi = self.metrics['PI']
        ri = self.metrics['RI']
        si = self.metrics['SI']
        cd = self.metrics['CD']
        
        if any(m is None for m in [pi, ri, si, cd]):
            raise ValueError("All impact metrics must be set")
        
        # Formula: (CD*5*PI*2+RI+SI*6)/14*10
        score = (cd * 5 * pi * 2 + ri + si * 6) / 14 * 10
        self.scores['IMP'] = score
        return score

    def calculate_adjusted_accessibility(self):
        """Calculate Adjusted Accessibility (ADJACC) score."""
        la = self.metrics['LA']
        
        if la is None:
            raise ValueError("Asset Access metric must be set")
        
        # Formula: LA
        self.scores['ADJACC'] = la
        return la

    def calculate_adjusted_criticality(self):
        """Calculate Adjusted Criticality (ADJIMP) score."""
        con = self.calculate_consequences()
        imp = self.calculate_impact()
        
        # Formula: (CON+(IMP*2))/3
        score = (con + (imp * 2)) / 3
        self.scores['ADJIMP'] = score
        return score

    def calculate_final_score(self):
        """Calculate final IVSS score based on all metrics."""
        if self.use_external_cvss:
            bs = self.external_cvss_score
        else:
            bs = self.calculate_base_severity_score()
            
        adj_imp = self.calculate_adjusted_criticality()
        adj_acc = self.calculate_adjusted_accessibility()
        
        # Debug intermediate values
        print(f"\n---- IVSS Score Calculation Breakdown ----")
        print(f"Base Severity (BS): {bs:.2f}")
        
        # Calculate Base Exploitability for debugging
        bex = self.calculate_base_exploitability_score()
        print(f"Base Exploitability (BEX): {bex:.2f}")
        
        # Calculate Base Accessibility for debugging
        av = self.metrics['AV']
        base_acc = av * 10 if av is not None else 0
        print(f"Base Accessibility (AV*10): {base_acc:.2f}")
        
        # Calculate Total Base Score for debugging
        total_base = (bs + bex + (base_acc * 2)) / 4 if av is not None else 0
        print(f"Total Base Score: {total_base:.2f}")
        
        # Local environment parameters
        la = self.metrics['LA']
        cp = self.metrics['CP']
        print(f"Asset Access (LA): {la:.2f}")
        print(f"Network Segmentation (CP): {cp:.2f}")
        
        # Local Accessibility
        local_acc = self.calculate_local_accessibility()
        print(f"Local Accessibility (ACC = LA*CP*10): {local_acc:.2f}")
        
        # Process consequences
        vi = self.metrics['VI']
        mi = self.metrics['MI']
        ci = self.metrics['CI']
        print(f"Process Visibility (VI): {vi:.2f}")
        print(f"Process Monitoring (MI): {mi:.2f}")
        print(f"Process Control (CI): {ci:.2f}")
        
        # Consequences calculation
        con = self.calculate_consequences()
        print(f"Consequences (CON = (VI+MI+CI*3)/5*10): {con:.2f}")
        
        # Impact parameters
        pi = self.metrics['PI']
        ri = self.metrics['RI']
        si = self.metrics['SI']
        cd = self.metrics['CD']
        print(f"Production Impact (PI): {pi:.2f}")
        print(f"Reliability Impact (RI): {ri:.2f}")
        print(f"Safety Impact (SI): {si:.2f}")
        print(f"Financial Loss Impact (CD): {cd:.2f}")
        
        # Impact calculation
        imp = self.calculate_impact()
        print(f"Impact (IMP = (CD*5*PI*2+RI+SI*6)/14*10): {imp:.2f}")
        
        # Adjusted values
        print(f"Adjusted Accessibility (ADJACC = LA): {adj_acc:.2f}")
        print(f"Adjusted Criticality (ADJIMP = (CON+(IMP*2))/3): {adj_imp:.2f}")
        
        # Final score calculation
        formula_components = f"({bs:.2f} + {adj_imp:.2f}*5 + {adj_acc:.2f}*10) / 16"
        numerator = bs + adj_imp * 5 + adj_acc * 10
        print(f"Final Score Formula: {formula_components}")
        print(f"Numerator: {numerator:.2f}")
        print(f"Final Score: {numerator:.2f} / 16 = {numerator/16:.2f}")
        
        # Original formula
        score = (bs + adj_imp * 5 + adj_acc * 10) / 16
        self.scores['FINAL'] = score
        return score
        
    def to_vector_string(self):
        """Convert current metrics to IVSS vector string."""
        parts = ["IVSS:1.0"]
        
        # Add base metrics
        for metric in ['RC', 'BC', 'RL', 'EC', 'EX', 'AU', 'UI', 'AV']:
            if self.metrics[metric] is not None:
                parts.append(f"{metric}:{self._get_metric_key(metric)}")
        
        # Add environmental metrics
        for metric in ['LA', 'CP', 'VI', 'MI', 'CI', 'PI', 'RI', 'SI', 'CD']:
            if self.metrics[metric] is not None:
                parts.append(f"{metric}:{self._get_metric_key(metric)}")
        
        return "/".join(parts)
        
    def _get_metric_key(self, metric):
        """Get key representation of a metric value."""
        value = self.metrics[metric]
        
        # Comprehensive mappings from numerical values to key representations
        mappings = {
            # Report Confidence
            'RC': {
                self.REPORT_CONFIDENCE_UNCONFIRMED: 'U',
                self.REPORT_CONFIDENCE_UNCORROBORATED: 'UC', 
                self.REPORT_CONFIDENCE_CONFIRMED: 'C',
                self.REPORT_CONFIDENCE_NOT_DEFINED: 'ND'
            },
            
            # Consequence
            'BC': {
                self.CONSEQUENCE_TEMPORARY_DENIAL: 'TD',
                self.CONSEQUENCE_DATA_MODIFICATION: 'DM',
                self.CONSEQUENCE_SUSTAINED_DENIAL: 'SD',
                self.CONSEQUENCE_CONTROL: 'C'
            },
            
            # Remediation Level
            'RL': {
                self.REMEDIATION_LEVEL_OFFICIAL_FIX: 'OF',
                self.REMEDIATION_LEVEL_WORKAROUND: 'W',
                self.REMEDIATION_LEVEL_TEMPORARY_FIX: 'TF',
                self.REMEDIATION_LEVEL_UNAVAILABLE: 'U',
                self.REMEDIATION_LEVEL_NOT_DEFINED: 'ND'
            },
            
            # Exploit Difficulty
            'EC': {
                self.EXPLOIT_DIFFICULTY_HIGH: 'H',
                self.EXPLOIT_DIFFICULTY_MODERATE: 'M',
                self.EXPLOIT_DIFFICULTY_LOW: 'L'
            },
            
            # Exploit Maturity
            'EX': {
                self.EXPLOIT_MATURITY_UNPROVEN: 'U',
                self.EXPLOIT_MATURITY_POC: 'POC',
                self.EXPLOIT_MATURITY_FUNCTIONAL: 'F',
                self.EXPLOIT_MATURITY_NOT_DEFINED: 'ND'
            },
            
            # Privilege Level
            'AU': {
                self.PRIVILEGE_LEVEL_ADMIN_ROOT: 'AR',
                self.PRIVILEGE_LEVEL_USER: 'U',
                self.PRIVILEGE_LEVEL_NONE: 'N'
            },
            
            # User Interaction
            'UI': {
                self.USER_INTERACTION_YES: 'Y',
                self.USER_INTERACTION_NO: 'N'
            },
            
            # Threat Vector
            'AV': {
                self.THREAT_VECTOR_LOCAL_HOST: 'LH',
                self.THREAT_VECTOR_LOCAL_NETWORK: 'LN',
                self.THREAT_VECTOR_ADJACENT_REMOTE: 'AR',
                self.THREAT_VECTOR_UNDEFINED: 'U'
            },
            
            # Asset Access
            'LA': {
                self.ASSET_ACCESS_LOCAL_HOST: 'LH',
                self.ASSET_ACCESS_LOCAL_NETWORK: 'LN',
                self.ASSET_ACCESS_ADJACENT_REMOTE: 'AR'
            },
            
            # Network Segmentation
            'CP': {
                self.NETWORK_SEGMENTATION_COMPLIANT: 'C',
                self.NETWORK_SEGMENTATION_PARTIAL: 'P',
                self.NETWORK_SEGMENTATION_DMZ_ONLY: 'D',
                self.NETWORK_SEGMENTATION_NONE: 'N'
            },
            
            # Process Visibility
            'VI': {
                self.PROCESS_VISIBILITY_NONE: 'N',
                self.PROCESS_VISIBILITY_PARTIAL: 'P',
                self.PROCESS_VISIBILITY_COMPLETE: 'C'
            },
            
            # Process Monitoring
            'MI': {
                self.PROCESS_MONITORING_NONE: 'N',
                self.PROCESS_MONITORING_PARTIAL: 'P',
                self.PROCESS_MONITORING_COMPLETE: 'C'
            },
            
            # Process Control
            'CI': {
                self.PROCESS_CONTROL_NONE: 'N',
                self.PROCESS_CONTROL_PARTIAL: 'P',
                self.PROCESS_CONTROL_COMPLETE: 'C'
            },
            
            # System Production Impact
            'PI': {
                self.SYSTEM_PRODUCTION_IMPACT_NONE: 'N',
                self.SYSTEM_PRODUCTION_IMPACT_LOW: 'L',
                self.SYSTEM_PRODUCTION_IMPACT_MEDIUM: 'M',
                self.SYSTEM_PRODUCTION_IMPACT_HIGH: 'H',
                self.SYSTEM_PRODUCTION_IMPACT_NOT_DEFINED: 'ND'
            },
            
            # System Reliability Impact
            'RI': {
                self.SYSTEM_RELIABILITY_IMPACT_NONE: 'N',
                self.SYSTEM_RELIABILITY_IMPACT_LOW: 'L',
                self.SYSTEM_RELIABILITY_IMPACT_MEDIUM: 'M',
                self.SYSTEM_RELIABILITY_IMPACT_HIGH: 'H',
                self.SYSTEM_RELIABILITY_IMPACT_NOT_DEFINED: 'ND'
            },
            
            # System Safety Impact
            'SI': {
                self.SYSTEM_SAFETY_IMPACT_NONE: 'N',
                self.SYSTEM_SAFETY_IMPACT_LOW: 'L',
                self.SYSTEM_SAFETY_IMPACT_MEDIUM: 'M',
                self.SYSTEM_SAFETY_IMPACT_HIGH: 'H',
                self.SYSTEM_SAFETY_IMPACT_NOT_DEFINED: 'ND'
            },
            
            # Financial Loss Impact
            'CD': {
                self.FINANCIAL_LOSS_IMPACT_NONE: 'N',
                self.FINANCIAL_LOSS_IMPACT_LOW: 'L',
                self.FINANCIAL_LOSS_IMPACT_LOW_MEDIUM: 'LM',
                self.FINANCIAL_LOSS_IMPACT_MEDIUM_HIGH: 'MH',
                self.FINANCIAL_LOSS_IMPACT_HIGH: 'H',
                self.FINANCIAL_LOSS_IMPACT_NOT_DEFINED: 'ND'
            }
        }
        
        # Check if metric has mapping and value exists
        if metric in mappings and value in mappings[metric]:
            return mappings[metric][value]
        
        # Return value as string if no specific mapping found
        return str(value)
        
    @classmethod
    def from_vector_string(cls, vector_string):
        """
        Create IVSS calculator from vector string.
        
        Vector string format: IVSS:1.0/METRIC1:VALUE1/METRIC2:VALUE2/...
        
        Supported metrics:
        Base Metrics: RC, BC, RL, EC, EX, AU, UI, AV
        Local Environment: LA, CP
        Process Consequences: VI, MI, CI
        Impact Metrics: PI, RI, SI, CD
        """
        calculator = cls()
        
        # Split vector string into components
        try:
            # Validate initial format
            if not vector_string.startswith('IVSS:1.0/'):
                raise ValueError("Invalid vector string format")
            
            # Remove 'IVSS:1.0/' prefix and split into metric components
            components = vector_string.replace('IVSS:1.0/', '').split('/')
            
            # Create comprehensive reverse mapping dictionaries
            reverse_mappings = {
                # Base metrics
                'RC': {
                    'U': cls.REPORT_CONFIDENCE_UNCONFIRMED,
                    'UC': cls.REPORT_CONFIDENCE_UNCORROBORATED,
                    'C': cls.REPORT_CONFIDENCE_CONFIRMED,
                    'ND': cls.REPORT_CONFIDENCE_NOT_DEFINED
                },
                'BC': {
                    'TD': cls.CONSEQUENCE_TEMPORARY_DENIAL,
                    'DM': cls.CONSEQUENCE_DATA_MODIFICATION,
                    'SD': cls.CONSEQUENCE_SUSTAINED_DENIAL,
                    'C': cls.CONSEQUENCE_CONTROL
                },
                'RL': {
                    'OF': cls.REMEDIATION_LEVEL_OFFICIAL_FIX,
                    'W': cls.REMEDIATION_LEVEL_WORKAROUND,
                    'TF': cls.REMEDIATION_LEVEL_TEMPORARY_FIX,
                    'U': cls.REMEDIATION_LEVEL_UNAVAILABLE,
                    'ND': cls.REMEDIATION_LEVEL_NOT_DEFINED
                },
                'EC': {
                    'H': cls.EXPLOIT_DIFFICULTY_HIGH,
                    'M': cls.EXPLOIT_DIFFICULTY_MODERATE,
                    'L': cls.EXPLOIT_DIFFICULTY_LOW
                },
                'EX': {
                    'U': cls.EXPLOIT_MATURITY_UNPROVEN,
                    'POC': cls.EXPLOIT_MATURITY_POC,
                    'F': cls.EXPLOIT_MATURITY_FUNCTIONAL,
                    'ND': cls.EXPLOIT_MATURITY_NOT_DEFINED
                },
                'AU': {
                    'AR': cls.PRIVILEGE_LEVEL_ADMIN_ROOT,
                    'U': cls.PRIVILEGE_LEVEL_USER,
                    'N': cls.PRIVILEGE_LEVEL_NONE
                },
                'UI': {
                    'Y': cls.USER_INTERACTION_YES,
                    'N': cls.USER_INTERACTION_NO
                },
                'AV': {
                    'LH': cls.THREAT_VECTOR_LOCAL_HOST,
                    'LN': cls.THREAT_VECTOR_LOCAL_NETWORK,
                    'AR': cls.THREAT_VECTOR_ADJACENT_REMOTE,
                    'U': cls.THREAT_VECTOR_UNDEFINED
                },
                
                # Local environment metrics
                'LA': {
                    'LH': cls.ASSET_ACCESS_LOCAL_HOST,
                    'LN': cls.ASSET_ACCESS_LOCAL_NETWORK,
                    'AR': cls.ASSET_ACCESS_ADJACENT_REMOTE
                },
                'CP': {
                    'C': cls.NETWORK_SEGMENTATION_COMPLIANT,
                    'P': cls.NETWORK_SEGMENTATION_PARTIAL,
                    'D': cls.NETWORK_SEGMENTATION_DMZ_ONLY,
                    'N': cls.NETWORK_SEGMENTATION_NONE
                },
                
                # Process consequence metrics
                'VI': {
                    'N': cls.PROCESS_VISIBILITY_NONE,
                    'P': cls.PROCESS_VISIBILITY_PARTIAL,
                    'C': cls.PROCESS_VISIBILITY_COMPLETE
                },
                'MI': {
                    'N': cls.PROCESS_MONITORING_NONE,
                    'P': cls.PROCESS_MONITORING_PARTIAL,
                    'C': cls.PROCESS_MONITORING_COMPLETE
                },
                'CI': {
                    'N': cls.PROCESS_CONTROL_NONE,
                    'P': cls.PROCESS_CONTROL_PARTIAL,
                    'C': cls.PROCESS_CONTROL_COMPLETE
                },
                
                # Impact metrics
                'PI': {
                    'N': cls.SYSTEM_PRODUCTION_IMPACT_NONE,
                    'L': cls.SYSTEM_PRODUCTION_IMPACT_LOW,
                    'M': cls.SYSTEM_PRODUCTION_IMPACT_MEDIUM,
                    'H': cls.SYSTEM_PRODUCTION_IMPACT_HIGH,
                    'ND': cls.SYSTEM_PRODUCTION_IMPACT_NOT_DEFINED
                },
                'RI': {
                    'N': cls.SYSTEM_RELIABILITY_IMPACT_NONE,
                    'L': cls.SYSTEM_RELIABILITY_IMPACT_LOW,
                    'M': cls.SYSTEM_RELIABILITY_IMPACT_MEDIUM,
                    'H': cls.SYSTEM_RELIABILITY_IMPACT_HIGH,
                    'ND': cls.SYSTEM_RELIABILITY_IMPACT_NOT_DEFINED
                },
                'SI': {
                    'N': cls.SYSTEM_SAFETY_IMPACT_NONE,
                    'L': cls.SYSTEM_SAFETY_IMPACT_LOW,
                    'M': cls.SYSTEM_SAFETY_IMPACT_MEDIUM,
                    'H': cls.SYSTEM_SAFETY_IMPACT_HIGH,
                    'ND': cls.SYSTEM_SAFETY_IMPACT_NOT_DEFINED
                },
                'CD': {
                    'N': cls.FINANCIAL_LOSS_IMPACT_NONE,
                    'L': cls.FINANCIAL_LOSS_IMPACT_LOW,
                    'LM': cls.FINANCIAL_LOSS_IMPACT_LOW_MEDIUM,
                    'MH': cls.FINANCIAL_LOSS_IMPACT_MEDIUM_HIGH,
                    'H': cls.FINANCIAL_LOSS_IMPACT_HIGH,
                    'ND': cls.FINANCIAL_LOSS_IMPACT_NOT_DEFINED
                }
            }
            
            # Parse metrics
            metrics = {}
            
            # Parse each component
            for component in components:
                metric, value = component.split(':')
                
                # Check if metric exists in mappings
                if metric in reverse_mappings:
                    # Check if value exists in mapping for this metric
                    if value in reverse_mappings[metric]:
                        metrics[metric] = reverse_mappings[metric][value]
                    else:
                        raise ValueError(f"Invalid value {value} for metric {metric}")
                else:
                    raise ValueError(f"Unknown metric {metric}")
            
            # Set metrics
            # Base metrics
            calculator.set_base_metrics(
                rc=metrics.get('RC', cls.REPORT_CONFIDENCE_NOT_DEFINED),
                bc=metrics.get('BC', cls.CONSEQUENCE_CONTROL),
                rl=metrics.get('RL', cls.REMEDIATION_LEVEL_NOT_DEFINED),
                ec=metrics.get('EC', cls.EXPLOIT_DIFFICULTY_LOW),
                ex=metrics.get('EX', cls.EXPLOIT_MATURITY_NOT_DEFINED),
                au=metrics.get('AU', cls.PRIVILEGE_LEVEL_NONE),
                ui=metrics.get('UI', cls.USER_INTERACTION_NO),
                av=metrics.get('AV', cls.THREAT_VECTOR_UNDEFINED)
            )
            
            # Local environment metrics
            calculator.set_local_environment_metrics(
                la=metrics.get('LA', cls.ASSET_ACCESS_LOCAL_NETWORK),
                cp=metrics.get('CP', cls.NETWORK_SEGMENTATION_NONE)
            )
            
            # Process consequences
            calculator.set_process_consequence_metrics(
                vi=metrics.get('VI', cls.PROCESS_VISIBILITY_NONE),
                mi=metrics.get('MI', cls.PROCESS_MONITORING_NONE),
                ci=metrics.get('CI', cls.PROCESS_CONTROL_NONE)
            )
            
            # Impact metrics
            calculator.set_impact_metrics(
                pi=metrics.get('PI', cls.SYSTEM_PRODUCTION_IMPACT_NOT_DEFINED),
                ri=metrics.get('RI', cls.SYSTEM_RELIABILITY_IMPACT_NOT_DEFINED),
                si=metrics.get('SI', cls.SYSTEM_SAFETY_IMPACT_NOT_DEFINED),
                cd=metrics.get('CD', cls.FINANCIAL_LOSS_IMPACT_NOT_DEFINED)
            )
            
            return calculator
        
        except Exception as e:
            raise ValueError(f"Error parsing vector string: {e}")

    def calculate_all_scores(self):
        """Calculate all scores and return as dictionary."""
        try:
            print("\n==== CALCULATING ALL IVSS SCORES ====")
            
            bs = self.calculate_base_severity_score()
            print(f"Base Severity Score: {bs:.2f}")
            
            bex = self.calculate_base_exploitability_score()
            print(f"Base Exploitability Score: {bex:.2f}")
            
            total_base = self.calculate_total_base_score()
            print(f"Total Base Score: {total_base:.2f}")
            
            acc = self.calculate_local_accessibility()
            print(f"Local Accessibility Score: {acc:.2f}")
            
            con = self.calculate_consequences()
            print(f"Consequences Score: {con:.2f}")
            
            imp = self.calculate_impact()
            print(f"Impact Score: {imp:.2f}")
            
            adj_acc = self.calculate_adjusted_accessibility()
            print(f"Adjusted Accessibility: {adj_acc:.2f}")
            
            adj_imp = self.calculate_adjusted_criticality()
            print(f"Adjusted Criticality: {adj_imp:.2f}")
            
            final = self.calculate_final_score()
            print(f"Final IVSS Score: {final:.2f}")
            print("==== END CALCULATION ====\n")
            
            return {
                'base_severity': bs,
                'base_exploitability': bex,
                'total_base': total_base,
                'local_accessibility': acc,
                'consequences': con,
                'impact': imp,
                'adjusted_accessibility': adj_acc,
                'adjusted_criticality': adj_imp,
                'final_score': final
            }
        except ValueError as e:
            print(f"Error calculating scores: {e}")
            return {'error': str(e)}