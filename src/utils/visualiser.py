"""
Visualisation Tool

Provides data visualisation for comparing CVSS and IVSS scoring results,
including comparative charts, distribution analysis, and interactive dashboards.
"""

import matplotlib.pyplot as plt
import numpy as np
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.utils.comparator import VulnerabilityComparator

class VulnerabilityVisualisation:
    def __init__(self, comparator=None):
        self.comparator = comparator or VulnerabilityComparator()
        
        self.colours = {
            'cvss': '#1A5F7A',      
            'ivss': '#A12D5F',      
            'diff': '#2E8B57',      
            'background': '#F4F6F7', 
            'text': '#2C3E50'       
        }
        
        plt.style.use('seaborn-v0_8-whitegrid')
        self._set_custom_style()
    
    def _set_custom_style(self):
        plt.rcParams['figure.figsize'] = (14, 10)
        plt.rcParams['font.family'] = 'Arial'
        plt.rcParams['font.size'] = 10
        plt.rcParams['axes.labelsize'] = 12
        plt.rcParams['axes.titlesize'] = 14
        plt.rcParams['axes.labelcolor'] = self.colours['text']
        plt.rcParams['xtick.labelsize'] = 10
        plt.rcParams['ytick.labelsize'] = 10
        plt.rcParams['legend.fontsize'] = 10
        plt.rcParams['figure.titlesize'] = 16
        plt.rcParams['figure.facecolor'] = self.colours['background']
        plt.rcParams['axes.facecolor'] = 'white'
    
    def plot_score_comparison(self, save_path=None):
        if not self.comparator.results:
            print("No results available for visualisation")
            return
        
        vulnerability_ids = [r['id'] for r in self.comparator.results]
        cvss_scores = [r['cvss']['score'] for r in self.comparator.results]
        ivss_scores = [r['ivss']['score'] for r in self.comparator.results]
        
        fig, ax = plt.subplots(figsize=(14, 8))
        bar_width = 0.35
        x = np.arange(len(vulnerability_ids))
        
        ax.bar(x - bar_width/2, cvss_scores, bar_width, label='CVSS', color=self.colours['cvss'], alpha=0.8)
        ax.bar(x + bar_width/2, ivss_scores, bar_width, label='IVSS', color=self.colours['ivss'], alpha=0.8)
        
        ax.set_xlabel('Vulnerability ID', fontweight='bold')
        ax.set_ylabel('Score', fontweight='bold')
        ax.set_title('CVSS vs IVSS Score Comparison', fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(vulnerability_ids, rotation=45, ha='right')
        ax.legend()
        
        ax.axhline(y=9.0, linestyle='--', color='gray', alpha=0.5, label='Critical')
        ax.axhline(y=7.0, linestyle='--', color='gray', alpha=0.5, label='High')
        ax.axhline(y=4.0, linestyle='--', color='gray', alpha=0.5, label='Medium')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            
        return fig, ax
    
    def plot_score_distribution(self, save_path=None):
        if not self.comparator.results:
            print("No results available for visualisation")
            return
        
        cvss_scores = [r['cvss']['score'] for r in self.comparator.results]
        ivss_scores = [r['ivss']['score'] for r in self.comparator.results]
        ivss_scores = [min(s, 10.0) for s in ivss_scores]
        
        fig, ax = plt.subplots(figsize=(12, 8))
        
        bins = np.linspace(0, 10, 11)
        ax.hist(cvss_scores, bins=bins, alpha=0.5, label='CVSS', color=self.colours['cvss'])
        ax.hist(ivss_scores, bins=bins, alpha=0.5, label='IVSS', color=self.colours['ivss'])
        
        ax.axvline(x=9.0, linestyle='--', color='gray', alpha=0.7)
        ax.axvline(x=7.0, linestyle='--', color='gray', alpha=0.7)
        ax.axvline(x=4.0, linestyle='--', color='gray', alpha=0.7)
        
        ax.set_xlabel('Score', fontweight='bold')
        ax.set_ylabel('Frequency', fontweight='bold')
        ax.set_title('Distribution of Scores', fontweight='bold')
        ax.legend()
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            
        return fig, ax
    
    def plot_severity_shifts(self, save_path=None):
        if not self.comparator.results:
            print("No results available for visualisation")
            return
        
        # Get severity shifts
        analysis = self.comparator.analyse_results()
        shifts = analysis['severity_shifts']
        
        # Set up figure
        fig, ax = plt.subplots(figsize=(10, 6))
        
        # Plot
        if len(shifts) > 1:
            # Use pie chart
            labels = list(shifts.keys())
            sizes = list(shifts.values())
            
            # Create colourmap
            colours = plt.cm.Paired(np.linspace(0, 1, len(labels)))
            
            wedges, texts, autotexts = ax.pie(
                sizes, 
                labels=labels, 
                autopct='%1.1f%%',
                startangle=90,
                colors=colours,
                wedgeprops={'edgecolor': 'w', 'linewidth': 1}
            )
            
            # Equal aspect ratio for circle
            ax.axis('equal')
            
            plt.title('Severity Category Shifts between CVSS and IVSS', fontweight='bold')
            
        else:
            # Use bar chart for single category
            labels = list(shifts.keys())
            values = list(shifts.values())
            
            ax.bar(labels, values, color=self.colours['cvss'])
            ax.set_ylabel('Count')
            ax.set_title('Severity Category Shifts between CVSS and IVSS', fontweight='bold')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            
        return fig, ax
        
    def plot_scatter_correlation(self, save_path=None):
        if not self.comparator.results:
            print("No results available for visualisation")
            return
        
        cvss_scores = [r['cvss']['score'] for r in self.comparator.results]
        ivss_scores = [r['ivss']['score'] for r in self.comparator.results]
        
        fig, ax = plt.subplots(figsize=(12, 12), dpi=100)
        
        cmap = plt.cm.get_cmap('coolwarm')
        
        scatter = ax.scatter(
            cvss_scores, 
            ivss_scores, 
            c=np.abs(np.array(cvss_scores) - np.array(ivss_scores)), 
            cmap=cmap,
            s=100,
            alpha=0.7,
            edgecolors='darkgray',
            linewidths=1
        )
        
        cbar = plt.colorbar(scatter, ax=ax, shrink=0.8)
        cbar.set_label('Score Difference', fontsize=10)
        
        ax.plot([0, 11], [0, 11], color='gray', linestyle='--', alpha=0.5)
        
        ax.set_xlabel('CVSS Score', fontweight='bold')
        ax.set_ylabel('IVSS Score', fontweight='bold')
        ax.set_title('CVSS vs IVSS Score Correlation', fontweight='bold')
        
        ax.grid(True, linestyle='--', linewidth=0.5, color='lightgray')
        ax.set_aspect('equal')
        ax.set_xlim(0, 11)
        ax.set_ylim(0, 11)
        
        threshold_style = {'linestyle': '--', 'color': 'gray', 'alpha': 0.5}
        ax.axhline(y=9.0, **threshold_style)
        ax.axhline(y=7.0, **threshold_style)
        ax.axhline(y=4.0, **threshold_style)
        ax.axvline(x=9.0, **threshold_style)
        ax.axvline(x=7.0, **threshold_style)
        ax.axvline(x=4.0, **threshold_style)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            
        return fig, ax
    
    def create_dashboard(self, save_path=None):
        """
        Create comprehensive dashboard with multiple visualisations.
        
        Parameters:
        - save_path: Optional path to save figure
        """
        if not self.comparator.results:
            print("No results available for visualisation")
            return
        
        # Create figure with subplots
        fig = plt.figure(figsize=(22, 16))
        
        # Define grid for subplots
        gs = fig.add_gridspec(3, 2, 
                            hspace=0.5,
                            wspace=0.4,
                            height_ratios=[1.2, 1, 1],
                            top=0.93,
                            bottom=0.07)
        
        # Bar Chart
        ax1 = fig.add_subplot(gs[0, :])
        self._create_score_comparison_subplot(ax1)
        
        # Distribution Histogram
        ax2 = fig.add_subplot(gs[1, 0])
        self._create_score_distribution_subplot(ax2)
        
        # Severity shift Pie Chart
        ax3 = fig.add_subplot(gs[1, 1])
        self._create_severity_shifts_subplot(ax3)
        
        # Scatter graph
        ax4 = fig.add_subplot(gs[2, 0])
        self._create_scatter_correlation_subplot(ax4)
        
        # Statistics
        ax5 = fig.add_subplot(gs[2, 1])
        self._create_statistics_subplot(ax5)

        fig.suptitle('Vulnerability Scoring System Comparison Dashboard', 
                    fontsize=24, 
                    y=0.98)
        
        plt.subplots_adjust(top=0.95, bottom=0.07, hspace=0.5, wspace=0.4)
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            
        return fig

    def _create_score_comparison_subplot(self, ax):
        """Create score comparison bar chart subplot."""
        # Extract data
        vulnerability_ids = [r['id'] for r in self.comparator.results]
        cvss_scores = [r['cvss']['score'] for r in self.comparator.results]
        ivss_scores = [r['ivss']['score'] for r in self.comparator.results]

        # Plot
        bar_width = 0.35

        x = np.arange(len(vulnerability_ids))
        
        ax.bar(x - bar_width/2, cvss_scores, bar_width, label='CVSS', color=self.colours['cvss'], alpha=0.8)
        ax.bar(x + bar_width/2, ivss_scores, bar_width, label='IVSS', color=self.colours['ivss'], alpha=0.8)
        
        ax.set_xlabel('Vulnerability ID', fontweight='bold')
        ax.set_ylabel('Score', fontweight='bold')
        ax.set_title('CVSS vs IVSS Score Comparison', fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(vulnerability_ids, rotation=45, ha='right')
        ax.legend()
        
        ax.axhline(y=9.0, linestyle='--', color='gray', alpha=0.5, label='Critical')
        ax.axhline(y=7.0, linestyle='--', color='gray', alpha=0.5, label='High')
        ax.axhline(y=4.0, linestyle='--', color='gray', alpha=0.5, label='Medium')

    def _create_score_distribution_subplot(self, ax):
        """Create score distribution histogram subplot."""
        # Extract data
        cvss_scores = [r['cvss']['score'] for r in self.comparator.results]
        ivss_scores = [r['ivss']['score'] for r in self.comparator.results]
        ivss_scores = [min(s, 10.0) for s in ivss_scores]
        
        # Plot
        bins = np.linspace(0, 10, 11)  # 0-10 range with 1-point bins
        ax.hist(cvss_scores, bins=bins, alpha=0.5, label='CVSS', color=self.colours['cvss'])
        ax.hist(ivss_scores, bins=bins, alpha=0.5, label='IVSS', color=self.colours['ivss'])
        
        ax.axvline(x=9.0, linestyle='--', color='gray', alpha=0.7)
        ax.axvline(x=7.0, linestyle='--', color='gray', alpha=0.7)
        ax.axvline(x=4.0, linestyle='--', color='gray', alpha=0.7)
        
        ax.set_xlabel('Score', fontweight='bold')
        ax.set_ylabel('Frequency', fontweight='bold')
        ax.set_title('Distribution of Scores', fontweight='bold')
        ax.legend()

    def _create_severity_shifts_subplot(self, ax):
        """Create severity shifts pie chart subplot."""
        # Get severity shifts
        analysis = self.comparator.analyse_results()
        shifts = analysis['severity_shifts']
        
        # Plot
        if len(shifts) > 1:
            labels = list(shifts.keys())
            sizes = list(shifts.values())

            colours = plt.cm.Paired(np.linspace(0, 1, len(labels)))
            
            wedges, texts, autotexts = ax.pie(
                sizes, 
                labels=labels, 
                autopct='%1.1f%%',
                startangle=90,
                colors=colours,
                wedgeprops={'edgecolor': 'w', 'linewidth': 1}
            )
            
            ax.axis('equal')
        else:
            # Use bar chart for single category
            labels = list(shifts.keys())
            values = list(shifts.values())
            
            ax.bar(labels, values, color=self.colours['cvss'])
            ax.set_ylabel('Count')
        
        ax.set_title('Severity Category Shifts', fontweight='bold')

    def _create_scatter_correlation_subplot(self, ax):
        """Create scatter correlation subplot."""
        # Extract data
        cvss_scores = [r['cvss']['score'] for r in self.comparator.results]
        ivss_scores = [r['ivss']['score'] for r in self.comparator.results]
        
        # Plot
        scatter = ax.scatter(
            cvss_scores, 
            ivss_scores, 
            c=np.abs(np.array(cvss_scores) - np.array(ivss_scores)), 
            cmap='coolwarm',
            s=80,
            alpha=0.7,
            edgecolors='darkgray',
            linewidths=0.5
        )
        
        cbar = plt.colorbar(scatter, ax=ax)
        cbar.set_label('Score Difference', fontsize=10)
        
        ax.plot([0, 11], [0, 11], color='gray', linestyle='--', alpha=0.5)
        
        ax.set_xlabel('CVSS Score', fontweight='bold')
        ax.set_ylabel('IVSS Score', fontweight='bold')
        ax.set_title('CVSS vs IVSS Correlation', fontweight='bold')
        
        ax.set_aspect('equal')
        ax.set_xlim(0, 11)
        ax.set_ylim(0, 11)
        
        ax.grid(True, linestyle='--', alpha=0.6)
        ax.axhline(y=9.0, linestyle='--', color='gray', alpha=0.5)
        ax.axhline(y=7.0, linestyle='--', color='gray', alpha=0.5)
        ax.axhline(y=4.0, linestyle='--', color='gray', alpha=0.5)
        
        ax.axvline(x=9.0, linestyle='--', color='gray', alpha=0.5)
        ax.axvline(x=7.0, linestyle='--', color='gray', alpha=0.5)
        ax.axvline(x=4.0, linestyle='--', color='gray', alpha=0.5)

    def _create_statistics_subplot(self, ax):
        """Create statistics text box subplot."""
        # Get results
        analysis = self.comparator.analyse_results()
        
        # Plot
        ax.axis('off')
        
        # Construct stats text
        stats_text = (
            "ANALYSIS SUMMARY\n\n"
            f"Total Vulnerabilities: {analysis['total_vulnerabilities']}\n\n"
            "Average Scores:\n"
            f"  CVSS: {analysis['average_scores']['cvss']:.2f}\n"
            f"  IVSS: {analysis['average_scores']['ivss']:.2f}\n"
            f"  Difference: {analysis['average_scores']['difference']:.2f}\n\n"
            "Largest Difference:\n"
        )
        
        if analysis['largest_differences']:
            largest = analysis['largest_differences'][0]
            stats_text += (
                f"  {largest['id']}\n"
                f"  CVSS: {largest['cvss_score']:.1f}\n"
                f"  IVSS: {largest['ivss_score']:.1f}\n"
                f"  Diff: {largest['difference']:.1f}\n"
            )
        
        # Style properties
        props = dict(boxstyle='round', facecolor='white', alpha=0.8)
        
        # Center text vertically and horizontally
        ax.text(0.5, 0.5, stats_text, 
                transform=ax.transAxes, 
                fontsize=10,
                verticalalignment='center', 
                horizontalalignment='center', 
                bbox=props, 
                family='monospace')
        
        ax.set_title('Statistics', fontweight='bold')