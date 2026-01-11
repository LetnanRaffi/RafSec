#!/usr/bin/env python3
"""
RafSec Malware Analysis Engine - CLI Entry Point
==================================================
A comprehensive static malware analysis tool for PE files.

Author: RafSec Team
Version: 1.0.0

Usage:
    python main.py <file.exe>                 # Basic scan
    python main.py <file.exe> --full          # Full analysis with ML
    python main.py <file.exe> --json          # JSON output
    python main.py <file.exe> --train-dummy   # Train ML model with dummy data
"""

import sys
import os
import json
import argparse
from typing import Optional

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.extractor import PEExtractor
from engine.analyzer import MalwareAnalyzer, ThreatLevel
from engine.ml_model import ThreatClassifier
from utils.helpers import FileValidator, ColorPrinter


class RafSecCLI:
    """
    Command-line interface for RafSec Malware Analysis Engine.
    
    Provides:
    - Quick scan (heuristics only)
    - Full scan (heuristics + ML)
    - JSON output for automation
    - Colored terminal output
    """
    
    BANNER = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗  █████╗ ███████╗███████╗███████╗ ██████╗          ║
║   ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝          ║
║   ██████╔╝███████║█████╗  ███████╗█████╗  ██║               ║
║   ██╔══██╗██╔══██║██╔══╝  ╚════██║██╔══╝  ██║               ║
║   ██║  ██║██║  ██║██║     ███████║███████╗╚██████╗          ║
║   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝ ╚═════╝          ║
║                                                              ║
║            Static Malware Analysis Engine v1.0               ║
║                  [ Linux PE Analyzer ]                       ║
╚══════════════════════════════════════════════════════════════╝
"""
    
    def __init__(self):
        """Initialize CLI."""
        self.args: Optional[argparse.Namespace] = None
    
    def parse_args(self) -> argparse.Namespace:
        """Parse command line arguments."""
        parser = argparse.ArgumentParser(
            description='RafSec Static Malware Analysis Engine',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
    python main.py suspicious.exe
    python main.py malware.exe --full
    python main.py sample.exe --json > report.json
    python main.py --train-dummy
            """
        )
        
        parser.add_argument(
            'file',
            nargs='?',
            help='Path to PE file (.exe, .dll) to analyze'
        )
        
        parser.add_argument(
            '--full', '-f',
            action='store_true',
            help='Full analysis including ML prediction'
        )
        
        parser.add_argument(
            '--json', '-j',
            action='store_true',
            help='Output results in JSON format'
        )
        
        parser.add_argument(
            '--quiet', '-q',
            action='store_true',
            help='Minimal output (just verdict)'
        )
        
        parser.add_argument(
            '--no-color',
            action='store_true',
            help='Disable colored output'
        )
        
        parser.add_argument(
            '--train-dummy',
            action='store_true',
            help='Train ML model with dummy data (demo mode)'
        )
        
        parser.add_argument(
            '--version', '-v',
            action='version',
            version='RafSec v1.0.0'
        )
        
        self.args = parser.parse_args()
        return self.args
    
    def print_banner(self) -> None:
        """Print the RafSec banner."""
        if not self.args.quiet and not self.args.json:
            print(self.BANNER)
    
    def validate_file(self, file_path: str) -> bool:
        """Validate target file before analysis."""
        is_valid, message = FileValidator.validate_for_analysis(file_path)
        
        if not is_valid:
            if self.args.json:
                print(json.dumps({'error': message}, indent=2))
            else:
                ColorPrinter.print_status('ERROR', message)
            return False
        
        return True
    
    def run_analysis(self, file_path: str) -> dict:
        """
        Run the complete analysis pipeline.
        
        Pipeline:
        1. Extract PE features
        2. Heuristic analysis
        3. ML prediction (if --full)
        4. Compile results
        """
        results = {
            'file': file_path,
            'status': 'analyzing'
        }
        
        try:
            # Step 1: Extract Features
            if not self.args.quiet and not self.args.json:
                ColorPrinter.print_colored(
                    "\n[*] Extracting PE features...", 'CYAN'
                )
            
            extractor = PEExtractor(file_path)
            features = extractor.extract_all()
            
            results['hashes'] = {
                'md5': features.md5,
                'sha256': features.sha256,
                'sha1': features.sha1,
                'imphash': features.imphash
            }
            
            results['metadata'] = {
                'size': features.file_size,
                'machine': features.machine_type,
                'timestamp': features.timestamp_readable,
                'sections': features.number_of_sections,
                'imports': features.total_imports,
                'entropy': features.overall_entropy
            }
            
            # Step 2: Heuristic Analysis
            if not self.args.quiet and not self.args.json:
                ColorPrinter.print_colored(
                    "[*] Running heuristic analysis...", 'CYAN'
                )
            
            analyzer = MalwareAnalyzer(features)
            analysis = analyzer.analyze()
            
            results['heuristic'] = {
                'threat_level': analysis.threat_level.value,
                'suspicion_score': analysis.suspicion_score,
                'scores': {
                    'entropy': analysis.entropy_score,
                    'imports': analysis.import_score,
                    'sections': analysis.section_score,
                    'headers': analysis.header_score,
                    'behavior': analysis.behavior_score
                },
                'findings': analysis.findings,
                'anomalies': features.anomalies,
                'recommendations': analysis.recommendations
            }
            
            # Step 3: ML Prediction (if full mode)
            if self.args.full:
                if not self.args.quiet and not self.args.json:
                    ColorPrinter.print_colored(
                        "[*] Running ML classification...", 'CYAN'
                    )
                
                try:
                    classifier = ThreatClassifier()
                    ml_result = classifier.predict(features)
                    
                    results['ml_prediction'] = {
                        'is_malicious': ml_result.is_malicious,
                        'confidence': ml_result.confidence,
                        'probabilities': ml_result.probabilities,
                        'model_version': ml_result.model_version
                    }
                except Exception as e:
                    results['ml_prediction'] = {
                        'error': str(e)
                    }
            
            # Determine final verdict
            results['verdict'] = analysis.threat_level.value
            results['score'] = analysis.suspicion_score
            results['status'] = 'complete'
            
            # Cleanup
            extractor.close()
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def print_results(self, results: dict) -> None:
        """Print analysis results."""
        if self.args.json:
            print(json.dumps(results, indent=2, default=str))
            return
        
        if self.args.quiet:
            verdict = results.get('verdict', 'ERROR')
            score = results.get('score', 0)
            print(f"{verdict} (Score: {score:.1f}/100)")
            return
        
        # Full formatted output
        print("\n" + "=" * 60)
        print("                    ANALYSIS RESULTS")
        print("=" * 60)
        
        # File info
        print(f"\n📁 File: {results['file']}")
        
        if 'hashes' in results:
            hashes = results['hashes']
            print(f"\n🔐 Hashes:")
            print(f"   MD5:     {hashes['md5']}")
            print(f"   SHA256:  {hashes['sha256']}")
            print(f"   Imphash: {hashes['imphash']}")
        
        if 'metadata' in results:
            meta = results['metadata']
            print(f"\n📊 Metadata:")
            print(f"   Size:     {meta['size']:,} bytes")
            print(f"   Machine:  {meta['machine']}")
            print(f"   Compiled: {meta['timestamp']}")
            print(f"   Sections: {meta['sections']}")
            print(f"   Imports:  {meta['imports']}")
            print(f"   Entropy:  {meta['entropy']:.4f}")
        
        if 'heuristic' in results:
            heur = results['heuristic']
            print(f"\n🔍 Heuristic Analysis:")
            print(f"   Threat Level: {heur['threat_level']}")
            print(f"   Score: {heur['suspicion_score']:.1f}/100")
            
            scores = heur['scores']
            print(f"\n   Score Breakdown:")
            print(f"      Entropy:  {scores['entropy']:.1f}/25")
            print(f"      Imports:  {scores['imports']:.1f}/25")
            print(f"      Sections: {scores['sections']:.1f}/20")
            print(f"      Headers:  {scores['headers']:.1f}/15")
            print(f"      Behavior: {scores['behavior']:.1f}/15")
            
            if heur['findings']:
                print(f"\n   ⚠️  Findings ({len(heur['findings'])}):")
                for finding in heur['findings'][:5]:  # Show top 5
                    severity = finding['severity']
                    title = finding['title']
                    if severity == 'CRITICAL':
                        ColorPrinter.print_colored(f"      [{severity}] {title}", 'RED')
                    elif severity == 'HIGH':
                        ColorPrinter.print_colored(f"      [{severity}] {title}", 'YELLOW')
                    else:
                        print(f"      [{severity}] {title}")
        
        if 'ml_prediction' in results and 'error' not in results['ml_prediction']:
            ml = results['ml_prediction']
            print(f"\n🤖 ML Prediction:")
            verdict = "MALICIOUS" if ml['is_malicious'] else "BENIGN"
            confidence = ml['confidence'] * 100
            
            if ml['is_malicious']:
                ColorPrinter.print_colored(
                    f"   Verdict: {verdict} ({confidence:.1f}% confidence)", 'RED'
                )
            else:
                ColorPrinter.print_colored(
                    f"   Verdict: {verdict} ({confidence:.1f}% confidence)", 'GREEN'
                )
        
        # Final verdict
        print("\n" + "=" * 60)
        verdict = results.get('verdict', 'UNKNOWN')
        score = results.get('score', 0)
        
        if verdict in ['CRITICAL', 'HIGH']:
            ColorPrinter.print_colored(
                f"  🚨 FINAL VERDICT: {verdict} (Score: {score:.1f}/100)", 'RED'
            )
        elif verdict == 'MEDIUM':
            ColorPrinter.print_colored(
                f"  ⚠️  FINAL VERDICT: {verdict} (Score: {score:.1f}/100)", 'YELLOW'
            )
        else:
            ColorPrinter.print_colored(
                f"  ✅ FINAL VERDICT: {verdict} (Score: {score:.1f}/100)", 'GREEN'
            )
        
        print("=" * 60 + "\n")
        
        # Recommendations
        if 'heuristic' in results and results['heuristic'].get('recommendations'):
            print("📋 Recommendations:")
            for rec in results['heuristic']['recommendations']:
                print(f"   • {rec}")
            print()
    
    def train_dummy_model(self) -> None:
        """Train ML model with dummy data."""
        print("\n[*] Training ML model with synthetic data...")
        print("    (In production, use real malware samples!)\n")
        
        try:
            classifier = ThreatClassifier()
            metrics = classifier.train_with_dummy_data()
            
            print("=" * 50)
            print("          TRAINING RESULTS")
            print("=" * 50)
            print(f"\nAccuracy: {metrics['accuracy']:.2%}")
            print(f"Samples Trained: {metrics['samples_trained']}")
            print(f"Samples Tested: {metrics['samples_tested']}")
            
            print("\nFeature Importance:")
            importance = sorted(
                metrics['feature_importance'].items(),
                key=lambda x: x[1],
                reverse=True
            )
            for name, imp in importance[:5]:
                bar = "█" * int(imp * 50)
                print(f"  {name:25s} {imp:.4f} {bar}")
            
            classifier.save_model()
            print("\n[OK] Model trained and saved successfully!\n")
            
        except Exception as e:
            print(f"\n[ERROR] Training failed: {e}\n")
    
    def run(self) -> int:
        """
        Main entry point.
        
        Returns:
            Exit code (0 = clean/success, 1 = malicious, 2 = error)
        """
        self.parse_args()
        
        # Handle special modes
        if self.args.train_dummy:
            self.train_dummy_model()
            return 0
        
        # Require file argument for analysis
        if not self.args.file:
            print("Error: Please provide a file to analyze.")
            print("Usage: python main.py <file.exe>")
            print("       python main.py --help for more options")
            return 2
        
        # Print banner
        self.print_banner()
        
        # Validate file
        if not self.validate_file(self.args.file):
            return 2
        
        # Run analysis
        results = self.run_analysis(self.args.file)
        
        # Print results
        self.print_results(results)
        
        # Return exit code based on verdict
        if results.get('status') == 'error':
            return 2
        elif results.get('verdict') in ['HIGH', 'CRITICAL']:
            return 1
        else:
            return 0


def main():
    """Entry point for the CLI."""
    cli = RafSecCLI()
    sys.exit(cli.run())


if __name__ == '__main__':
    main()
