#!/usr/bin/env python3
"""
Generic script to analyze method usage across test files.
Generates analysis organized by test modules with calling function names in dotted notation.
"""

import os
import re
import glob
from collections import defaultdict

indent = "    - "


def find_method_usage(method_name, test_files):
    """Find usage of a method by examining actual method calls in test functions"""
    usages = []

    for test_file in test_files:
        with open(test_file, 'r') as f:
            lines = f.readlines()

        current_class = None
        current_test = None

        for i, line in enumerate(lines):
            line_stripped = line.strip()

            # Check for class definition
            if line_stripped.startswith('class '):
                class_match = re.match(r'class\s+([a-zA-Z0-9_]+)', line_stripped)
                if class_match:
                    current_class = class_match.group(1)
                continue

            # Check for test function definition
            if line_stripped.startswith('def test_') and '(self):' in line_stripped:
                test_match = re.match(r'def\s+(test_[a-zA-Z0-9_]+)', line_stripped)
                if test_match:
                    current_test = test_match.group(1)
                continue

            # Check for regular function definition (non-test)
            if line_stripped.startswith('def ') and not line_stripped.startswith('def test_'):
                func_match = re.match(r'def\s+([a-zA-Z0-9_]+)', line_stripped)
                if func_match:
                    current_test = func_match.group(1)
                continue

            # Check if this line uses the method
            if current_class and current_test:
                if f'self.{method_name}(' in line or f'{method_name}(' in line:
                    module_name = os.path.splitext(os.path.basename(test_file))[0]
                    dotted_name = f"mfa.tests.{module_name}.{current_class}.{current_test}"
                    usages.append(dotted_name)

    return list(set(usages))

def get_all_methods_from_source_file(source_file):
    """Extract all method names from a source file"""
    methods = []

    with open(source_file, 'r') as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        if line.startswith('def '):
            method_match = re.match(r'def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', line)
            if method_match:
                method_name = method_match.group(1)
                if not method_name.startswith('_'):  # Skip private methods
                    methods.append(method_name)

    return methods

def analyze_method_usage(source_file, test_files, output_file):
    """Analyze method usage and generate report organized by test modules"""

    # Get all methods from source file
    all_methods = get_all_methods_from_source_file(source_file)

    # Group usages by test module
    module_usages = defaultdict(lambda: defaultdict(list))

    for method in all_methods:
        usages = find_method_usage(method, test_files)
        for usage in usages:
            # Parse the dotted notation to extract module and class
            parts = usage.split('.')
            if len(parts) >= 4:  # mfa.tests.module.class.function
                module = parts[2]  # test_module
                class_name = parts[3]  # TestClass
                function_name = parts[4] if len(parts) > 4 else 'unknown'
                module_usages[module][method].append(f"{class_name}.{function_name}")

    # Generate report
    report = []
    report.append(f"# Method Usage Analysis")
    report.append(f"")
    report.append(f"Source file: `{source_file}`")
    report.append(f"")

    # Sort modules for consistent output
    for module in sorted(module_usages.keys()):
        report.append(f"## {module}")
        report.append("")

        # Sort methods for consistent output
        for method in sorted(module_usages[module].keys()):
            usages = module_usages[module][method]
            report.append(f"- `{method}()` - {method.replace('_', ' ').title()} ({len(usages)} uses)")

            # Sort usages for consistent output
            for usage in sorted(usages):
                report.append(f"{indent}{usage}")
            report.append("")

    return '\n'.join(report)

def main():
    """Main function to run the analysis"""
    import sys

    # Default parameters
    source_file = 'mfatestcase.py'
    test_pattern = 'test_*.py'
    output_file = 'mfatestcase_usage_analysis.md'

    # Allow command line overrides
    if len(sys.argv) > 1:
        source_file = sys.argv[1]
    if len(sys.argv) > 2:
        test_pattern = sys.argv[2]
    if len(sys.argv) > 3:
        output_file = sys.argv[3]

    # Get test files
    test_files = glob.glob(test_pattern)

    if not test_files:
        print(f"No test files found matching pattern: {test_pattern}")
        return

    if not os.path.exists(source_file):
        print(f"Source file not found: {source_file}")
        return

    # Generate analysis
    analysis = analyze_method_usage(source_file, test_files, output_file)

    # Write to file
    with open(output_file, 'w') as f:
        f.write(analysis)

    print(f"Analysis complete! Updated {output_file}")
    print(f"Analyzed {len(test_files)} test files for methods from {source_file}")

if __name__ == "__main__":
    main()
