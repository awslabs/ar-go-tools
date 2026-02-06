#!/usr/bin/env python3
"""Analyze summary generator logs and print usage statistics."""

import argparse
import re
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path


# ANSI color codes for tools
COLORS = [
    '\033[91m',  # Red
    '\033[92m',  # Green
    '\033[93m',  # Yellow
    '\033[94m',  # Blue
    '\033[95m',  # Magenta
    '\033[96m',  # Cyan
    '\033[97m',  # White
]
RESET = '\033[0m'


def parse_log_line(line):
    """Parse a log line into components."""
    match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) \| (\w+) \| ([\w.]+) \| (.+)', line)
    if not match:
        return None
    timestamp_str, level, logger, message = match.groups()
    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
    return {'timestamp': timestamp, 'level': level, 'logger': logger, 'message': message}


def extract_tool_name(message):
    """Extract tool name from message."""
    match = re.search(r"tool_name=<([^>]+)>", message)
    return match.group(1) if match else None


def compute_statistics(log_file):
    """Compute statistics from log file."""
    with open(log_file) as f:
        lines = [parse_log_line(line) for line in f if line.strip()]
    
    logs = [l for l in lines if l]
    if not logs:
        return {}
    
    # Session stats
    start_time = logs[0]['timestamp']
    end_time = logs[-1]['timestamp']
    duration = (end_time - start_time).total_seconds()
    
    # Model invocation stats
    model_invocations = []
    tool_calls = Counter()
    tool_timeline = []  # (timestamp, tool_name)
    tool_errors = 0
    tool_successes = 0
    
    invoke_time = None
    for log in logs:
        msg = log['message']
        
        # Track model invocations
        if 'invoking model' in msg:
            invoke_time = log['timestamp']
        elif 'finished streaming response' in msg and invoke_time:
            model_invocations.append((log['timestamp'] - invoke_time).total_seconds())
            invoke_time = None
        
        # Track tool usage
        if 'streaming' in msg and 'tool_name=' in msg:
            tool_name = extract_tool_name(msg)
            if tool_name:
                tool_calls[tool_name] += 1
                tool_timeline.append((log['timestamp'], tool_name))
        
        # Track tool results
        if 'status: success' in msg:
            tool_successes += 1
        elif 'status: error' in msg:
            tool_errors += 1
    
    # Level counts
    level_counts = Counter(log['level'] for log in logs)
    
    return {
        'session': {
            'start': start_time,
            'end': end_time,
            'duration_seconds': duration,
            'total_log_entries': len(logs)
        },
        'model': {
            'total_invocations': len(model_invocations),
            'avg_response_time': sum(model_invocations) / len(model_invocations) if model_invocations else 0,
            'min_response_time': min(model_invocations) if model_invocations else 0,
            'max_response_time': max(model_invocations) if model_invocations else 0,
            'total_time': sum(model_invocations)
        },
        'tools': {
            'total_calls': sum(tool_calls.values()),
            'unique_tools': len(tool_calls),
            'successes': tool_successes,
            'errors': tool_errors,
            'by_tool': dict(tool_calls.most_common()),
            'timeline': tool_timeline
        },
        'log_levels': dict(level_counts)
    }


def print_timeline(stats, width=120):
    """Print timeline visualization of tool usage."""
    timeline = stats['tools']['timeline']
    if not timeline:
        return
    
    start = stats['session']['start']
    duration = stats['session']['duration_seconds']
    
    # Assign colors to tools
    unique_tools = sorted(set(tool for _, tool in timeline))
    tool_colors = {tool: COLORS[i % len(COLORS)] for i, tool in enumerate(unique_tools)}
    
    # Create buckets
    buckets = [[] for _ in range(width)]
    for timestamp, tool in timeline:
        elapsed = (timestamp - start).total_seconds()
        bucket_idx = min(int((elapsed / duration) * width), width - 1)
        buckets[bucket_idx].append(tool)
    
    print(f"\n⏱️  TOOL USAGE TIMELINE ({width} columns = {duration:.1f}s)")
    
    # Print timeline
    line = ""
    for bucket in buckets:
        if not bucket:
            line += "\033[100m░\033[0m"  # Grey background with light shade
        else:
            # Use most common tool in bucket
            tool = Counter(bucket).most_common(1)[0][0]
            line += f"{tool_colors[tool]}█{RESET}"
    print(f"  {line}")
    
    # Print time markers at quarters
    markers = "  "
    for i in range(width):
        if i == 0 or i == width // 4 or i == width // 2 or i == 3 * width // 4 or i == width - 1:
            markers += "|"
        else:
            markers += " "
    print(markers)
    
    # Print time labels
    labels = f"  0s{' ' * (width // 4 - 4)}{duration/4:.1f}s{' ' * (width // 4 - 6)}{duration/2:.1f}s{' ' * (width // 4 - 6)}{3*duration/4:.1f}s{' ' * (width // 4 - 6)}{duration:.1f}s"
    print(labels)
    
    # Print legend
    print(f"\n  Legend:")
    for tool in unique_tools:
        count = sum(1 for _, t in timeline if t == tool)
        print(f"    {tool_colors[tool]}█{RESET} {tool} ({count})")


def print_statistics(stats):
    """Print statistics in a readable format."""
    print("=" * 60)
    print("SUMMARY GENERATOR LOG STATISTICS")
    print("=" * 60)
    
    # Session
    s = stats['session']
    print(f"\n📊 SESSION")
    print(f"  Start:    {s['start']}")
    print(f"  End:      {s['end']}")
    print(f"  Duration: {s['duration_seconds']:.1f}s ({s['duration_seconds']/60:.1f}m)")
    print(f"  Log entries: {s['total_log_entries']}")
    
    # Model
    m = stats['model']
    print(f"\n🤖 MODEL INVOCATIONS")
    print(f"  Total calls:     {m['total_invocations']}")
    print(f"  Avg response:    {m['avg_response_time']:.2f}s")
    print(f"  Min response:    {m['min_response_time']:.2f}s")
    print(f"  Max response:    {m['max_response_time']:.2f}s")
    print(f"  Total LLM time:  {m['total_time']:.1f}s ({m['total_time']/60:.1f}m)")
    
    # Tools
    t = stats['tools']
    print(f"\n🔧 TOOL USAGE")
    print(f"  Total calls:   {t['total_calls']}")
    print(f"  Unique tools:  {t['unique_tools']}")
    print(f"  Successes:     {t['successes']}")
    print(f"  Errors:        {t['errors']}")
    
    if t['by_tool']:
        print(f"\n  Top tools:")
        for tool, count in sorted(t['by_tool'].items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"    {tool:30s} {count:3d}")
    
    # Timeline
    print_timeline(stats)
    
    # Log levels
    print(f"\n📝 LOG LEVELS")
    for level, count in sorted(stats['log_levels'].items()):
        print(f"  {level:8s} {count:5d}")
    
    print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(description='Analyze summary generator logs')
    parser.add_argument('log_file', help='Path to log file')
    args = parser.parse_args()
    
    if not Path(args.log_file).exists():
        print(f"Error: Log file not found: {args.log_file}")
        return 1
    
    stats = compute_statistics(args.log_file)
    print_statistics(stats)
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
