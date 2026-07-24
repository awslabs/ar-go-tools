"""Safe file operation tools for the summary generator agent."""

import os
import subprocess
from pathlib import Path
from typing import List
from strands.tools import tool


def create_dataflow_prompt_tool(repo_root: str):
    """Create a tool that returns the dataflow summary generation prompt.
    
    Args:
        repo_root: Path to the repository root
        
    Returns:
        Tool function
    """
    prompt_path = Path(repo_root) / "cmd" / "argot-mcp-server" / "dataflow-summary-generation-prompt.txt"
    
    @tool
    def get_dataflow_summary_prompt() -> str:
        """Get the dataflow summary generation prompt.
        
        Returns the complete prompt that explains how to generate dataflow summaries
        for Go functions in YAML format.
        
        Returns:
            The dataflow summary generation prompt text
        """
        try:
            if not prompt_path.exists():
                return f"Error: Prompt file not found at {prompt_path}"
            
            with open(prompt_path, 'r') as f:
                return f.read()
        except Exception as e:
            return f"Error reading prompt: {e}"
    
    return get_dataflow_summary_prompt


def create_go_doc_tool(cwd: str):
    """Create a tool that runs `go doc` for a package/function/method query.

    Args:
        cwd: Directory to run `go doc` from -- must be inside the target repo's own Go
            module for the query to resolve against that module's dependencies, so this
            should be the same directory passed as mcp_cwd (not config_dir, which may be a
            different, unrelated module).

    Returns:
        Tool function
    """

    @tool
    def go_doc(query: str, src: bool = False) -> str:
        """Run `go doc` to look up a function/method/type's signature and documentation.

        Always includes unexported symbols (`go doc -u`), since many functions/types worth
        summarizing (e.g. unexported structs/methods on a public package) are otherwise
        reported as "not found" even though they exist.

        Args:
            query: The go doc query, e.g. "fmt.Sprintf" or "bytes.Buffer.Write"
            src: If true, also show the source code (equivalent to `go doc -src`)

        Returns:
            The command's output, or an error message
        """
        cmd = ["go", "doc", "-u"]
        if src:
            cmd.append("-src")
        cmd.append(query)
        try:
            result = subprocess.run(
                cmd, cwd=cwd, capture_output=True, text=True, timeout=30
            )
            output = result.stdout
            if result.returncode != 0:
                output += f"\n(exit code {result.returncode})\n{result.stderr}"
            return output or "(no output)"
        except subprocess.TimeoutExpired:
            return "Error: go doc timed out after 30s"
        except Exception as e:
            return f"Error running go doc: {e}"

    return go_doc


class SafeFileTools:
    """File operation tools restricted to a base directory."""
    
    def __init__(self, base_dir: str):
        """Initialize with a base directory for all operations.
        
        Args:
            base_dir: Base directory - all operations are restricted to this directory and subdirectories
        """
        self.base_dir = Path(base_dir).resolve()
    
    def _validate_path(self, path: str) -> Path:
        """Validate that a path is within the base directory.
        
        Args:
            path: Path to validate (relative or absolute)
            
        Returns:
            Resolved absolute path
            
        Raises:
            ValueError: If path is outside base directory
        """
        # Resolve the path relative to base_dir
        if Path(path).is_absolute():
            resolved = Path(path).resolve()
        else:
            resolved = (self.base_dir / path).resolve()
        
        # Check if it's within base_dir
        try:
            resolved.relative_to(self.base_dir)
        except ValueError:
            raise ValueError(f"Path {path} is outside allowed directory {self.base_dir}")
        
        return resolved
    
    @tool
    def list_files(self, directory: str = ".") -> str:
        """List files and directories in a directory.
        
        Args:
            directory: Directory path (relative to config directory, default: current)
            
        Returns:
            List of files and directories
        """
        try:
            dir_path = self._validate_path(directory)
            
            if not dir_path.exists():
                return f"Error: Directory {directory} does not exist"
            
            if not dir_path.is_dir():
                return f"Error: {directory} is not a directory"
            
            entries = []
            for entry in sorted(dir_path.iterdir()):
                entry_type = "DIR" if entry.is_dir() else "FILE"
                rel_path = entry.relative_to(self.base_dir)
                entries.append(f"{entry_type}: {rel_path}")
            
            return "\n".join(entries) if entries else "Empty directory"
            
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Error listing directory: {e}"
    
    @tool
    def read_file(self, file_path: str) -> str:
        """Read contents of a text file.
        
        Args:
            file_path: Path to file (relative to config directory)
            
        Returns:
            File contents
        """
        try:
            path = self._validate_path(file_path)
            
            if not path.exists():
                return f"Error: File {file_path} does not exist"
            
            if not path.is_file():
                return f"Error: {file_path} is not a file"
            
            with open(path, 'r') as f:
                return f.read()
                
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Error reading file: {e}"
    
    @tool
    def write_yaml_file(self, file_path: str, content: str) -> str:
        """Write content to a YAML file.
        
        Only .yaml and .yml files can be written.
        
        Args:
            file_path: Path to YAML file (relative to config directory)
            content: YAML content to write
            
        Returns:
            Success or error message
        """
        try:
            path = self._validate_path(file_path)
            
            # Check file extension
            if path.suffix not in ['.yaml', '.yml']:
                return f"Error: Only .yaml and .yml files can be written, got {path.suffix}"
            
            # Create parent directories if needed
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, 'w') as f:
                f.write(content)
            
            rel_path = path.relative_to(self.base_dir)
            return f"Successfully wrote {rel_path}"
            
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Error writing file: {e}"
    
    def get_tools(self) -> List:
        """Get list of tool functions for the agent.
        
        Returns:
            List of tool functions
        """
        return [self.list_files, self.read_file, self.write_yaml_file]

