#!/usr/bin/env python3

from typing import Optional, List
# from

CONFIG = "release"


class PowersOfTauProcessCommand:
    """
    Wrapper around the pot-process command.
    """

    def __init__(
            self, pot_process_tool: Optional[str] = None, dry_run: bool = False):
        self.pot_process_tool = pot_process_tool or _default_tool()
        self.dry_run = dry_run

    def compute_lagrange(
            self,
            pot_file: str,
            pot_degree: int,
            lagrange_output_file: str,
            lagrange_degree: Optional[int]) -> bool:
        lagrange_degree = lagrange_degree or pot_degree
        return self._exec(
            ["--out", lagrange_output_file,
             "--lagrange-degree", str(lagrange_degree),
             pot_file,
             str(pot_degree)])

    def _exec(self, args: List[str]) -> bool:
        import subprocess
        args = [self.pot_process_tool] + args
        print(f"CMD: {' '.join(args)}")
        return self.dry_run or \
            subprocess.run(args=args, check=False).returncode == 0


def _default_tool() -> str:
    from os.path import join, dirname
    return join(dirname(__file__), "..", "..", "build", "src", "pot-process")
