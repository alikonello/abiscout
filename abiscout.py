#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
abiscout — offline ABI surface mapper & risk hotspot reporter.

What it does (offline):
  • Load 1..N ABI JSON files (array form or Etherscan-style).
  • Compute 4-byte selectors for all functions.
  • Classify functions into buckets:
      - Ownership/Admin (transferOwnership, renounceOwnership, onlyOwner-ish)
      - AccessControl (grantRole, revokeRole, renounceRole, setRoleAdmin)
      - Upgradeability (upgradeTo, upgradeToAndCall, initialize, proxy admin)
      - Token permissions (approve, permit, setApprovalForAll)
      - Pausable/Guardian (pause, unpause)
      - Value transfer hotspots (payable external, withdraw, sweep)
      - Raw call/exec hooks (execute, multicall, call, delegatecall-ish by name)
  • Mark fallback/receive behavior and whether they are payable.
  • Output:
      - Pretty console summary
      - JSON report (--json)
      - CSV flat list (--csv)
      - SVG badge (--svg) summarizing hotspots

Examples:
  $ python abiscout.py scan MyToken.abi --pretty --svg badge.svg
  $ python abiscout.py scan ./abis/*.json --json surface.json --csv funcs.csv
"""

import csv
import glob
import json
import os
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

import click
from eth_utils import keccak

# ------------------------------ Models ------------------------------

@dataclass
class Func:
    name: str
    selector: str
    state: str             # view|pure|nonpayable|payable
    inputs: List[Dict[str, Any]]
    outputs: List[Dict[str, Any]]
    kind: str              # function|constructor|fallback|receive
    bucket: List[str]      # classification tags

@dataclass
class Report:
    file: str
    contracts: List[str]
    funcs: List[Func]
    fallback: Optional[Dict[str, Any]]
    receive: Optional[Dict[str, Any]]
    totals: Dict[str, int]
    hotspots: Dict[str, int]  # counts by tag

# ------------------------------ Helpers ------------------------------

ADMIN_NAMES = {"owner", "getowner", "getOwner"}
ADMIN_MUTATORS = {"transferownership", "renounceownership"}
ACCESS_CTRL = {"grantrole", "revokerole", "renouncerole", "setroleadmin"}
UPGRADES = {"upgradeto", "upgradetoandcall", "changeadmin", "upgrade", "proxiadmin", "proxyadmin", "upgradeimplementation"}
INIT_NAMES = {"initialize", "initializer"}
PAUSABLE = {"pause", "unpause"}
TOKEN_PERMS = {
    "approve(address,uint256)": "approve",
    "setApprovalForAll(address,bool)": "setApprovalForAll",
    "permit(address,address,uint256,uint256,uint256,uint8,bytes32,bytes32)": "permit"
}
RAW_EXEC = {"execute", "rawcall", "call", "delegatecall", "functioncall", "multicall"}

VALUE_DRAIN_HINTS = {"withdraw", "sweep", "rescue", "claim", "transfereth", "sendeth"}

def fn_signature(name: str, inputs: List[Dict[str, Any]]) -> str:
    types = ",".join([normalize_abi_type(i.get("type","")) for i in inputs])
    return f"{name}({types})"

def normalize_abi_type(t: str) -> str:
    # Tidy Etherscan weirdness like "uint" -> "uint256"
    if t == "uint": return "uint256"
    if t == "int": return "int256"
    return t

def fourbyte(sig: str) -> str:
    return "0x" + keccak(text=sig)[:4].hex()

def classify(name: str, signature: str, state: str, payable: bool) -> List[str]:
    tags: List[str] = []
    lname = name.lower()
    if lname in ADMIN_MUTATORS or lname in {"setowner"}:
        tags.append("admin.owner-change")
    if lname in ADMIN_NAMES:
        tags.append("admin.read-owner")
    if lname in ACCESS_CTRL:
        tags.append("access.role-change")
    if lname in UPGRADES or signature.startswith(("upgradeTo(", "upgradeToAndCall(")):
        tags.append("upgradeability")
    if lname in INIT_NAMES:
        tags.append("init")
    if signature in TOKEN_PERMS or lname in {"approve", "setapprovalforall", "permit"}:
        tags.append("token.permission")
    if lname in PAUSABLE:
        tags.append("pause-control")
    if lname in RAW_EXEC or lname.startswith(("exec", "multicall")):
        tags.append("raw.exec")
    if payable or lname in VALUE_DRAIN_HINTS:
        tags.append("value-path")
    return tags

def load_abi(path: str) -> List[Dict[str, Any]]:
    """
    Accept:
      - Plain array ABI
      - Etherscan-style JSON with "result" being a stringified ABI
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "abi" in data and isinstance(data["abi"], list):
            return data["abi"]
        if "result" in data:
            try:
                arr = json.loads(data["result"])
                if isinstance(arr, list):
                    return arr
            except Exception:
                pass
    raise click.ClickException(f"Unrecognized ABI format: {path}")

# ------------------------------ Core scan ------------------------------

def scan_one(path: str) -> Report:
    abi = load_abi(path)

    funcs: List[Func] = []
    fallback = None
    receive = None
    contracts = set()

    for item in abi:
        typ = item.get("type", "function")
        state = item.get("stateMutability", "nonpayable")
        name = item.get("name", "") if typ == "function" else typ

        if typ in ("fallback", "receive"):
            meta = {"stateMutability": state, "payable": state == "payable", "type": typ}
            if typ == "fallback": fallback = meta
            if typ == "receive": receive = meta
            continue

        if typ == "constructor":
            # treat as function-like for reporting
            f = Func(
                name="constructor",
                selector="0x",  # no selector
                state=state,
                inputs=item.get("inputs", []),
                outputs=item.get("outputs", []),
                kind="constructor",
                bucket=["init"] if state in ("nonpayable", "payable") else []
            )
            funcs.append(f)
            continue

        if typ != "function":
            continue

        inputs = item.get("inputs", [])
        outputs = item.get("outputs", [])
        sig = fn_signature(name, inputs)
        sel = fourbyte(sig)
        payable = state == "payable"

        tags = classify(name, sig, state, payable)

        funcs.append(Func(
            name=name,
            selector=sel,
            state=state,
            inputs=inputs,
            outputs=outputs,
            kind="function",
            bucket=tags
        ))

        # Guess contract name if present in devdoc/metadata (optional)
        if "name" in item:
            contracts.add(item["name"])

    # Totals & hotspots
    totals = {
        "functions": sum(1 for f in funcs if f.kind == "function"),
        "payable": sum(1 for f in funcs if f.state == "payable"),
        "view": sum(1 for f in funcs if f.state == "view"),
        "pure": sum(1 for f in funcs if f.state == "pure"),
        "init": sum(1 for f in funcs if "init" in f.bucket) + (1 if receive else 0) + (1 if fallback else 0),
    }

    hotspot_tags = ["admin.owner-change","access.role-change","upgradeability","token.permission","raw.exec","value-path","pause-control"]
    hotspots = {t: sum(1 for f in funcs if t in f.bucket) for t in hotspot_tags}

    return Report(
        file=os.path.basename(path),
        contracts=sorted(list(contracts)) or [os.path.splitext(os.path.basename(path))[0]],
        funcs=funcs,
        fallback=fallback,
        receive=receive,
        totals=totals,
        hotspots=hotspots
    )

# ------------------------------ CLI ------------------------------

@click.group(context_settings=dict(help_option_names=["-h","--help"]))
def cli():
    """abiscout — offline ABI surface mapper & risk hotspot reporter."""
    pass

@cli.command("scan")
@click.argument("paths", nargs=-1)
@click.option("--pretty", is_flag=True, help="Human-readable summary to stdout.")
@click.option("--json", "json_out", type=click.Path(writable=True), default=None, help="Write JSON report (array per file).")
@click.option("--csv", "csv_out", type=click.Path(writable=True), default=None, help="Write CSV of functions (flat list).")
@click.option("--svg", "svg_out", type=click.Path(writable=True), default=None, help="Write tiny SVG badge for the first file scanned.")
def scan_cmd(paths, pretty, json_out, csv_out, svg_out):
    """Scan one or more ABI JSON files (or globs like ./abis/*.json)."""
    # Expand globs
    expanded: List[str] = []
    for p in paths or []:
        g = glob.glob(p)
        if g:
            expanded.extend(g)
        elif os.path.isfile(p):
            expanded.append(p)
    if not expanded:
        raise click.ClickException("No ABI files found. Pass paths or globs like ./abis/*.json")

    reports = [scan_one(p) for p in expanded]

    if pretty:
        for rep in reports:
            click.echo(f"== {rep.file} == ")
            fb = (rep.fallback or {}).get("stateMutability")
            rc = (rep.receive or {}).get("stateMutability")
            if rep.receive:
                click.echo(f"  receive(): {rc}")
            if rep.fallback:
                click.echo(f"  fallback(): {fb}")
            # Hotspots summary
            hot = {k:v for k,v in rep.hotspots.items() if v>0}
            if hot:
                click.echo("  hotspots:")
                for k,v in hot.items():
                    click.echo(f"    - {k}: {v}")
            # Top functions
            click.echo("  functions:")
            for f in rep.funcs[:10]:
                tags = ",".join(f.bucket) if f.bucket else "-"
                click.echo(f"    {f.selector}  {f.name}({','.join([i.get('type','') for i in f.inputs])})  [{f.state}]  {tags}")
            if len(rep.funcs) > 10:
                click.echo(f"    … +{len(rep.funcs)-10} more")
            click.echo("")

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump([{
                "file": r.file,
                "contracts": r.contracts,
                "totals": r.totals,
                "hotspots": r.hotspots,
                "fallback": r.fallback,
                "receive": r.receive,
                "functions": [asdict(x) for x in r.funcs]
            }], f, indent=2)
        click.echo(f"Wrote JSON report: {json_out}")

    if csv_out:
        with open(csv_out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["file","name","selector","state","bucket","inputs","outputs"])
            for r in reports:
                for fn in r.funcs:
                    w.writerow([
                        r.file,
                        fn.name,
                        fn.selector,
                        fn.state,
                        "|".join(fn.bucket),
                        ",".join(i.get("type","") for i in fn.inputs),
                        ",".join(o.get("type","") for o in fn.outputs),
                    ])
        click.echo(f"Wrote CSV: {csv_out}")

    if svg_out:
        r0 = reports[0]
        high = r0.hotspots.get("upgradeability",0) + r0.hotspots.get("admin.owner-change",0) + r0.hotspots.get("access.role-change",0)
        med = r0.hotspots.get("token.permission",0) + r0.hotspots.get("raw.exec",0) + r0.hotspots.get("value-path",0)
        color = "#3fb950" if (high==0 and med==0) else "#d29922" if (high==0 and med>0) else "#f85149"
        label = f"admin:{r0.hotspots.get('admin.owner-change',0)}  roles:{r0.hotspots.get('access.role-change',0)}  upg:{r0.hotspots.get('upgradeability',0)}"
        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="680" height="48" role="img" aria-label="abiscout hotspots">
  <rect width="680" height="48" fill="#0d1117" rx="8"/>
  <text x="16" y="30" font-family="Segoe UI, Inter, Arial" font-size="16" fill="#e6edf3">
    abiscout: {r0.file} — {label}
  </text>
  <circle cx="655" cy="24" r="6" fill="{color}"/>
</svg>"""
        with open(svg_out, "w", encoding="utf-8") as f:
            f.write(svg)
        click.echo(f"Wrote SVG badge: {svg_out}")

    if not (pretty or json_out or csv_out or svg_out):
        # default to JSON on stdout
        click.echo(json.dumps([{
            "file": r.file,
            "contracts": r.contracts,
            "totals": r.totals,
            "hotspots": r.hotspots,
            "fallback": r.fallback,
            "receive": r.receive,
            "functions": [asdict(x) for x in r.funcs]
        } for r in reports], indent=2))

if __name__ == "__main__":
    cli()
