#!/usr/bin/env python3
"""
PHASMOWATCH v1.1
Monitors Phasmophobia process memory pointers (from pointers.xml) and displays:
 - detected ghost type
 - ghost selection chart (highlighted)
 - evidence chart (3 columns, highlights matching evidences)

This script is intended for EDUCATIONAL / DEBUGGING purposes (memory-reading education).
See README.md for ethics/disclaimer.
"""

import os
import time
import struct
import signal
import sys
from collections import Counter
from lxml import etree
import psutil
from pymem import Pymem, process

# --- CONFIG ---
PROCESS_NAME = "Phasmophobia.exe"
XML_FILE = "pointers.xml"
REFRESH_INTERVAL = 30  # seconds

# --- GHOSTS ---
GHOST_TYPES = {
    0: "Spirit",
    1: "Wraith",
    2: "Phantom",
    3: "Poltergeist",
    4: "Banshee",
    5: "Jinn",
    6: "Mare",
    7: "Revenant",
    8: "Shade",
    9: "Demon",
    10: "Yurei",
    11: "Oni",
    12: "Yokai",
    13: "Hantu",
    14: "Goryo",
    15: "Myling",
    16: "Onryo",
    17: "The Twins",
    18: "Raiju",
    19: "Obake",
    20: "The Mimic",
    21: "Moroi",
    22: "Deogen",
    23: "Thaye"
}

# --- EVIDENCE MAP ---
# Each ghost maps to its canonical evidences (primary 3). The Mimic historically has a hidden orb presence,
# so it is represented here as an extra note in the list.
EVIDENCE_MAP = {
    "Spirit": ["EMF Level 5", "Spirit Box", "Ghost Writing"],
    "Wraith": ["EMF Level 5", "Spirit Box", "D.O.T.S Projector"],
    "Phantom": ["Spirit Box", "D.O.T.S Projector", "Fingerprints"],
    "Poltergeist": ["Spirit Box", "Ghost Writing", "Fingerprints"],
    "Banshee": ["D.O.T.S Projector", "Fingerprints", "Ghost Orb"],
    "Jinn": ["EMF Level 5", "Freezing Temperatures", "Fingerprints"],
    "Mare": ["Ghost Orb", "Spirit Box", "Ghost Writing"],
    "Revenant": ["Freezing Temperatures", "Ghost Writing", "Ghost Orb"],
    "Shade": ["EMF Level 5", "Freezing Temperatures", "Ghost Writing"],
    "Demon": ["Freezing Temperatures", "Fingerprints", "Ghost Writing"],
    "Yurei": ["Freezing Temperatures", "D.O.T.S Projector", "Ghost Orb"],
    "Oni": ["EMF Level 5", "D.O.T.S Projector", "Freezing Temperatures"],
    "Yokai": ["Spirit Box", "Ghost Orb", "D.O.T.S Projector"],
    "Hantu": ["Freezing Temperatures", "Fingerprints", "Ghost Orb"],
    "Goryo": ["EMF Level 5", "D.O.T.S Projector", "Fingerprints"],
    "Myling": ["EMF Level 5", "Fingerprints", "Ghost Writing"],
    "Onryo": ["Spirit Box", "Freezing Temperatures", "Ghost Orb"],
    "The Twins": ["EMF Level 5", "Spirit Box", "Freezing Temperatures"],
    "Raiju": ["EMF Level 5", "D.O.T.S Projector", "Ghost Orb"],
    "Obake": ["EMF Level 5", "Fingerprints", "Ghost Orb"],
    "The Mimic": ["Spirit Box", "Fingerprints", "Freezing Temperatures", "(+Ghost Orb hidden)"],
    "Moroi": ["Spirit Box", "Ghost Writing", "Freezing Temperatures"],
    "Deogen": ["Spirit Box", "Ghost Writing", "D.O.T.S Projector"],
    "Thaye": ["Ghost Orb", "Ghost Writing", "D.O.T.S Projector"]
}

# --- ALL EVIDENCES (display order) ---
ALL_EVIDENCES = [
    "EMF Level 5",
    "Spirit Box",
    "Ghost Writing",
    "Fingerprints",
    "Freezing Temperatures",
    "Ghost Orb",
    "D.O.T.S Projector",
]

# --- COLORS ---
RESET = "\033[0m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
GREEN = "\033[92m"
RED = "\033[91m"
BOLD = "\033[1m"

# Graceful exit flag
RUNNING = True


def signal_handler(signum, frame):
    global RUNNING
    RUNNING = False


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def find_pid_by_name(name):
    for p in psutil.process_iter(["name", "pid"]):
        try:
            if p.info["name"] and p.info["name"].lower() == name.lower():
                return p.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def parse_address_spec(spec):
    s = spec.strip().replace('"', "")
    module, off = s.split("+", 1)
    return module.strip(), int(off.strip().replace("0x", ""), 16)


def parse_offsets(offset_nodes):
    offs = []
    for n in offset_nodes:
        txt = (n.text or "").strip().lower().replace("0x", "")
        if txt:
            offs.append(int(txt, 16))
    return offs


def resolve_pointer(pm, module_name, base_offset, offsets):
    """
    Resolve a multi-level pointer using a pattern consistent with the original code.
    Returns final absolute address or None on failure.
    """
    try:
        mod = process.module_from_name(pm.process_handle, module_name)
        base_addr = mod.lpBaseOfDll + base_offset
        # read pointer at module base + base_offset
        addr_bytes = pm.read_bytes(base_addr, 8)
        addr = int.from_bytes(addr_bytes, "little")
        # follow intermediate offsets (all but last)
        for off in offsets[:-1]:
            addr_bytes = pm.read_bytes(addr + off, 8)
            addr = int.from_bytes(addr_bytes, "little")
        # final target = last offset added
        return addr + (offsets[-1] if offsets else 0)
    except Exception:
        return None


def load_entries(xml_path):
    tree = etree.parse(xml_path)
    entries = tree.findall(".//CheatEntry")
    parsed = []
    for entry in entries:
        addr_spec = entry.findtext("Address")
        offsets_node = entry.find("Offsets")
        offsets = []
        if offsets_node is not None:
            offsets = parse_offsets(offsets_node.findall("Offset"))
            # NOTE: keep the same reversal behavior as your original tool
            offsets.reverse()
        if not addr_spec:
            continue
        module_name, base_offset = parse_address_spec(addr_spec)
        parsed.append((module_name, base_offset, offsets))
    return parsed


def draw_header(title):
    bar = f"{MAGENTA}{'=' * 40}{RESET}"
    print(f"{bar}\n{BOLD}{CYAN}{title.center(40)}{RESET}\n{bar}\n")


def draw_value_line(value, address, ratio):
    print(f"{BOLD}{CYAN}Value:{RESET} {value} at {hex(address)} {ratio} hits\n")


def draw_ghost_chart(current_ghost):
    ghost_names = [
        ["Spirit", "Wraith", "Phantom"],
        ["Poltergeist", "Banshee", "Jinn"],
        ["Mare", "Revenant", "Shade"],
        ["Demon", "Yurei", "Oni"],
        ["Yokai", "Hantu", "Goryo"],
        ["Myling", "Onryo", "The Twins"],
        ["Raiju", "Obake", "The Mimic"],
        ["Moroi", "Deogen", "Thaye"]
    ]

    for row in ghost_names:
        row_display = []
        for g in row:
            if current_ghost and g.lower() == current_ghost.lower():
                row_display.append(f"{BOLD}{GREEN}{g:<12}{RESET}")
            else:
                row_display.append(f"{g:<12}")
        print("  ".join(row_display))

    print(f"{MAGENTA}{'-' * 40}{RESET}\n")

def draw_evidence_chart(current_ghost):
    """
    Display ALL evidences in 2 columns and highlight ones that match the current_ghost.
    """
    ghost_evidence = []
    if current_ghost:
        ghost_evidence = [e.lower() for e in EVIDENCE_MAP.get(current_ghost, [])]

    col_width = 23
    # 2 columns
    for i in range(0, len(ALL_EVIDENCES), 2):
        row = ALL_EVIDENCES[i:i + 2]
        display_row = []
        for ev in row:
            # highlight if this evidence is part of the ghost's evidences
            matches = any(ev.lower() in ge or ge in ev.lower() for ge in ghost_evidence)
            if matches:
                display_row.append(f"{BOLD}{GREEN}{ev:<{col_width}}{RESET}")
            else:
                display_row.append(f"{ev:<{col_width}}")
        print("  ".join(display_row))

    print(f"{MAGENTA}{'-' * 40}{RESET}")


def main():
    if not os.path.exists(XML_FILE):
        print(f"{RED}Missing {XML_FILE}{RESET}")
        return

    entries = load_entries(XML_FILE)
    if not entries:
        print(f"{RED}No valid entries found in XML.{RESET}")
        return

    global RUNNING
    while RUNNING:
        clear_screen()
        draw_header("PHASMOWATCH  v1.1")

        pid = find_pid_by_name(PROCESS_NAME)
        if not pid:
            print(f"{RED}Game not running... waiting for {PROCESS_NAME}{RESET}")
            for _ in range(max(1, REFRESH_INTERVAL)):
                if not RUNNING:
                    break
                time.sleep(1)
            continue

        pm = None
        try:
            pm = Pymem(PROCESS_NAME)
        except Exception as e:
            print(f"{RED}Could not attach to process: {e}{RESET}")
            for _ in range(max(1, REFRESH_INTERVAL)):
                if not RUNNING:
                    break
                time.sleep(1)
            continue

        try:
            results = []
            for module_name, base_offset, offsets in entries:
                addr = resolve_pointer(pm, module_name, base_offset, offsets)
                if addr:
                    try:
                        raw = pm.read_bytes(addr, 4)
                        val = struct.unpack("<i", raw)[0]
                        results.append((addr, val))
                    except Exception:
                        # skip invalid reads
                        continue

            if not results:
                print(f"{RED}No valid pointers found.{RESET}")
                for _ in range(max(1, REFRESH_INTERVAL)):
                    if not RUNNING:
                        break
                    time.sleep(1)
                continue

            addrs = [a for a, _ in results]
            counter = Counter(addrs)
            best_addr, count = counter.most_common(1)[0]

            try:
                raw_best = pm.read_bytes(best_addr, 4)
                value = struct.unpack("<i", raw_best)[0]
            except Exception:
                print(f"{RED}Memory read failed.{RESET}")
                for _ in range(max(1, REFRESH_INTERVAL)):
                    if not RUNNING:
                        break
                    time.sleep(1)
                continue

            ghost = GHOST_TYPES.get(value, "Unknown")
            draw_value_line(f"{value}", best_addr, f"{count}/{len(results)}")
            draw_ghost_chart(ghost)
            draw_evidence_chart(ghost)

            # refresh countdown
            print(f"{CYAN}Refreshing in {REFRESH_INTERVAL}s... (press Ctrl+C to quit){RESET}")
            for _ in range(max(1, REFRESH_INTERVAL)):
                if not RUNNING:
                    break
                time.sleep(1)

        finally:
            # attempt to close Pymem cleanly
            try:
                if pm:
                    pm.close_process()
            except Exception:
                pass

    print("\nExiting PHASMOWATCH. Goodbye.")


if __name__ == "__main__":
    main()
