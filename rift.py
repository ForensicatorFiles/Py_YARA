#!/usr/bin/env python3

import curses
import os
import zipfile
import yara  # type: ignore
import argparse
from typing import List, Tuple
from tqdm import tqdm


# ======================================================================
#  ZIP SCANNING + YARA MATCHING
# ======================================================================

def scan_zip_for_matches(zip_path: str, rules) -> List[Tuple[str, List[str]]]:
    """
    Scans a ZIP archive with YARA rules.
    Returns a list of tuples: (file_path_inside_zip, matched_rule_list)
    """

    matches = []

    with zipfile.ZipFile(zip_path, "r") as z:
        namelist = z.namelist()

        print(f"[*] Scanning {len(namelist)} files with YARA…")

        for name in tqdm(namelist, desc="Scanning", unit="file"):
            matched = set()

            # Filename matching
            try:
                for m in rules.match(data=name):
                    matched.add(m.rule)
            except Exception:
                pass

            ## NOTE: Content scanning disabled for speed & safety
            ## Uncomment carefully — opening unknown files can be slow/dangerous
            ##
            # try:
            #     with z.open(name) as f:
            #         data = f.read()
            #     for m in rules.match(data=data):
            #         matched.add(m.rule)
            # except Exception:
            #     pass

            if matched:
                matches.append((name, sorted(list(matched))))

    return matches


def is_folder(path: str) -> bool:
    """Detects if a ZIP path entry represents a folder."""
    return path.endswith("/")


def safe_extract(zip_path: str, files: List[str], out_dir: str):
    """
    Extracts only the selected files.
    Flattens paths so all files land directly inside out_dir/.
    """

    os.makedirs(out_dir, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as z:
        for f in files:
            filename_only = os.path.basename(f)
            target = os.path.join(out_dir, filename_only)

            try:
                with z.open(f) as fr, open(target, "wb") as fw:
                    fw.write(fr.read())
            except Exception as e:
                print(f"[!] Failed to extract {f}: {e}")


# ======================================================================
#  CYBERPUNK CURSES UI
# ======================================================================

class CursesUI:

    def __init__(self, matches, zip_path, out_dir):
        self.matches = matches
        self.zip_path = zip_path
        self.out_dir = out_dir

        self.selected = [False] * len(matches)
        self.idx = 0
        self.scroll = 0

    # --------------------------------------------------------------
    # Entry point
    # --------------------------------------------------------------
    def run(self):
        curses.wrapper(self.main)

    # --------------------------------------------------------------
    # Color initialization
    # --------------------------------------------------------------
    def init_colors(self):
        """
        Defines cyberpunk color palette for curses.
        """

        curses.start_color()

        # Basic neon cyberpunk palette
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)      # header
        curses.init_pair(2, curses.COLOR_MAGENTA, curses.COLOR_BLACK)   # highlight
        curses.init_pair(3, curses.COLOR_GREEN, curses.COLOR_BLACK)     # selected file
        curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK)    # rule list
        curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)   # footer / help bar

    # --------------------------------------------------------------
    # Main UI loop
    # --------------------------------------------------------------
    def main(self, stdscr):
        curses.curs_set(0)
        stdscr.nodelay(False)
        stdscr.keypad(True)
        self.init_colors()

        while True:
            stdscr.clear()
            max_y, max_x = stdscr.getmaxyx()

            list_width = int(max_x * 0.65)
            sidebar_x = list_width + 2

            # -------------------------
            # TITLE + HEADER
            # -------------------------
            stdscr.attron(curses.color_pair(1))
            stdscr.addstr(0, 0, "YARA ZIP SCANNER (FF EDITION)")
            stdscr.addstr(1, 0, f"Archive: {self.zip_path}")
            stdscr.attroff(curses.color_pair(1))

            stdscr.addstr(3, 0, "Sel  File".ljust(list_width - 1), curses.color_pair(1))
            stdscr.addstr(3, sidebar_x, "Matched Rules", curses.color_pair(1))

            # -------------------------
            # SCROLL LOGIC
            # -------------------------
            visible_rows = max_y - 6

            if self.idx < self.scroll:
                self.scroll = self.idx
            elif self.idx >= self.scroll + visible_rows:
                self.scroll = max(0, self.idx - visible_rows + 1)

            # -------------------------
            # MAIN FILE LIST
            # -------------------------
            for screen_row in range(visible_rows):
                match_idx = self.scroll + screen_row
                if match_idx >= len(self.matches):
                    break

                fname, _rules = self.matches[match_idx]

                # Selected marker
                marker = "[x]" if self.selected[match_idx] else "[ ]"
                display = f"{marker} {fname}"

                # Highlight current row
                if match_idx == self.idx:
                    stdscr.addstr(
                        4 + screen_row,
                        0,
                        display[:list_width - 1],
                        curses.color_pair(2) | curses.A_BOLD
                    )
                else:
                    color = curses.color_pair(3) if self.selected[match_idx] else curses.A_NORMAL
                    stdscr.addstr(4 + screen_row, 0, display[:list_width - 1], color)

            # -------------------------
            # SIDEBAR: MATCHED RULES
            # -------------------------
            if 0 <= self.idx < len(self.matches):
                _, rule_list = self.matches[self.idx]
                y = 4
                for r in rule_list:
                    if y < max_y - 2:
                        stdscr.addstr(
                            y,
                            sidebar_x,
                            f"- {r}",
                            curses.color_pair(4)
                        )
                    y += 1

            # -------------------------
            # FOOTER / HELP BAR
            # -------------------------
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(
                max_y - 1,
                0,
                "↑/↓ Move  SPACE Toggle  ENTER Extract  A All  D None  ESC Quit".ljust(max_x - 1)
            )
            stdscr.attroff(curses.color_pair(5))

            # -------------------------
            # INPUT HANDLING
            # -------------------------
            key = stdscr.getch()

            if key in (curses.KEY_UP, ord('k')):
                self.idx = max(0, self.idx - 1)

            elif key in (curses.KEY_DOWN, ord('j')):
                self.idx = min(len(self.matches) - 1, self.idx + 1)

            elif key == ord(' '):
                # Toggle file or whole directory
                current_path = self.matches[self.idx][0]
                new_val = not self.selected[self.idx]

                if is_folder(current_path):
                    self.selected[self.idx] = new_val
                    for i, (path, _) in enumerate(self.matches):
                        if path.startswith(current_path) and not is_folder(path):
                            self.selected[i] = new_val
                else:
                    self.selected[self.idx] = new_val

            elif key == ord('a'):
                self.selected = [True] * len(self.matches)

            elif key == ord('d'):
                self.selected = [False] * len(self.matches)

            elif key in (curses.KEY_ENTER, 10, 13):
                selected_files = [self.matches[i][0] for i, v in enumerate(self.selected) if v]
                if selected_files:
                    self.extract_popup(stdscr, selected_files)
                else:
                    curses.flash()

            elif key == 27:  # ESC
                break

    # --------------------------------------------------------------
    # Extraction popup window
    # --------------------------------------------------------------
    def extract_popup(self, stdscr, files):
        max_y, max_x = stdscr.getmaxyx()

        box_w = 50
        box_h = 7
        box_y = (max_y - box_h) // 2
        box_x = (max_x - box_w) // 2

        safe_extract(self.zip_path, files, self.out_dir)

        win = curses.newwin(box_h, box_w, box_y, box_x)
        win.border()

        win.addstr(1, 2, "Extraction Complete!", curses.color_pair(2) | curses.A_BOLD)
        win.addstr(3, 2, f"{len(files)} files saved to:")
        win.addstr(4, 2, self.out_dir[:box_w - 4], curses.color_pair(3))
        win.addstr(5, 2, "Press any key to continue.")

        win.refresh()
        win.getch()


# ======================================================================
# MAIN
# ======================================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("zip_path")
    parser.add_argument("rules_path")
    parser.add_argument("-o", "--out", default="extracted")
    args = parser.parse_args()

    rules = yara.compile(filepath=args.rules_path)
    matches = scan_zip_for_matches(args.zip_path, rules)

    if not matches:
        print("[*] No matches found.")
        return

    ui = CursesUI(matches, args.zip_path, args.out)
    ui.run()


if __name__ == "__main__":
    main()
