#!/usr/bin/env python3
"""
Retheme all PlantUML diagrams to Oblivion Edge brand colors.
Tron-like dark theme with teal/cyan glow and steel accents.
"""
import os
import re
import glob

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIAGRAM_DIR = os.path.join(BASE, "docs", "diagrams")

# Oblivion Edge palette
THEME_HEADER = """
skinparam backgroundColor #0D1117
skinparam defaultFontColor #E0E0E0
skinparam defaultFontSize 10
skinparam ArrowColor #4DD0E1
skinparam ArrowFontColor #B0BEC5

skinparam rectangle {
  BackgroundColor #1A2332
  BorderColor #00BCD4
  FontColor #E0E0E0
  BorderThickness 1
  RoundCorner 5
}

skinparam note {
  BackgroundColor #1A2332
  BorderColor #37474F
  FontColor #B0BEC5
}

skinparam participant {
  BackgroundColor #1A2332
  BorderColor #00BCD4
  FontColor #E0E0E0
}

skinparam cloud {
  BackgroundColor #0D1B2A
  BorderColor #00BCD4
  FontColor #E0E0E0
}

skinparam database {
  BackgroundColor #1A2332
  BorderColor #4DD0E1
  FontColor #E0E0E0
}

skinparam node {
  BackgroundColor #1A2332
  BorderColor #00E5FF
  FontColor #E0E0E0
}

skinparam package {
  BackgroundColor #0D1B2A
  BorderColor #00BCD4
  FontColor #E0E0E0
}

skinparam component {
  BackgroundColor #1A2332
  BorderColor #00BCD4
  FontColor #E0E0E0
}

skinparam activity {
  BackgroundColor #1A2332
  BorderColor #00BCD4
  FontColor #E0E0E0
  BarColor #00E5FF
}

skinparam sequence {
  ArrowColor #4DD0E1
  LifeLineBorderColor #37474F
  LifeLineBackgroundColor #1A2332
  ParticipantBorderColor #00BCD4
  ParticipantBackgroundColor #1A2332
  ParticipantFontColor #E0E0E0
  DividerBackgroundColor #0D1B2A
  DividerBorderColor #37474F
  DividerFontColor #4DD0E1
  GroupBackgroundColor #0D1B2A
  GroupBorderColor #00BCD4
}

skinparam title {
  FontColor #00E5FF
  BorderColor #00BCD4
  BackgroundColor #0D1117
}
"""

# Color mapping: old color -> new color
# Tier-based colors using the teal palette with semantic meaning
COLOR_MAP = {
    # Reds (malicious/initial access) -> bright red-orange on dark
    "#FFCCCC": "#2A1520",  # light red bg -> dark crimson
    "#FF9999": "#3D1A25",  # medium red -> dark rose
    "#FF8888": "#4A1F2B",  # red -> darker rose
    "#FFB3B3": "#331A22",  # light pink -> dark pink
    "#FF6666": "#FF5252",  # bright red -> accent red (keep bright for emphasis)
    "#FF7777": "#E04848",  # red -> slightly muted red
    "#FFBBBB": "#2D1520",  # pink -> dark pink
    "#FFE0E0": "#1F1520",  # very light pink -> very dark pink
    "#FFE8E8": "#1C1318",  # lightest pink -> near black pink

    # Oranges (payloads/execution) -> amber on dark
    "#FFEEDD": "#1F1A15",  # light orange bg -> dark amber
    "#FFDDBB": "#2A2015",  # medium orange -> dark amber
    "#FFCC88": "#33291A",  # orange -> amber
    "#FFE0B3": "#2A2215",  # light amber -> dark amber
    "#FFB366": "#B87333",  # bright orange -> bronze
    "#FF9933": "#CC7A29",  # deep orange -> copper
    "#FFDDAA": "#2A2015",  # peach -> dark amber
    "#FFE8CC": "#1F1A15",  # light peach -> dark warm

    # Blues (infrastructure/C2) -> teal/cyan on dark
    "#BBDDFF": "#0D2137",  # light blue -> dark navy
    "#6699CC": "#00838F",  # medium blue -> teal
    "#4477AA": "#00695C",  # dark blue -> deep teal
    "#DDEEFF": "#0D1B2A",  # very light blue -> dark navy
    "#CCCCFF": "#0D1A33",  # lavender -> dark indigo
    "#E0E0FF": "#0D1525",  # light lavender -> very dark indigo
    "#99BBDD": "#006064",  # steel blue -> dark cyan

    # Greens (staging/legitimate) -> green-teal on dark
    "#CCFFCC": "#0D2A1A",  # light green -> dark green
    "#66CC66": "#00897B",  # medium green -> teal-green
    "#DDFFDD": "#0D2215",  # very light green -> very dark green
    "#BBFFBB": "#0D2A1A",  # light green -> dark green
    "#E8FFE8": "#0D1F15",  # lightest green -> near black green
    "#E0FFE0": "#0D1F15",  # light green -> very dark green
    "#AAFFAA": "#00796B",  # bright green -> dark teal
    "#99FF99": "#00695C",  # green -> deep teal
    "#88EEEE": "#00838F",  # cyan-green -> teal

    # Purples (domain infrastructure) -> purple-teal on dark
    "#EEDDFF": "#1A0D2A",  # light purple -> dark purple
    "#CC99FF": "#4A148C",  # medium purple -> deep purple
    "#BB88EE": "#38006B",  # purple -> dark purple
    "#AA77DD": "#311B92",  # dark purple -> indigo
    "#EEEEFF": "#0D0D1A",  # lightest purple -> near black
    "#FFE8FF": "#1A0D1A",  # pink-purple -> dark magenta
    "#FFBBFF": "#2A0D2A",  # light magenta -> dark magenta
    "#FFDDFF": "#1F0D1F",  # very light magenta -> very dark magenta

    # Grays (VPN/anonymization) -> steel on dark
    "#E8E8E8": "#1A2332",  # light gray -> dark steel
    "#E0E0E0": "#1A2332",  # gray -> dark steel
    "#CCCCCC": "#263238",  # medium gray -> blue-gray
    "#BBBBBB": "#37474F",  # gray -> dark blue-gray
    "#AAAAAA": "#455A64",  # darker gray -> medium blue-gray
    "#DDDDDD": "#1E2A35",  # light gray -> dark

    # Whites and very light backgrounds
    "#FEFEFE": "#0D1117",  # near-white -> near-black
    "#FFFFFF": "#0D1117",  # white -> near-black

    # Special tier colors
    "#FF6666": "#FF5252",  # T1 C2 accent red
    "#FF9966": "#E65100",  # T2 redirector orange
    "#FFCC66": "#F9A825",  # T3 staging amber
    "#CC9999": "#5D4037",  # T5 bulletproof brown

    # Specific colors in certain diagrams
    "#FFEEDD": "#1F1A15",
    "#FFE0D0": "#1F1815",
    "#FFE0E0": "#1F1520",
}

def retheme_puml(filepath):
    with open(filepath) as f:
        content = f.read()

    # Remove old skinparam blocks that we'll replace
    # Remove backgroundColor line
    content = re.sub(r'skinparam backgroundColor #[0-9A-Fa-f]{6}\n', '', content)

    # Remove old skinparam blocks for rectangle, note, etc.
    content = re.sub(r'skinparam defaultFontSize \d+\n', '', content)
    content = re.sub(r'skinparam ArrowColor #[0-9A-Fa-f]{6}\n', '', content)

    # Remove old skinparam rectangle/cloud/database/node/package blocks
    for element in ['rectangle', 'cloud', 'database', 'node', 'package', 'component']:
        content = re.sub(
            rf'skinparam {element} \{{[^}}]*\}}\n?', '', content, flags=re.DOTALL
        )

    # Remove old defaultFontColor if present
    content = re.sub(r'skinparam defaultFontColor #[0-9A-Fa-f]{6}\n', '', content)

    # Replace inline color codes
    for old_color, new_color in COLOR_MAP.items():
        content = content.replace(old_color, new_color)

    # Also handle lowercase variants
    for old_color, new_color in COLOR_MAP.items():
        content = content.replace(old_color.lower(), new_color)

    # Insert theme header right after @startuml and title line
    # Find the position after @startuml
    startuml_match = re.search(r'(@startuml\n)', content)
    if startuml_match:
        insert_pos = startuml_match.end()
        # Find title line if it exists
        title_match = re.search(r'(title .+\n)', content[insert_pos:])
        if title_match:
            insert_pos += title_match.end()
        content = content[:insert_pos] + THEME_HEADER + content[insert_pos:]

    # Fix any arrow colors that use old hex
    content = re.sub(r'-\[#[0-9A-Fa-f]{6}\]->', '-[#4DD0E1]->', content)
    content = re.sub(r'-\[#FF0000\]->', '-[#FF5252]->', content)
    content = re.sub(r'-\[#0000FF\]->', '-[#00E5FF]->', content)
    content = re.sub(r'-\[#666666\]->', '-[#37474F]->', content)

    # Fix title color
    content = re.sub(r'(title .+)', r'\1', content)

    with open(filepath, 'w') as f:
        f.write(content)

    print(f"  Rethemed: {os.path.basename(filepath)}")


def main():
    puml_files = sorted(glob.glob(os.path.join(DIAGRAM_DIR, "*.puml")))
    print(f"Rethreming {len(puml_files)} diagrams to Oblivion Edge palette...\n")

    for filepath in puml_files:
        retheme_puml(filepath)

    print(f"\nDone. Now compile with: plantuml -tpng docs/diagrams/*.puml")


if __name__ == "__main__":
    main()
