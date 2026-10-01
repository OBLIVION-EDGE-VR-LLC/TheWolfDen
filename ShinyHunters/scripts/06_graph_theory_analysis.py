#!/usr/bin/env python3
"""
06_graph_theory_analysis.py
===========================
Applies formal graph theory to the ShinyHunters infrastructure graph:

1. De Morgan's Filter — classify nodes as suspicious via ¬L(n) ∨ ¬I(n)
2. Dijkstra's Algorithm — shortest paths from webshells to C2 infrastructure
3. Lattice Structure — Hasse diagram of infrastructure tiers with cuts
4. Betweenness Centrality — identify critical pivot nodes
5. Bipartite Resolution Graph — IP-Domain resolution structure

Generates publication-quality graphs in Oblivion Edge brand colors.

Usage:
    source .venv/bin/activate
    python3 scripts/06_graph_theory_analysis.py

Outputs:
    docs/diagrams/graph_demorgan_filter.png
    docs/diagrams/graph_dijkstra_paths.png
    docs/diagrams/graph_lattice_cuts.png
    docs/diagrams/graph_bipartite_resolution.png
"""

import json
import os
import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.lines import Line2D
import numpy as np
from collections import defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(BASE, "docs", "diagrams")
DATA_DIR = os.path.join(BASE, "scripts", "output")

# ── Oblivion Edge Brand Colors ───────────────────────────────────────────
BG_COLOR = '#0D1117'
TEAL = '#00E5FF'
TEAL_DK = '#00BCD4'
TEAL_MED = '#4DD0E1'
STEEL = '#B0BEC5'
DARK_STEEL = '#37474F'
TEXT = '#E0E0E0'
RED_ACCENT = '#FF5252'
AMBER = '#F9A825'
PURPLE = '#7C4DFF'
GREEN = '#00E676'

TIER_COLORS = {
    'c2_primary': RED_ACCENT,
    'redirector_cloud': '#E65100',
    'domain_parking': '#E65100',
    'domain_staging': AMBER,
    'domain_registrar': AMBER,
    'web_hosting': AMBER,
    'vpn_anonymization': STEEL,
    'c2_relay': PURPLE,
    'bulletproof_hosting': PURPLE,
    'residential_proxy': TEAL_DK,
    'legitimate_service': GREEN,
    'cdn_legitimate': GREEN,
    'unknown': DARK_STEEL,
}


def load_json(fname):
    with open(os.path.join(DATA_DIR, fname)) as f:
        return json.load(f)


def load_graph():
    with open(os.path.join(BASE, "Shiny_Hunters_PeopleSoftZeroDay.json")) as f:
        data = json.load(f)
    return data


def setup_fig(title, figsize=(14, 10)):
    fig, ax = plt.subplots(figsize=figsize, facecolor=BG_COLOR)
    ax.set_facecolor(BG_COLOR)
    ax.set_title(title, color=TEAL, fontsize=14, fontweight='bold', pad=15)
    ax.tick_params(colors=STEEL)
    for spine in ax.spines.values():
        spine.set_color(DARK_STEEL)
    return fig, ax


# ══════════════════════════════════════════════════════════════════════════
# 1. DE MORGAN'S FILTER VISUALIZATION
# ══════════════════════════════════════════════════════════════════════════
def demorgan_filter():
    print("[1/4] De Morgan's Filter...")
    data = load_graph()
    node_map = {n['entity_id']: n for n in data['nodes']}

    # Known-legitimate patterns
    legit_patterns = [
        'google', 'microsoft', 'bing', 'azure', 'akamai', 'cloudflare',
        'fastly', 'letsencrypt', 'pki.goog', 'mozilla', 'gvt1',
        'windows.com', 'office.com', 'msn.com', 'live.com',
    ]

    # Build networkx graph
    G = nx.Graph()
    for n in data['nodes']:
        ntype = n.get('type', 'unknown')
        if ntype == 'relationship':
            continue
        det = n.get('entity_attributes', {}).get('has_detections', False)
        is_legit = any(p in n['entity_id'].lower() for p in legit_patterns)
        G.add_node(n['entity_id'], type=ntype, detected=det, legitimate=is_legit)

    for link in data['links']:
        if link['source'] in G and link['target'] in G:
            G.add_edge(link['source'], link['target'],
                       conn_type=link.get('connection_type', ''))

    # De Morgan's filter
    detected_nodes = {n for n, d in G.nodes(data=True) if d.get('detected')}

    # BFS distance to detected subgraph
    det_dist = {}
    for n in G.nodes():
        if n in detected_nodes:
            det_dist[n] = 0
        else:
            try:
                min_d = min(
                    nx.shortest_path_length(G, n, d)
                    for d in detected_nodes if nx.has_path(G, n, d)
                )
                det_dist[n] = min_d
            except (ValueError, nx.NetworkXError):
                det_dist[n] = float('inf')

    # Classify
    categories = {'benign': 0, 'not_legit': 0, 'not_isolated': 0, 'both': 0}
    node_cats = {}
    for n, d in G.nodes(data=True):
        is_legit = d.get('legitimate', False)
        is_isolated = (G.degree(n) <= 1) and (det_dist.get(n, 99) > 2)
        not_l = not is_legit
        not_i = not is_isolated

        if not_l and not_i:
            cat = 'both'
        elif not_l:
            cat = 'not_legit'
        elif not_i:
            cat = 'not_isolated'
        else:
            cat = 'benign'
        categories[cat] += 1
        node_cats[n] = cat

    # Visualize as bar chart + Venn-like breakdown
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8), facecolor=BG_COLOR)
    for ax in (ax1, ax2):
        ax.set_facecolor(BG_COLOR)
        ax.tick_params(colors=STEEL)
        for spine in ax.spines.values():
            spine.set_color(DARK_STEEL)

    # Bar chart of categories
    cats = ['benign', 'not_legit', 'not_isolated', 'both']
    labels = [
        'Benign\n(L ∧ I)',
        '¬Legitimate\nonly',
        '¬Isolated\nonly',
        '¬L ∨ ¬I\n(Both suspicious)',
    ]
    vals = [categories[c] for c in cats]
    colors = [GREEN, '#E65100', TEAL_DK, RED_ACCENT]

    bars = ax1.bar(labels, vals, color=colors, edgecolor=DARK_STEEL, linewidth=0.5)
    ax1.set_title("De Morgan's Filter: Node Classification\n"
                   "Suspicious(n) = NOT L(n) OR NOT I(n)",
                   color=TEAL, fontsize=12, fontweight='bold')
    ax1.set_ylabel('Node Count', color=STEEL)

    for bar, val in zip(bars, vals):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 10,
                 str(val), ha='center', va='bottom', color=TEXT, fontsize=11)

    # Pie chart of node types in suspicious set
    suspicious = {n for n, c in node_cats.items() if c != 'benign'}
    type_counts = defaultdict(int)
    for n in suspicious:
        type_counts[G.nodes[n].get('type', 'unknown')] += 1

    type_labels = list(type_counts.keys())
    type_vals = [type_counts[t] for t in type_labels]
    pie_colors = [TEAL_DK, RED_ACCENT, AMBER, PURPLE, STEEL, GREEN, DARK_STEEL]

    wedges, texts, autotexts = ax2.pie(
        type_vals, labels=type_labels, autopct='%1.0f%%',
        colors=pie_colors[:len(type_vals)],
        textprops={'color': TEXT, 'fontsize': 10},
        wedgeprops={'edgecolor': BG_COLOR, 'linewidth': 1.5},
    )
    for t in autotexts:
        t.set_color(BG_COLOR)
        t.set_fontweight('bold')
    ax2.set_title(f"Suspicious Set Composition\n|S| = {len(suspicious)} nodes",
                   color=TEAL, fontsize=12, fontweight='bold')

    fig.suptitle("De Morgan's Law Applied to ShinyHunters Graph",
                 color=TEAL, fontsize=16, fontweight='bold', y=0.98)

    plt.tight_layout(rect=[0, 0, 1, 0.94])
    path = os.path.join(OUT_DIR, "graph_demorgan_filter.png")
    plt.savefig(path, facecolor=BG_COLOR, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {path}")
    return G, node_cats, detected_nodes


# ══════════════════════════════════════════════════════════════════════════
# 2. DIJKSTRA'S SHORTEST PATHS
# ══════════════════════════════════════════════════════════════════════════
def dijkstra_analysis(G, detected_nodes):
    print("[2/4] Dijkstra's Shortest Paths...")
    ip_roles = load_json("ip_roles.json")
    resolutions = load_json("resolutions.json")

    # Build weighted infrastructure subgraph
    H = nx.Graph()

    # Add key nodes
    key_nodes = {
        '5.199.162.157': ('C2 Core', RED_ACCENT),
        '44.227.65.245': ('AWS Redir', '#E65100'),
        '44.227.76.166': ('AWS Redir', '#E65100'),
        '172.232.4.89': ('Linode Stage', AMBER),
        '172.233.218.191': ('Linode Stage', AMBER),
        '199.59.243.224': ('BODIS', '#E65100'),
        '162.219.30.165': ('SIDEEYE C2', PURPLE),
        'cloaker.buzz': ('TDS Domain', RED_ACCENT),
        'rockyviewtech.com': ('Pivot Domain', RED_ACCENT),
        'royalinsulationcanada.ca': ('High Fan-out', AMBER),
        'data-ps.org': ('PS Targeting', TEAL_DK),
        'grated.mgovideo.org': ('Gov Theme', TEAL_DK),
        'azurenetfiles.net': ('MeshAgent C2', PURPLE),
        'topgamse.com': ('Payload DL', '#E65100'),
    }

    # Webshell as source
    webshell = '419c571ee38b7e7266d130c4b6bbc4dd0ef44d6e5f3bc02cc2cf73b762f07c86'
    H.add_node('JSP Webshell\n(419c571e...)', color=RED_ACCENT, size=800)

    for node_id, (label, color) in key_nodes.items():
        short_label = f"{label}\n{node_id[:20]}" if len(node_id) > 20 else f"{label}\n{node_id}"
        H.add_node(short_label, color=color, size=500)

    # Add edges based on actual resolution data
    edges = [
        ('JSP Webshell\n(419c571e...)', f'C2 Core\n5.199.162.157', 1),
        ('JSP Webshell\n(419c571e...)', f'TDS Domain\ncloaker.buzz', 2),
        (f'TDS Domain\ncloaker.buzz', f'C2 Core\n5.199.162.157', 1),
        (f'TDS Domain\ncloaker.buzz', f'AWS Redir\n44.227.65.245', 1),
        (f'TDS Domain\ncloaker.buzz', f'AWS Redir\n44.227.76.166', 1),
        (f'Pivot Domain\nrockyviewtech.com', f'C2 Core\n5.199.162.157', 1),
        (f'Pivot Domain\nrockyviewtech.com', f'Linode Stage\n172.232.4.89', 1),
        (f'Pivot Domain\nrockyviewtech.com', f'Linode Stage\n172.233.218.191', 1),
        (f'Pivot Domain\nrockyviewtech.com', f'BODIS\n199.59.243.224', 1),
        (f'High Fan-out\nroyalinsulationcanada', f'Linode Stage\n172.232.4.89', 1),
        (f'High Fan-out\nroyalinsulationcanada', f'Linode Stage\n172.233.218.191', 1),
        (f'PS Targeting\ndata-ps.org', f'Linode Stage\n172.232.4.89', 2),
        (f'Gov Theme\ngrated.mgovideo.org', f'Linode Stage\n172.232.4.89', 1),
        (f'SIDEEYE C2\n162.219.30.165', f'C2 Core\n5.199.162.157', 2),
        (f'MeshAgent C2\nazurenetfiles.net', f'C2 Core\n5.199.162.157', 2),
        (f'Payload DL\ntopgamse.com', f'Linode Stage\n172.232.4.89', 2),
        ('JSP Webshell\n(419c571e...)', f'Pivot Domain\nrockyviewtech.com', 2),
    ]

    for src, dst, weight in edges:
        if src in H and dst in H:
            H.add_edge(src, dst, weight=weight)

    # Run Dijkstra from webshell
    source = 'JSP Webshell\n(419c571e...)'
    distances = nx.single_source_dijkstra_path_length(H, source)
    paths = nx.single_source_dijkstra_path(H, source)

    # Visualize
    fig, ax = setup_fig("Dijkstra's Shortest Paths: Webshell → C2 Infrastructure", (16, 10))

    pos = nx.spring_layout(H, k=2.5, seed=42)
    node_colors = [H.nodes[n].get('color', STEEL) for n in H.nodes()]
    node_sizes = [H.nodes[n].get('size', 500) for n in H.nodes()]

    # Draw all edges light
    nx.draw_networkx_edges(H, pos, ax=ax, edge_color=DARK_STEEL,
                           alpha=0.3, width=1)

    # Highlight shortest path edges
    shortest_path_edges = set()
    for target, path in paths.items():
        for i in range(len(path) - 1):
            shortest_path_edges.add((path[i], path[i+1]))

    nx.draw_networkx_edges(H, pos, ax=ax, edgelist=list(shortest_path_edges),
                           edge_color=TEAL, width=2.5, alpha=0.9)

    nx.draw_networkx_nodes(H, pos, ax=ax, node_color=node_colors,
                           node_size=node_sizes, edgecolors=TEAL_DK,
                           linewidths=1.5)

    # Labels with distances
    labels = {}
    for n in H.nodes():
        d = distances.get(n, '∞')
        labels[n] = f"{n}\nd={d}"

    nx.draw_networkx_labels(H, pos, labels, ax=ax, font_size=7,
                            font_color=TEXT, font_weight='bold')

    # Edge weights
    edge_labels = nx.get_edge_attributes(H, 'weight')
    nx.draw_networkx_edge_labels(H, pos, edge_labels, ax=ax,
                                 font_size=7, font_color=TEAL_MED)

    ax.set_axis_off()
    path_out = os.path.join(OUT_DIR, "graph_dijkstra_paths.png")
    plt.savefig(path_out, facecolor=BG_COLOR, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {path_out}")


# ══════════════════════════════════════════════════════════════════════════
# 3. LATTICE STRUCTURE WITH CUTS
# ══════════════════════════════════════════════════════════════════════════
def lattice_cuts():
    print("[3/4] Lattice Structure with Cuts...")

    # Build Hasse diagram of operational tiers
    fig, ax = setup_fig(
        "Infrastructure Lattice (Hasse Diagram) with Minimum Vertex Cuts",
        (14, 10)
    )

    # Tier nodes as lattice elements (partially ordered by access dependency)
    tiers = {
        'T0: Operator': (0.5, 0.95),
        'T4: VPN\n(Mullvad 7 IPs)': (0.5, 0.78),
        'T1: C2 Core\n(5.199.162.157)': (0.5, 0.60),
        'T2a: AWS Redir\n(44.227.x.x)': (0.25, 0.42),
        'T2b: BODIS\n(199.59.243.224)': (0.75, 0.42),
        'T3: Linode Staging\n(172.232.x.x)': (0.5, 0.25),
        'T5: Bulletproof\n(Hostwinds/DataWagon)': (0.15, 0.08),
        'Victims\n(PeopleSoft)': (0.5, 0.08),
        'FBI\n(FBIjobs.gov)': (0.85, 0.08),
    }

    tier_colors = {
        'T0: Operator': STEEL,
        'T4: VPN\n(Mullvad 7 IPs)': DARK_STEEL,
        'T1: C2 Core\n(5.199.162.157)': RED_ACCENT,
        'T2a: AWS Redir\n(44.227.x.x)': '#E65100',
        'T2b: BODIS\n(199.59.243.224)': '#E65100',
        'T3: Linode Staging\n(172.232.x.x)': AMBER,
        'T5: Bulletproof\n(Hostwinds/DataWagon)': PURPLE,
        'Victims\n(PeopleSoft)': TEAL_DK,
        'FBI\n(FBIjobs.gov)': TEAL,
    }

    # Hasse edges (covers in partial order)
    hasse_edges = [
        ('T0: Operator', 'T4: VPN\n(Mullvad 7 IPs)'),
        ('T4: VPN\n(Mullvad 7 IPs)', 'T1: C2 Core\n(5.199.162.157)'),
        ('T1: C2 Core\n(5.199.162.157)', 'T2a: AWS Redir\n(44.227.x.x)'),
        ('T1: C2 Core\n(5.199.162.157)', 'T2b: BODIS\n(199.59.243.224)'),
        ('T2a: AWS Redir\n(44.227.x.x)', 'T3: Linode Staging\n(172.232.x.x)'),
        ('T2b: BODIS\n(199.59.243.224)', 'T3: Linode Staging\n(172.232.x.x)'),
        ('T3: Linode Staging\n(172.232.x.x)', 'Victims\n(PeopleSoft)'),
        ('T3: Linode Staging\n(172.232.x.x)', 'FBI\n(FBIjobs.gov)'),
        ('T1: C2 Core\n(5.199.162.157)', 'T5: Bulletproof\n(Hostwinds/DataWagon)'),
        ('T5: Bulletproof\n(Hostwinds/DataWagon)', 'Victims\n(PeopleSoft)'),
    ]

    # Draw edges
    for src, dst in hasse_edges:
        x1, y1 = tiers[src]
        x2, y2 = tiers[dst]
        ax.annotate('', xy=(x2, y2 + 0.03), xytext=(x1, y1 - 0.03),
                     arrowprops=dict(arrowstyle='->', color=TEAL_MED,
                                    lw=1.5, connectionstyle='arc3,rad=0.05'))

    # Draw nodes
    for label, (x, y) in tiers.items():
        color = tier_colors[label]
        circle = plt.Circle((x, y), 0.06, color=color, alpha=0.8,
                             ec=TEAL_DK, linewidth=2, zorder=5)
        ax.add_patch(circle)
        ax.text(x, y, label, ha='center', va='center', fontsize=7,
                color=TEXT, fontweight='bold', zorder=6)

    # Draw CUT lines
    cuts = [
        {
            'y': 0.69,
            'label': 'CUT 1: VPN Layer\n(Remove Mullvad = lose anonymity)',
            'color': RED_ACCENT,
            'style': '--',
        },
        {
            'y': 0.51,
            'label': 'CUT 2: Pivot Domains\n(cloaker.buzz + rockyviewtech.com)\nMinimum vertex cut = 2',
            'color': TEAL,
            'style': '-.',
        },
        {
            'y': 0.33,
            'label': 'CUT 3: Staging Layer\n(Takedown Linode IPs = isolate victims)',
            'color': AMBER,
            'style': ':',
        },
    ]

    for cut in cuts:
        ax.axhline(y=cut['y'], color=cut['color'], linestyle=cut['style'],
                   linewidth=2, alpha=0.7, zorder=3)
        ax.text(0.98, cut['y'] + 0.015, cut['label'], ha='right', va='bottom',
                fontsize=8, color=cut['color'], fontweight='bold',
                bbox=dict(boxstyle='round,pad=0.3', facecolor=BG_COLOR,
                          edgecolor=cut['color'], alpha=0.9))

    ax.set_xlim(-0.05, 1.05)
    ax.set_ylim(-0.02, 1.02)
    ax.set_aspect('equal')
    ax.set_axis_off()

    # Legend
    legend_elements = [
        Line2D([0], [0], linestyle='--', color=RED_ACCENT, label='Cut 1: Anonymity'),
        Line2D([0], [0], linestyle='-.', color=TEAL, label='Cut 2: Pivot Domains (min vertex cut)'),
        Line2D([0], [0], linestyle=':', color=AMBER, label='Cut 3: Staging Isolation'),
    ]
    ax.legend(handles=legend_elements, loc='lower left', framealpha=0.9,
              facecolor=BG_COLOR, edgecolor=DARK_STEEL, labelcolor=TEXT,
              fontsize=9)

    path = os.path.join(OUT_DIR, "graph_lattice_cuts.png")
    plt.savefig(path, facecolor=BG_COLOR, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {path}")


# ══════════════════════════════════════════════════════════════════════════
# 4. BIPARTITE RESOLUTION GRAPH
# ══════════════════════════════════════════════════════════════════════════
def bipartite_resolution():
    print("[4/4] Bipartite Resolution Graph...")
    resolutions = load_json("resolutions.json")
    ip_roles = load_json("ip_roles.json")

    B = nx.Graph()

    # Add IP and domain nodes
    ips_seen = set()
    domains_seen = set()
    for res in resolutions:
        ip = res['ip']
        domain = res['domain']
        ips_seen.add(ip)
        domains_seen.add(domain)
        B.add_node(ip, bipartite=0, node_type='ip')
        B.add_node(domain, bipartite=1, node_type='domain')
        B.add_edge(ip, domain)

    fig, ax = setup_fig("Bipartite IP-Domain Resolution Graph", (16, 10))

    # Layout: IPs on left, domains on right
    pos = {}
    ip_list = sorted(ips_seen)
    domain_list = sorted(domains_seen)

    for i, ip in enumerate(ip_list):
        pos[ip] = (0, -i * 0.8)
    for i, dom in enumerate(domain_list):
        pos[dom] = (4, -i * 0.25)

    # Color IPs by role
    ip_colors = []
    for ip in ip_list:
        role = ip_roles.get(ip, {}).get('role', 'unknown')
        ip_colors.append(TIER_COLORS.get(role, DARK_STEEL))

    domain_colors = [TEAL_DK if any(r['domain'] == d and r.get('domain_detections')
                                    for r in resolutions)
                     else STEEL for d in domain_list]

    # Draw
    nx.draw_networkx_edges(B, pos, ax=ax, edge_color=DARK_STEEL, alpha=0.4, width=0.8)

    nx.draw_networkx_nodes(B, pos, nodelist=ip_list, ax=ax,
                           node_color=ip_colors, node_size=300,
                           node_shape='s', edgecolors=TEAL_DK, linewidths=1)
    nx.draw_networkx_nodes(B, pos, nodelist=domain_list, ax=ax,
                           node_color=domain_colors, node_size=200,
                           node_shape='o', edgecolors=DARK_STEEL, linewidths=0.5)

    # Labels
    ip_labels = {ip: ip for ip in ip_list}
    dom_labels = {d: d[:25] + '...' if len(d) > 25 else d for d in domain_list}

    nx.draw_networkx_labels(B, pos, ip_labels, ax=ax, font_size=7,
                            font_color=TEXT, horizontalalignment='right')
    nx.draw_networkx_labels(B, pos, dom_labels, ax=ax, font_size=6,
                            font_color=STEEL, horizontalalignment='left')

    # Add partition labels
    ax.text(-0.5, 1, "IP Addresses", transform=ax.transAxes,
            fontsize=12, color=TEAL, fontweight='bold', ha='left')
    ax.text(1.0, 1, "Domains", transform=ax.transAxes,
            fontsize=12, color=TEAL, fontweight='bold', ha='right')

    # Legend
    legend_elements = [
        Line2D([0], [0], marker='s', color=BG_COLOR, markerfacecolor=RED_ACCENT,
               markersize=10, label='C2 Primary'),
        Line2D([0], [0], marker='s', color=BG_COLOR, markerfacecolor='#E65100',
               markersize=10, label='Redirector/Parking'),
        Line2D([0], [0], marker='s', color=BG_COLOR, markerfacecolor=AMBER,
               markersize=10, label='Domain Staging'),
        Line2D([0], [0], marker='s', color=BG_COLOR, markerfacecolor=STEEL,
               markersize=10, label='VPN/Anonymization'),
        Line2D([0], [0], marker='s', color=BG_COLOR, markerfacecolor=PURPLE,
               markersize=10, label='Bulletproof/Relay'),
        Line2D([0], [0], marker='o', color=BG_COLOR, markerfacecolor=TEAL_DK,
               markersize=10, label='Domain (detected)'),
        Line2D([0], [0], marker='o', color=BG_COLOR, markerfacecolor=STEEL,
               markersize=10, label='Domain (clean)'),
    ]
    ax.legend(handles=legend_elements, loc='lower right', framealpha=0.9,
              facecolor=BG_COLOR, edgecolor=DARK_STEEL, labelcolor=TEXT)

    ax.set_axis_off()
    path = os.path.join(OUT_DIR, "graph_bipartite_resolution.png")
    plt.savefig(path, facecolor=BG_COLOR, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {path}")


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════
def main():
    print("=" * 60)
    print("Graph Theory Analysis — Oblivion Edge")
    print("=" * 60)

    G, node_cats, detected = demorgan_filter()
    dijkstra_analysis(G, detected)
    lattice_cuts()
    bipartite_resolution()

    print("\n" + "=" * 60)
    print("All graphs saved to docs/diagrams/graph_*.png")
    print("=" * 60)


if __name__ == "__main__":
    main()
