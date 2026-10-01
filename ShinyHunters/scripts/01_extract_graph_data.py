#!/usr/bin/env python3
"""
01_extract_graph_data.py
========================
Extracts and structures all node/link data from the ShinyHunters PeopleSoft
zero-day campaign VirusTotal graph exports.

Outputs structured JSON summaries to scripts/output/ for downstream analysis.

Usage:
    python3 scripts/01_extract_graph_data.py
"""

import json
import os
from collections import defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "scripts", "output")
os.makedirs(OUT, exist_ok=True)


def load_json(fname):
    with open(os.path.join(BASE, fname)) as f:
        return json.load(f)


def main():
    # Load all data sources
    graph = load_json("Shiny_Hunters_PeopleSoftZeroDay.json")
    entire = load_json("EntireGraph.json")
    webshell_ids = load_json(
        "b809f2a5-0acc-4270-b428-d995746f8722_jspWebShellIdentifiers.json"
    )
    undefined = load_json("undefined.json")

    webshell_hashes = set(webshell_ids["files"])
    node_map = {n["entity_id"]: n for n in graph["nodes"]}

    # ── 1. Categorize all nodes ──────────────────────────────────────────
    nodes_by_type = defaultdict(list)
    for n in graph["nodes"]:
        ntype = n.get("type", "unknown")
        entry = {
            "id": n["entity_id"],
            "type": ntype,
            "has_detections": n.get("entity_attributes", {}).get(
                "has_detections", False
            ),
            "country": n.get("entity_attributes", {}).get("country", ""),
        }
        nodes_by_type[ntype].append(entry)

    # ── 2. Build adjacency with connection types ─────────────────────────
    adjacency = defaultdict(list)
    for link in graph["links"]:
        src, tgt, ct = link["source"], link["target"], link["connection_type"]
        adjacency[src].append({"target": tgt, "type": ct})
        adjacency[tgt].append({"target": src, "type": ct})

    # ── 3. Trace webshell → relationship → entity (2-hop) ───────────────
    webshell_connections = defaultdict(lambda: defaultdict(list))
    for link in graph["links"]:
        src, tgt, ct = link["source"], link["target"], link["connection_type"]
        if src in webshell_hashes and node_map.get(tgt, {}).get("type") == "relationship":
            rel_id = tgt
            for link2 in graph["links"]:
                if link2["source"] == rel_id or link2["target"] == rel_id:
                    other = (
                        link2["target"]
                        if link2["source"] == rel_id
                        else link2["source"]
                    )
                    if other != src and other in node_map:
                        other_node = node_map[other]
                        if other_node["type"] in (
                            "ip_address",
                            "domain",
                            "file",
                            "url",
                        ):
                            webshell_connections[src][ct].append(
                                {
                                    "id": other,
                                    "type": other_node["type"],
                                    "has_detections": other_node.get(
                                        "entity_attributes", {}
                                    ).get("has_detections", False),
                                    "country": other_node.get(
                                        "entity_attributes", {}
                                    ).get("country", ""),
                                }
                            )

    # ── 4. Extract resolution chains (domain ↔ IP) ──────────────────────
    resolutions = []
    for link in graph["links"]:
        if link["connection_type"] == "resolutions":
            src_node = node_map.get(link["source"], {})
            tgt_node = node_map.get(link["target"], {})
            # Trace through relationship nodes
            if src_node.get("type") == "ip_address":
                ip_id = link["source"]
                rel_id = link["target"]
                # Find domains linked to this resolution relationship
                for link2 in graph["links"]:
                    if (link2["source"] == rel_id or link2["target"] == rel_id) and (
                        link2["source"] != ip_id and link2["target"] != ip_id
                    ):
                        other = (
                            link2["target"]
                            if link2["source"] == rel_id
                            else link2["source"]
                        )
                        other_node = node_map.get(other, {})
                        if other_node.get("type") == "domain":
                            resolutions.append(
                                {
                                    "ip": ip_id,
                                    "domain": other,
                                    "ip_detections": node_map[ip_id]
                                    .get("entity_attributes", {})
                                    .get("has_detections", False),
                                    "domain_detections": other_node.get(
                                        "entity_attributes", {}
                                    ).get("has_detections", False),
                                }
                            )
            elif src_node.get("type") == "domain":
                domain_id = link["source"]
                rel_id = link["target"]
                for link2 in graph["links"]:
                    if (link2["source"] == rel_id or link2["target"] == rel_id) and (
                        link2["source"] != domain_id
                        and link2["target"] != domain_id
                    ):
                        other = (
                            link2["target"]
                            if link2["source"] == rel_id
                            else link2["source"]
                        )
                        other_node = node_map.get(other, {})
                        if other_node.get("type") == "ip_address":
                            resolutions.append(
                                {
                                    "ip": other,
                                    "domain": domain_id,
                                    "ip_detections": other_node.get(
                                        "entity_attributes", {}
                                    ).get("has_detections", False),
                                    "domain_detections": node_map[domain_id]
                                    .get("entity_attributes", {})
                                    .get("has_detections", False),
                                }
                            )

    # ── 5. Detected IPs with metadata ────────────────────────────────────
    detected_ips = [
        {
            "ip": n["entity_id"],
            "country": n.get("entity_attributes", {}).get("country", ""),
            "has_detections": True,
        }
        for n in graph["nodes"]
        if n["type"] == "ip_address"
        and n.get("entity_attributes", {}).get("has_detections")
    ]

    # ── 6. Detected domains ─────────────────────────────────────────────
    detected_domains = [
        {"domain": n["entity_id"], "has_detections": True}
        for n in graph["nodes"]
        if n["type"] == "domain"
        and n.get("entity_attributes", {}).get("has_detections")
    ]

    # ── 7. SSL certificate relationships ─────────────────────────────────
    ssl_links = []
    for link in graph["links"]:
        if link["connection_type"] == "historical_ssl_certificates":
            ssl_links.append(
                {"source": link["source"], "target": link["target"]}
            )

    # ── 8. Communicating files (files contacting IPs) ────────────────────
    comm_files = []
    for link in graph["links"]:
        if link["connection_type"] == "communicating_files":
            comm_files.append(
                {
                    "source": link["source"],
                    "target": link["target"],
                    "source_type": node_map.get(link["source"], {}).get("type", ""),
                    "target_type": node_map.get(link["target"], {}).get("type", ""),
                }
            )

    # ── 9. Identify DGA domain patterns ──────────────────────────────────
    dga_patterns = defaultdict(list)
    for n in graph["nodes"]:
        if n["type"] == "domain":
            d = n["entity_id"]
            if d.startswith("gacy"):
                dga_patterns["gacy*.com"].append(d)
            elif d.startswith("gady"):
                dga_patterns["gady*.com"].append(d)
            elif d.startswith("gahy"):
                dga_patterns["gahy*.com"].append(d)
            # Random consonant-heavy patterns
            parts = d.split(".")
            if len(parts) >= 2 and len(parts[0]) >= 8:
                vowels = sum(1 for c in parts[0] if c in "aeiou")
                if vowels / len(parts[0]) < 0.2 and len(parts[0]) > 10:
                    dga_patterns["random_consonant"].append(d)

    # ── 10. IP clustering ────────────────────────────────────────────────
    ip_clusters = defaultdict(list)
    for n in graph["nodes"]:
        if n["type"] == "ip_address" and n.get("entity_attributes", {}).get(
            "has_detections"
        ):
            ip = n["entity_id"]
            prefix = ".".join(ip.split(".")[:3])
            ip_clusters[prefix].append(ip)

    # Filter to clusters with 2+ IPs
    ip_clusters = {k: v for k, v in ip_clusters.items() if len(v) >= 2}

    # ── Write outputs ────────────────────────────────────────────────────
    outputs = {
        "nodes_by_type.json": dict(nodes_by_type),
        "webshell_connections.json": {
            k: dict(v) for k, v in webshell_connections.items()
        },
        "resolutions.json": resolutions,
        "detected_ips.json": detected_ips,
        "detected_domains.json": detected_domains,
        "ssl_links.json": ssl_links,
        "communicating_files.json": comm_files,
        "dga_patterns.json": {k: v for k, v in dga_patterns.items()},
        "ip_clusters.json": ip_clusters,
        "webshell_hashes.json": list(webshell_hashes),
    }

    for fname, data in outputs.items():
        path = os.path.join(OUT, fname)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"Wrote {path} ({len(json.dumps(data))} bytes)")

    # ── Summary statistics ───────────────────────────────────────────────
    print("\n=== SUMMARY ===")
    print(f"Total nodes: {len(graph['nodes'])}")
    print(f"Total links: {len(graph['links'])}")
    for ntype, nodes in sorted(nodes_by_type.items()):
        detected = sum(1 for n in nodes if n["has_detections"])
        print(f"  {ntype}: {len(nodes)} ({detected} with detections)")
    print(f"Webshell hashes: {len(webshell_hashes)}")
    print(f"Webshell hashes in graph: {len(webshell_connections)}")
    print(f"Resolution pairs: {len(resolutions)}")
    print(f"DGA pattern groups: {len(dga_patterns)}")
    print(f"IP clusters (2+): {len(ip_clusters)}")
    for prefix, ips in sorted(ip_clusters.items()):
        print(f"  {prefix}.x: {ips}")


if __name__ == "__main__":
    main()
