# engine/results_to_html.py
import json, sys, html, datetime

IN = "scan_results.json"
OUT = "scan_report.html"


def load(path=IN):
    with open(path, "r") as f:
        return json.load(f)


def host_color(port_count):
    if port_count == 0:
        return "#c8e6c9"   # green-ish
    if port_count <= 2:
        return "#fff9c4"   # yellow-ish
    return "#ffcdd2"       # red-ish


def build_html(results):
    # Summary stats
    total_hosts = len(results)
    total_ports = sum(len(services) for services in results.values())
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_parts = [
        "<!doctype html><html><head><meta charset='utf-8'><title>Sentinel Scan Report</title>",
        "<style>",
        "body{font-family:Arial, sans-serif; padding:16px; background:#f4f6f8;}",
        "h1{color:#2c3e50;}",
        ".summary{background:#ffffff;padding:12px;margin-bottom:20px;border-radius:10px;box-shadow:0 2px 4px rgba(0,0,0,0.1);}",
        ".host{background:#ffffff;border-radius:10px;padding:16px;margin:12px 0;box-shadow:0 2px 4px rgba(0,0,0,0.1);}",
        ".host h3{margin:0 0 10px 0;}",
        "table{width:100%;border-collapse:collapse;margin-top:10px;}",
        "th,td{border:1px solid #ddd;padding:8px;text-align:left;font-size:14px;}",
        "th{background:#2c3e50;color:white;}",
        ".open{color:green;font-weight:bold;}",
        ".closed{color:red;}",
        ".timestamp{font-size:13px;color:#666;}",
        "</style>",
        "</head><body>",
        "<h1>Sentinel — Scan Report</h1>",
        f"<div class='summary'><p><strong>Total Hosts:</strong> {total_hosts}</p>",
        f"<p><strong>Total Open Ports:</strong> {total_ports}</p>",
        f"<p class='timestamp'>Generated: {timestamp}</p></div>",
    ]

    if not results:
        html_parts.append("<p><em>No hosts found.</em></p>")

    for host, services in sorted(results.items()):
        count = len(services)
        color = host_color(count)
        html_parts.append(f"<div class='host' style='border-left:10px solid {color}'>")
        html_parts.append(f"<h3>{host} — {count} open port(s)</h3>")
        if count:
            html_parts.append("<table>")
            html_parts.append("<tr><th>Port</th><th>Status</th><th>Banner</th></tr>")
            for s in services:
                banner = html.escape(s.get('banner') or '')
                html_parts.append(
                    f"<tr><td>{s.get('port')}</td>"
                    f"<td class='open'>Open</td>"
                    f"<td>{banner}</td></tr>"
                )
            html_parts.append("</table>")
        html_parts.append("</div>")
    html_parts.append("</body></html>")
    return "\n".join(html_parts)


def main():
    try:
        results = load()
    except FileNotFoundError:
        print("scan_results.json not found; run the scanner first.")
        return
    out = build_html(results)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(out)
    print(f"Wrote report to {OUT} — open it with your browser (e.g. code {OUT} or xdg-open {OUT})")


if __name__ == "__main__":
    main()
