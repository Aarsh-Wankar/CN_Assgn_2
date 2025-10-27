import re
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

LOG_FILE = "dns_resolution_h1.log"

domain_re = re.compile(r"Domain:\s+([\w\.-]+)\.")
total_time_re = re.compile(r"Total Time:\s+([\d\.]+)s")
servers_re = re.compile(r"Total DNS Servers visited\s*:\s*(\d+)")
resolved_ip_re = re.compile(r"Resolved IP:\s*([\d\.]+)")
rtt_re = re.compile(r"RTT:\s*([\d\.]+)s")

records = []

with open(LOG_FILE, "r", encoding="utf-8") as f:
    block = []
    for line in f:
        line = line.strip()
        if line.startswith("----- New Query -----"):
            block = []
        elif line.startswith("----- End Query -----"):
            if block:
                text = " ".join(block)
                domain_match = domain_re.search(text)
                total_time_match = total_time_re.search(text)
                servers_match = servers_re.search(text)
                ip_match = resolved_ip_re.search(text)
                rtts = [float(x) for x in rtt_re.findall(text)]
                if domain_match and total_time_match and servers_match and ip_match:
                    avg_rtt = sum(rtts) / len(rtts) if rtts else 0.0
                    records.append({
                        "domain": domain_match.group(1),
                        "total_time_s": float(total_time_match.group(1)),
                        "dns_servers_visited": int(servers_match.group(1)),
                        "resolved_ip": ip_match.group(1),
                        "avg_rtt_s": avg_rtt
                    })
            block = []
        else:
            block.append(line)

df = pd.DataFrame(records)
if df.empty:
    print("No valid DNS resolution records found.")
    exit()

df = df.head(10)
print(df.to_string(index=False))

plt.figure(figsize=(8, 5))
plt.bar(df["domain"], df["dns_servers_visited"], color="royalblue", width=0.6)
plt.ylabel("DNS Servers Visited")
plt.title("Total DNS Servers Visited per Domain")
plt.xticks(rotation=45, ha="right")
plt.grid(axis="y", linestyle="--", alpha=0.6)
plt.yticks(range(0, int(df["dns_servers_visited"].max()) + 2))
plt.tight_layout()
plt.show()

plt.figure(figsize=(8, 5))
plt.bar(df["domain"], df["total_time_s"], color="seagreen", width=0.6)
plt.ylabel("Total Query Time (s)")
plt.title("Total DNS Query Time per Domain")
plt.xticks(rotation=45, ha="right")
plt.grid(axis="y", linestyle="--", alpha=0.6)
yticks = [round(x, 2) for x in list(np.arange(0, df["total_time_s"].max() + 0.5, 0.2))]
plt.yticks(yticks)
plt.tight_layout()
plt.show()

plt.figure(figsize=(8, 5))
plt.bar(df["domain"], df["avg_rtt_s"], color="darkorange", width=0.6)
plt.ylabel("Average RTT (s)")
plt.title("Average RTT per Domain")
plt.xticks(rotation=45, ha="right")
plt.grid(axis="y", linestyle="--", alpha=0.6)
yticks = [round(x, 3) for x in list(np.arange(0, df["avg_rtt_s"].max() + 0.05, 0.02))]
plt.yticks(yticks)
plt.tight_layout()
plt.show()

print("\nSummary Statistics:")
print(f"Average Total Query Time: {df['total_time_s'].mean():.3f} s")
print(f"Average DNS Servers Visited: {df['dns_servers_visited'].mean():.2f}")
print(f"Average RTT: {df['avg_rtt_s'].mean():.4f} s")
