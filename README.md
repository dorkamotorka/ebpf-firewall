# ebpf-firewall

A tiny **XDP/eBPF firewall** that drops incoming packets when the **source IPv4** matches a **blocked CIDR range** (e.g. `192.168.178.0/24`).

It uses a `BPF_MAP_TYPE_LPM_TRIE` map so you can block **entire IP ranges** efficiently via longest-prefix matching. :contentReference[oaicite:0]{index=0}

Learn more about it through the Interactive Lab: https://labs.iximiuz.com/tutorials/ebpf-firewall-ed03d648
