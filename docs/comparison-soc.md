# Vendor Comparison — SOC

!!! warning "Not a drop-in replacement — yet"
    `open-soar` is a **self-contained MVP** with mock/in-memory backends,
    tagged **v0.1-scaffold**, and is not part of the spine-proven subset.
    See the [maturity legend](comparison.md#maturity-legend).

| Component | Maturity | Comparable vendors / OSS | What it replaces for you |
|---|---|---|---|
| `open-soar` | 🟥 Scaffold (v0.1-scaffold) | **Commercial:** Splunk SOAR (Phantom), Palo Alto Cortex XSOAR, Tines, D3 Security, IBM QRadar SOAR. **OSS:** Shuffle, TheHive + Cortex, n8n, StackStorm | A SOAR license (XSOAR/Tines-class pricing) for core IR automation: playbook DAG engine with parallel branches and dependency ordering, case management, enrichment, response actions, AI-assisted triage, and a hash-chained audit trail — self-hosted with zero runtime npm dependencies. Unlike Shuffle/TheHive it ships no large connector marketplace; connectors are the missing piece before it replaces anything real. |
