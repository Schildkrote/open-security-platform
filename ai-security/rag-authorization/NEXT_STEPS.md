# Next Steps — rag-authorization

## Real retrieval backends
- Adapters for real vector DBs (pgvector, Qdrant, Weaviate, Pinecone) using
  **metadata filtering** so ACLs are enforced *inside* the query, not just after.
- Use real **embeddings** (sentence-transformers) instead of hashed BoW.
- **Pre-retrieval authorization**: push group/clearance filters into the query
  plan to avoid leaking the existence of restricted docs.

## Classification & labeling
- NER/ML classifiers for PII and sensitive data; integrate with a DLP engine.
- **Auto-labeling** on ingest and label drift detection over time.
- Sensitivity inheritance from source systems (SharePoint, Drive, Confluence).

## Governance
- **Access reviews** and entitlement analytics for the RAG corpus.
- **RAG poisoning detection** (malicious docs manipulating retrieval) — pair
  with `mcp-security-gateway` poisoning signals.
- Attribute-based access control (ABAC) and purpose-based restrictions.

## Integration
- Middleware for LangChain/LlamaIndex retrievers.
- Require an `agent-identity` token so agents retrieve with the user's ACLs.
- Emit overexposure findings to `ai-compliance-hub` and `open-soar`.

## Platform
- HTTP API, Postgres backend, incremental indexing, multi-tenant workspaces.
