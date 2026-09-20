# rag-authorization

An open **RAG Authorization Engine**: enforce document-level access control
inside retrieval-augmented generation pipelines, with sensitivity labels,
automatic data classification, overexposure detection, and a tamper-evident
audit trail. Pure Python standard library (no vector DB or ML deps).

## Features (MVP)

- **Document ACLs**: owner/group/public permissions plus per-user **clearance**
  vs. document **sensitivity** (PUBLIC → RESTRICTED)
- **Authorized retrieval middleware**: filters vector search results to only
  what the requesting user may read (pre-retrieval candidate expansion +
  post-retrieval ACL filter)
- **Automatic data classification**: suggests a sensitivity level from content
  (SSNs, cards, keys, confidential keywords, emails)
- **Overexposure detection**: finds under-classified docs, sensitive-but-public
  docs, and confidential docs with too broad an audience
- **Dependency-free vector store**: hashed bag-of-words embeddings + cosine search
- **Hash-chained audit log** of every retrieval decision

## Quickstart

```bash
python3 examples/demo.py
```

```python
from rag_authz import (Sensitivity, User, Document, DocumentStore,
                       VectorStore, AuthorizedRetriever, detect_overexposure)

docs, vectors = DocumentStore(), VectorStore()
docs.add(Document("fin", "revenue forecast", owner="cfo", groups={"finance"},
                  sensitivity=Sensitivity.CONFIDENTIAL))
vectors.add("fin", "revenue forecast")

retriever = AuthorizedRetriever(docs, vectors)
user = User("alice", groups={"eng"}, clearance=Sensitivity.CONFIDENTIAL)
result = retriever.retrieve(user, "revenue forecast")
print(result.results, result.denied_ids)  # 'fin' is denied for alice
```

## Tests

```bash
python3 -m unittest discover -s tests
```

## License

AGPL-3.0-only
