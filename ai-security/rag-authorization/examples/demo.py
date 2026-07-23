"""Demo: authorized retrieval and overexposure detection."""
from rag_authz import (
    Sensitivity, User, Document, DocumentStore, VectorStore,
    AuthorizedRetriever, detect_overexposure,
)

docs = DocumentStore()
vectors = VectorStore()
corpus = [
    Document("pub", "public company handbook and culture", owner="hr", sensitivity=Sensitivity.PUBLIC),
    Document("eng", "engineering build and deploy guide", owner="eng", groups={"eng"}, sensitivity=Sensitivity.INTERNAL),
    Document("fin", "quarterly financial results and revenue", owner="cfo", groups={"finance"}, sensitivity=Sensitivity.CONFIDENTIAL),
    Document("leak", "employee ssn 123-45-6789 spreadsheet", owner="hr", sensitivity=Sensitivity.PUBLIC),
]
for d in corpus:
    docs.add(d)
    vectors.add(d.id, d.text)

retriever = AuthorizedRetriever(docs, vectors)
alice = User("alice", groups={"eng"}, clearance=Sensitivity.CONFIDENTIAL)

res = retriever.retrieve(alice, "financial results revenue", k=4)
print("alice query 'financial results revenue':")
print("  granted:", res.results)
print("  denied ids:", res.denied_ids)

users = [User(f"u{i}", groups=set(), clearance=Sensitivity.RESTRICTED) for i in range(5)]
print("\noverexposure issues:")
for issue in detect_overexposure(docs, users):
    print(" ", issue)

print("\naudit chain valid:", retriever.audit.verify())
