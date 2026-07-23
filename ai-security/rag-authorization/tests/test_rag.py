import unittest

from rag_authz import (
    AuthorizedRetriever,
    Document,
    DocumentStore,
    Sensitivity,
    User,
    VectorStore,
    can_access,
    classify,
    detect_overexposure,
)


def build():
    docs = DocumentStore()
    vectors = VectorStore()
    corpus = [
        Document("pub", "public handbook about company culture", owner="hr",
                 groups=set(), sensitivity=Sensitivity.PUBLIC),
        Document("eng", "engineering onboarding and build guide", owner="eng",
                 groups={"eng"}, sensitivity=Sensitivity.INTERNAL),
        Document("fin", "quarterly financial results and revenue forecast", owner="cfo",
                 groups={"finance"}, sensitivity=Sensitivity.CONFIDENTIAL),
        Document("secret", "layoff plan restricted to executives SSN 123-45-6789", owner="ceo",
                 groups={"exec"}, sensitivity=Sensitivity.RESTRICTED),
    ]
    for d in corpus:
        docs.add(d)
        vectors.add(d.id, d.text)
    return docs, vectors


class AclTests(unittest.TestCase):
    def test_clearance_and_groups(self):
        docs, _ = build()
        eng = User("alice", groups={"eng"}, clearance=Sensitivity.CONFIDENTIAL)
        self.assertTrue(can_access(eng, docs.get("pub")))
        self.assertTrue(can_access(eng, docs.get("eng")))
        self.assertFalse(can_access(eng, docs.get("fin")))   # no finance group
        self.assertFalse(can_access(eng, docs.get("secret")))  # clearance too low

    def test_owner_and_public(self):
        docs, _ = build()
        low = User("bob", groups=set(), clearance=Sensitivity.PUBLIC)
        self.assertTrue(can_access(low, docs.get("pub")))
        self.assertFalse(can_access(low, docs.get("eng")))
        cfo = User("cfo", groups=set(), clearance=Sensitivity.CONFIDENTIAL)
        self.assertTrue(can_access(cfo, docs.get("fin")))  # owner


class ClassifyTests(unittest.TestCase):
    def test_classification_levels(self):
        self.assertEqual(classify("hello world")[0], Sensitivity.PUBLIC)
        self.assertEqual(classify("contact a@b.com")[0], Sensitivity.INTERNAL)
        self.assertEqual(classify("ssn 123-45-6789")[0], Sensitivity.CONFIDENTIAL)
        self.assertEqual(classify("-----BEGIN PRIVATE KEY-----")[0], Sensitivity.RESTRICTED)


class RetrievalTests(unittest.TestCase):
    def test_filtering_enforces_acl(self):
        docs, vectors = build()
        retriever = AuthorizedRetriever(docs, vectors)
        eng = User("alice", groups={"eng"}, clearance=Sensitivity.CONFIDENTIAL)
        res = retriever.retrieve(eng, "financial results revenue", k=4)
        ids = [doc_id for doc_id, _ in res.results]
        self.assertNotIn("fin", ids)     # not in finance group
        self.assertNotIn("secret", ids)  # clearance too low
        self.assertGreater(res.denied, 0)
        self.assertTrue(retriever.audit.verify())

    def test_finance_user_sees_finance(self):
        docs, vectors = build()
        retriever = AuthorizedRetriever(docs, vectors)
        fin = User("carol", groups={"finance"}, clearance=Sensitivity.CONFIDENTIAL)
        res = retriever.retrieve(fin, "financial results revenue", k=4)
        ids = [doc_id for doc_id, _ in res.results]
        self.assertIn("fin", ids)


class OverexposureTests(unittest.TestCase):
    def test_detects_mislabel_and_broad_access(self):
        docs = DocumentStore()
        # Labeled PUBLIC but contains an SSN -> sensitive_but_public + under_classified.
        docs.add(Document("leak", "employee ssn 123-45-6789 list", owner="hr",
                          groups=set(), sensitivity=Sensitivity.PUBLIC))
        users = [User(f"u{i}", groups={"all"}, clearance=Sensitivity.RESTRICTED) for i in range(5)]
        issues = detect_overexposure(docs, users, broad_threshold=3)
        kinds = {i["issue"] for i in issues}
        self.assertIn("sensitive_but_public", kinds)
        self.assertIn("under_classified", kinds)


if __name__ == "__main__":
    unittest.main()
