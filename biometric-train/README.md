# biometric-train

Client-permissioned facial-recognition training loop.

**Only** images a client enrolled under a valid, unrevoked consent enter the
training set. Checkpoints store gallery IDs + embeddings, never raw pixels
by default. Consent revocation purges that client's embeddings.

## Quickstart

```bash
python3 -m train.cli enrol --client alice --hashes h1,h2,h3
python3 -m train.cli train --client alice
python3 -m train.cli status --client alice
python3 -m train.cli revoke --client alice
python3 -m unittest discover -s tests
```

## License

Apache-2.0
