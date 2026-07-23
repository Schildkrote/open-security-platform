# Intentionally vulnerable AI training targets.
# FOR LOCAL TRAINING/AUTHORIZED TESTING ONLY. Never expose publicly.
FROM python:3.12-slim

WORKDIR /app
COPY range_apps ./range_apps
COPY server.py ./server.py

# Range apps bind to 127.0.0.1 inside the container; expose for linked testing.
EXPOSE 8091 8092 8093 8094 8095

CMD ["python", "server.py", "all"]
