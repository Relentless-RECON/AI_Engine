# SentinelFuzz Core AI Engine

SentinelFuzz Core AI Engine is a backend-oriented, API-first vulnerability scanning engine designed for authorized Dynamic Application Security Testing (DAST) workflows.

It is built as a standalone Python service so a Node.js backend can call it over HTTP with a stable JSON contract.

## Start Here

Use the backend integration guide:

- [BACKEND_ENGINEER_GUIDE.md](/f:/Hackathon/SentinelFuzz/AI_Engine/BACKEND_ENGINEER_GUIDE.md)

Key runtime files:

- [run_server.py](/f:/Hackathon/SentinelFuzz/AI_Engine/run_server.py)
- [sentinelfuzz_engine/server.py](/f:/Hackathon/SentinelFuzz/AI_Engine/sentinelfuzz_engine/server.py)
- [examples/node_client.js](/f:/Hackathon/SentinelFuzz/AI_Engine/examples/node_client.js)
- [.env.example](/f:/Hackathon/SentinelFuzz/AI_Engine/.env.example)
