# API Security Test Scaffold

This directory contains an explicit, authorization-required API test harness scaffold.
It does not pretend to prove IDOR/BOLA automatically.

Set:
- SECURITY_API_BASE_URL
- SECURITY_API_AUTH_HEADER
- SECURITY_API_USER_ID
- SECURITY_API_OTHER_USER_ID

Then adapt `negative-tests.py` to the application's OpenAPI contract and identity model.
Use only staging/ephemeral targets.
