# Running the Demo

```text
python main.py
```

## Expected output (approx):

```text
=== Initialising stores and KDC ===

=== AS exchange (obtain TGT) ===
Client obtained TGT and session_key_c_tgs

=== TGS exchange (obtain service ticket) ===
Client obtained service ticket and session_key_c_s

=== Service exchange (access service) ===
[Service fileserver] Accepted request from 'alice' at ts=...
Service accepted request: True

```
## Running the Tests
This project includes a small but meaningful test suite using Python’s built-in `unittest` framework.

```text
python -m unittest discover -s basic_kerberos/tests -v
```

Tests included:

-   `test_full_flow_success`
- `test_unknown_user_rejected`
- `test_unknown_service_rejected`
- `test_ticket_for_wrong_service_fails`

All tests should pass.
