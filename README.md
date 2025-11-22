# Kerberos
A modular, educational implementation of Kerberos-style authentication in Python. Includes AS/TGS/Service flows, AES-GCM crypto, PBKDF2 key derivation, and a basic unit test suite.
# Mini Kerberos – Educational Python Implementation

This repository contains a **minimal, educational implementation of a Kerberos-style authentication protocol** in Python.

The goal of this project is **not** to provide a production-ready security system, but to demonstrate:

- How Kerberos-style authentication works (AS → TGS → Service)
- How tickets and authenticators are issued and verified
- How to structure a small security / crypto project in a **modular architecture**
- Clean use of modern Python + AES-GCM + PBKDF2

---

## Features

- 🔐 **AS / TGS / Service flow**
  - Authentication Service (AS) issues a Ticket-Granting Ticket (TGT)
  - Ticket-Granting Service (TGS) issues service tickets
  - Service validates service ticket + authenticator

- 🧩 **Modular design**
  - `core/` – crypto, models, error types
  - `infra/` – in-memory stores for users & services
  - `protocol/` – protocol logic (KDC, client, service)
  - `app/` – flows + demo wiring
  - `tests/` – basic unit tests

- 🔑 **Crypto primitives**
  - AES-GCM for authenticated encryption
  - PBKDF2-HMAC-SHA256 for password → key derivation
  - Base64 encoding for serialised keys

- ✅ **Unit tests**
  - End-to-end happy path
  - Unknown user
  - Unknown service
  - Ticket used for the wrong service

---

## Project Structure

```text
.
├─ main.py
├─ requirements.txt
└─ basic_kerberos/
   ├─ __init__.py
   │
   ├─ core/
   │  ├─ crypto.py        # AES-GCM, PBKDF2, base64, timing helpers
   │  ├─ models.py        # UserRecord, ServiceRecord, Ticket, Authenticator
   │  └─ errors.py        # KerberosError, AuthenticationError, TicketError, ...
   │
   ├─ infra/
   │  ├─ user_store.py    # InMemoryUserStore
   │  └─ service_store.py # InMemoryServiceStore
   │
   ├─ protocol/
   │  ├─ kdc_protocol.py      # AS + TGS logic
   │  ├─ client_protocol.py   # Client-side logic (no networking)
   │  └─ service_protocol.py  # Service-side logic (+ safe error mapping)
   │
   ├─ app/
   │  ├─ flows.py        # as_flow(), tgs_flow(), service_flow()
   │  └─ demo.py         # demo_flow() wiring everything together
   │
   └─ tests/
      └─ test_basic_flow.py   # basic unit tests

---
