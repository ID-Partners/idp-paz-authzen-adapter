"""
Tiny in-memory "core banking" system for the demo.

Not persistent, not concurrent-safe beyond a process — it exists only to give the
Bank API something realistic to act on so the Ping Authorize policy decisions
(now enforced at the Kong gateway) have visible effects: accounts get created,
balances move.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Account:
    id: str
    customer_id: str
    type: str          # checking | savings | ...
    nickname: str
    currency: str
    balance: float
    status: str = "open"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Customer:
    id: str
    name: str
    email: str
    kyc_verified: bool = True
    accounts: list[str] = field(default_factory=list)


class BankStore:
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        """Restore the bank to its seeded starting state (fresh balances, only the
        two seeded accounts) — powers the demo's 'Reset demo' control."""
        self._customers: dict[str, Customer] = {}
        self._accounts: dict[str, Account] = {}
        self._acct_seq = itertools.count(1002)
        # The most recent open_account result per (customer, type). Lets open_account
        # be idempotent while the account is still empty, so a step-up retry funds the
        # SAME account the user consented to (RFC 9396 RAR pins the creditor account) —
        # otherwise each retry would open a fresh account and never match the consent.
        self._last_opened: dict[tuple[str, str], str] = {}
        self._seed()

    def _seed(self) -> None:
        # Customer id == the authenticated OIDC principal (`sub`) so the identity
        # the user logs in as IS the identity the bank authorizes — see the
        # X-Auth-Principal enforcement in app.py.
        alice = Customer(id="alice", name="Alice Ferrand",
                         email="alice@example.com", kyc_verified=True)
        self._customers[alice.id] = alice
        chk = Account(id="CHK-1001", customer_id=alice.id, type="checking",
                      nickname="Everyday Checking", currency="AUD", balance=5000.00)
        self._accounts[chk.id] = chk
        alice.accounts.append(chk.id)
        # A savings account so the demo's happy-path transfer (pay from checking
        # to savings) has a real destination and the balance visibly moves.
        sav = Account(id="SAV-1002", customer_id=alice.id, type="savings",
                      nickname="Rainy Day Savings", currency="AUD", balance=1200.00)
        self._accounts[sav.id] = sav
        alice.accounts.append(sav.id)

    # --- customers ---
    def get_customer(self, customer_id: str) -> Customer | None:
        return self._customers.get(customer_id)

    # --- accounts ---
    def list_accounts(self, customer_id: str) -> list[Account]:
        return [self._accounts[a] for a in self._customers[customer_id].accounts]

    def get_account(self, account_id: str) -> Account | None:
        return self._accounts.get(account_id)

    def open_account(self, customer_id: str, account_type: str, nickname: str,
                     currency: str = "AUD") -> Account:
        # Idempotent while empty: if the last account we opened for this
        # (customer, type) still exists and hasn't been funded yet, return it
        # instead of minting a new id. This keeps the destination account stable
        # across a step-up retry so it matches the account the user consented to
        # in the RAR. Once the account is funded (balance > 0), a subsequent
        # open_account creates a genuinely new account.
        prev_id = self._last_opened.get((customer_id, account_type))
        if prev_id:
            prev = self._accounts.get(prev_id)
            if prev is not None and prev.customer_id == customer_id and prev.balance == 0.0:
                return prev
        acct_id = f"{account_type[:3].upper()}-{next(self._acct_seq)}"
        acct = Account(id=acct_id, customer_id=customer_id, type=account_type,
                       nickname=nickname or f"{account_type.title()} Account",
                       currency=currency, balance=0.0)
        self._accounts[acct_id] = acct
        self._customers[customer_id].accounts.append(acct_id)
        self._last_opened[(customer_id, account_type)] = acct_id
        return acct

    def transfer(self, from_id: str, to_id: str, amount: float) -> None:
        src = self._accounts[from_id]
        dst = self._accounts[to_id]
        if src.balance < amount:
            raise ValueError(f"Insufficient funds in {from_id}: balance {src.balance:.2f} < {amount:.2f}")
        src.balance -= amount
        dst.balance += amount


# single process-wide store
store = BankStore()
