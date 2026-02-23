#!/usr/bin/env python3
"""Container confidentiality prototype using MK-TME key domains.

Design goal: each container receives an independent memory-encryption key domain.
Even if a compromised host process can read another container's sealed blob, it cannot
recover plaintext without the right domain key.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List

from mktme_syscalls import MKTMEController


def _keystream(key_material: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        digest = hashlib.blake2b(key_material + nonce + counter.to_bytes(8, "little")).digest()
        out.extend(digest)
        counter += 1
    return bytes(out[:length])


def seal(key_material: bytes, plaintext: bytes) -> Dict[str, str]:
    nonce = secrets.token_bytes(16)
    ks = _keystream(key_material, nonce, len(plaintext))
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, ks))
    tag = hashlib.blake2s(key_material + nonce + ciphertext).digest()
    return {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
    }


def unseal(key_material: bytes, blob: Dict[str, str]) -> bytes:
    nonce = bytes.fromhex(blob["nonce"])
    ciphertext = bytes.fromhex(blob["ciphertext"])
    tag = bytes.fromhex(blob["tag"])
    expected = hashlib.blake2s(key_material + nonce + ciphertext).digest()
    if expected != tag:
        raise ValueError("integrity check failed (wrong key domain)")
    ks = _keystream(key_material, nonce, len(ciphertext))
    return bytes(c ^ k for c, k in zip(ciphertext, ks))


@dataclass
class ContainerResult:
    container_id: str
    keyid: int
    attack_success: bool


class ContainerDomain:
    def __init__(self, container_id: str, ctrl: MKTMEController):
        self.container_id = container_id
        self.ctrl = ctrl
        self.keyid = ctrl.allocate_key(policy=0)
        # Derivation only for prototype cryptographic envelope; in real mode this would
        # be tied to hardware keyslot semantics.
        self.key_material = hashlib.sha256(f"domain:{self.keyid}".encode()).digest()

    def close(self) -> None:
        self.ctrl.free_key(self.keyid)


def run_demo(container_count: int, output_dir: Path) -> Dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    ctrl = MKTMEController()
    domains: List[ContainerDomain] = [ContainerDomain(f"c{i}", ctrl) for i in range(container_count)]

    try:
        shared_store = {}
        for dom in domains:
            secret = f"SECRET::{dom.container_id}::{secrets.token_hex(8)}".encode()
            shared_store[dom.container_id] = seal(dom.key_material, secret)

        attacks = []
        for victim in domains:
            attacker = domains[(int(victim.container_id[1:]) + 1) % container_count]
            ok = False
            try:
                _ = unseal(attacker.key_material, shared_store[victim.container_id])
                ok = True
            except ValueError:
                ok = False
            attacks.append(ContainerResult(victim.container_id, victim.keyid, ok))

        report = {
            "timestamp": int(time.time()),
            "mode": ctrl.mode,
            "container_count": container_count,
            "attacks": [asdict(item) for item in attacks],
            "successful_attacks": sum(1 for a in attacks if a.attack_success),
        }
        (output_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report
    finally:
        for dom in domains:
            dom.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="MK-TME container isolation demo")
    parser.add_argument("--containers", type=int, default=4)
    parser.add_argument("--output", type=Path, default=Path("artifacts"))
    args = parser.parse_args()

    report = run_demo(args.containers, args.output)
    print(json.dumps(report, indent=2))
    if report["successful_attacks"] != 0:
        raise SystemExit("Demo failed: at least one cross-container decryption succeeded")


if __name__ == "__main__":
    main()
