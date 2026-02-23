#!/usr/bin/env python3
"""MK-TME syscall bridge with automatic mock fallback.

This module isolates all raw syscall interactions so experiments can run on:
1. A patched kernel exposing MK-TME syscalls (real mode), or
2. A stock kernel for reproducible paper artifacts (mock mode).
"""
from __future__ import annotations

import ctypes
import os
import random
from dataclasses import dataclass
from typing import Dict, Optional


class SyscallError(RuntimeError):
    """Raised when a configured syscall returns an error."""


@dataclass
class KernelConfig:
    alloc_key_nr: Optional[int]
    protect_range_nr: Optional[int]
    free_key_nr: Optional[int]

    @property
    def enabled(self) -> bool:
        return None not in (self.alloc_key_nr, self.protect_range_nr, self.free_key_nr)


class MKTMEController:
    """Thin MK-TME key management facade.

    Environment variables:
    - MKTME_SYSCALL_ALLOC_KEY
    - MKTME_SYSCALL_PROTECT_RANGE
    - MKTME_SYSCALL_FREE_KEY

    If any variable is missing, controller enters mock mode.
    """

    def __init__(self) -> None:
        self.libc = ctypes.CDLL("libc.so.6", use_errno=True)
        self.config = KernelConfig(
            alloc_key_nr=self._read_nr("MKTME_SYSCALL_ALLOC_KEY"),
            protect_range_nr=self._read_nr("MKTME_SYSCALL_PROTECT_RANGE"),
            free_key_nr=self._read_nr("MKTME_SYSCALL_FREE_KEY"),
        )
        self.mode = "real" if self.config.enabled else "mock"
        self.mock_allocations: Dict[int, str] = {}

    @staticmethod
    def _read_nr(env_name: str) -> Optional[int]:
        value = os.getenv(env_name)
        if value is None or value == "":
            return None
        return int(value)

    def _syscall(self, nr: int, *args: int) -> int:
        rc = self.libc.syscall(ctypes.c_long(nr), *[ctypes.c_ulong(a) for a in args])
        if rc < 0:
            err = ctypes.get_errno()
            raise SyscallError(f"syscall(nr={nr}, args={args}) failed: errno={err}")
        return int(rc)

    def allocate_key(self, policy: int = 0) -> int:
        if self.mode == "real":
            assert self.config.alloc_key_nr is not None
            return self._syscall(self.config.alloc_key_nr, policy)

        # Mock: reserve a random non-zero keyid.
        while True:
            keyid = random.randint(1, 4095)
            if keyid not in self.mock_allocations:
                self.mock_allocations[keyid] = "allocated"
                return keyid

    def protect_range(self, start_addr: int, length: int, keyid: int) -> int:
        if self.mode == "real":
            assert self.config.protect_range_nr is not None
            return self._syscall(self.config.protect_range_nr, start_addr, length, keyid)

        if keyid not in self.mock_allocations:
            raise SyscallError(f"mock protect_range: keyid {keyid} not allocated")
        return 0

    def free_key(self, keyid: int) -> int:
        if self.mode == "real":
            assert self.config.free_key_nr is not None
            return self._syscall(self.config.free_key_nr, keyid)

        self.mock_allocations.pop(keyid, None)
        return 0
