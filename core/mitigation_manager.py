# core/mitigation_manager.py
import asyncio
import time
import logging
from collections import deque

import config
# <--- REMOVED: GeoIPManager is no longer needed. --->
# from .geoip_manager import GeoIPManager

logger = logging.getLogger("ddos-preventer")

class TokenBucket:
    """Implements rate limiting for each IP address."""
    def __init__(self, rate, capacity):
        self.rate = float(rate)
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.last = time.time()

    def consume(self, amount=1.0):
        """Tries to consume a token from the bucket. Returns True if successful."""
        now = time.time()
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False

class MitigationManager:
    """
    Centrally manages the DDoS mitigation logic for all incoming connections.
    This version implements per-IP rate limiting, connection limiting, and blacklisting.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(MitigationManager, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_initialized'): return
        self._initialized = True
        
        logger.info("MitigationManager starting (Per-IP mode only)...")
        self.rate = int(config.DEFAULT_RATE)
        self.burst = int(config.DEFAULT_BURST)
        self.conn_limit = int(config.DEFAULT_CONN_LIMIT)
        self.block_sec = int(config.DEFAULT_BLOCK_SEC)
        
        self.buckets, self.locks, self.conns = {}, {}, {}
        self.blacklist, self.whitelist, self.recent = {}, set(), {}
        
        # <--- REMOVED: All attributes related to Geo-blocking are gone. --->
        self.metrics = {"total":0,"allowed":0,"blocked":0,"blacklisted":0}

    def _now(self): return time.time()
    def _get_lock(self, ip): return self.locks.setdefault(ip, asyncio.Lock())
    def _get_recent(self, ip): return self.recent.setdefault(ip, deque(maxlen=1000))

    def is_blocked(self, ip):
        if ip in self.whitelist: return False
        ts = self.blacklist.get(ip)
        return bool(ts and ts > self._now())

    async def clear_expired_entries(self):
        now = self._now()
        expired_ips = [ip for ip, ts in self.blacklist.items() if ts <= now]
        for ip in expired_ips: self.blacklist.pop(ip, None)
        
        # <--- REMOVED: Logic for clearing expired country blocks. --->
        
        if expired_ips:
            logger.info(f"{len(expired_ips)} IP bans have been lifted.")

    # <--- REMOVED: The entire handle_geo_blocking method is gone. --->

    async def check_and_mitigate(self, ip):
        self.metrics["total"] += 1
        if self.is_blocked(ip):
            self.metrics["blocked"] += 1
            return False, "IP blacklisted"
        
        # <--- REMOVED: The call to handle_geo_blocking is gone. --->

        async with self._get_lock(ip):
            tb = self.buckets.get(ip) or TokenBucket(self.rate, self.burst)
            self.buckets[ip] = tb
            r = self._get_recent(ip); r.append(self._now())
            if not tb.consume():
                if len([t for t in r if self._now() - t < 10]) > self.burst:
                    logger.warning(f"IP blacklisted (rate limit burst): {ip}")
                    self.blacklist[ip] = self._now() + self.block_sec
                    self.metrics["blacklisted"] = len(self.blacklist)
                self.metrics["blocked"] += 1
                return False, "Rate limit exceeded"
        self.metrics["allowed"] += 1
        return True, "Allowed"
    
    async def increment_connection(self, ip):
        async with self._get_lock(ip):
            self.conns[ip] = self.conns.get(ip, 0) + 1
            if self.conns[ip] > self.conn_limit:
                logger.warning(f"IP blacklisted (connection limit): {ip}")
                self.blacklist[ip] = self._now() + self.block_sec
                self.metrics["blocked"] += 1
                return False
        return True
        
    async def decrement_connection(self, ip):
        async with self._get_lock(ip):
            self.conns[ip] = max(0, self.conns.get(ip, 1) - 1)

    async def run_background_tasks(self):
        while True:
            try:
                await self.clear_expired_entries()
            except Exception as e:
                logger.exception("Error in background cleanup task: %s", e)
            await asyncio.sleep(10)