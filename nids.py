#!/usr/bin/env python3
import argparse
import logging
import logging.handlers
import json
import os
import socket
import sys
import threading
import time
from collections import defaultdict, deque, Counter
from datetime import datetime
from math import log2
from queue import Queue

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf, L3RawSocket

DEFAULT_CONFIG = {
    "pps_threshold": 200,
    "syn_threshold": 100,
    "udp_threshold": 300,
    "icmp_threshold": 200,
    "portscan_ports_threshold": 50,
    "portscan_window_seconds": 5,
    "sliding_window_seconds": 10,
    "window_bucket_seconds": 1,
    "blacklist_block_seconds": 300,
    "logfile": "nids_alerts.log",
    "rotate_size": 5 * 1024 * 1024,
    "rotate_count": 3,
    "signature_strings": ["malicious", "exploit", "botnet", "evil"],
    "verbose": True
}

class SimpleNIDS:
    def __init__(self, iface=None, config=None):
        self.iface = iface
        self.config = DEFAULT_CONFIG.copy()
        if config:
            self.config.update(config)
        self.lock = threading.RLock()
        self.running = False
        self.packet_queue = Queue(maxsize=10000)
        self.alert_queue = Queue()
        self.per_ip_counters = defaultdict(lambda: deque())
        self.per_ip_syn = defaultdict(lambda: deque())
        self.per_ip_udp = defaultdict(lambda: deque())
        self.per_ip_icmp = defaultdict(lambda: deque())
        self.per_ip_ports = defaultdict(lambda: deque())
        self.blacklist = {}
        self.whitelist = set()
        self.signature_hits = defaultdict(int)
        self.init_logging()
        self._ensure_root()
        self.listener_thread = None
        self.processor_thread = None
        self.alerter_thread = None
        self.housekeeper_thread = None
        self.start_time = time.time()

    def _ensure_root(self):
        if os.geteuid() != 0:
            msg = "This script requires root privileges to sniff packets. Exiting."
            print(msg)
            sys.exit(1)

    def init_logging(self):
        self.logger = logging.getLogger("SimpleNIDS")
        self.logger.setLevel(logging.DEBUG if self.config.get("verbose") else logging.INFO)
        fmt = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
        rh = logging.handlers.RotatingFileHandler(
            self.config.get("logfile"),
            maxBytes=self.config.get("rotate_size"),
            backupCount=self.config.get("rotate_count"),
        )
        rh.setFormatter(fmt)
        self.logger.addHandler(rh)
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        self.logger.addHandler(sh)

    def start(self):
        self.running = True
        self.listener_thread = threading.Thread(target=self._sniff_loop, name="Listener", daemon=True)
        self.processor_thread = threading.Thread(target=self._process_loop, name="Processor", daemon=True)
        self.alerter_thread = threading.Thread(target=self._alert_loop, name="Alerter", daemon=True)
        self.housekeeper_thread = threading.Thread(target=self._housekeeper_loop, name="Housekeeper", daemon=True)
        self.listener_thread.start()
        self.processor_thread.start()
        self.alerter_thread.start()
        self.housekeeper_thread.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        time.sleep(0.5)
        self.logger.info("Shutting down NIDS...")
        while not self.packet_queue.empty():
            try:
                self.packet_queue.get_nowait()
            except Exception:
                break

    def _sniff_loop(self):
        conf.sniff_promisc = True
        conf.recvbuf_size = 2 ** 20
        if self.iface:
            sniff(prn=self._packet_handler, store=False, iface=self.iface, stop_filter=lambda x: not self.running)
        else:
            sniff(prn=self._packet_handler, store=False, stop_filter=lambda x: not self.running)

    def _packet_handler(self, pkt):
        try:
            self.packet_queue.put_nowait(pkt)
        except Exception:
            try:
                self.packet_queue.get_nowait()
            except Exception:
                pass
            try:
                self.packet_queue.put_nowait(pkt)
            except Exception:
                pass

    def _process_loop(self):
        while True:
            if not self.running and self.packet_queue.empty():
                break
            try:
                pkt = self.packet_queue.get(timeout=1)
            except Exception:
                continue
            try:
                self._analyze_packet(pkt)
            except Exception as e:
                self.logger.debug(f"Error analyzing packet: {e}")

    def _alert_loop(self):
        while True:
            if not self.running and self.alert_queue.empty():
                break
            try:
                alert = self.alert_queue.get(timeout=1)
            except Exception:
                continue
            try:
                self._handle_alert(alert)
            except Exception as e:
                self.logger.debug(f"Error handling alert: {e}")

    def _housekeeper_loop(self):
        while True:
            if not self.running:
                break
            try:
                self._periodic_checks()
            except Exception as e:
                self.logger.debug(f"Housekeeper error: {e}")
            time.sleep(self.config.get("window_bucket_seconds", 1))

    def _periodic_checks(self):
        now = time.time()
        window = self.config.get("sliding_window_seconds", 10)
        pps_threshold = self.config.get("pps_threshold")
        syn_threshold = self.config.get("syn_threshold")
        udp_threshold = self.config.get("udp_threshold")
        icmp_threshold = self.config.get("icmp_threshold")
        portscan_threshold = self.config.get("portscan_ports_threshold")
        portscan_window = self.config.get("portscan_window_seconds")

        with self.lock:
            to_alert = []
            for ip, deq in list(self.per_ip_counters.items()):
                while deq and (now - deq[0]) > window:
                    deq.popleft()
                count = len(deq)
                if count >= pps_threshold:
                    to_alert.append(("pps", ip, count))
            for ip, deq in list(self.per_ip_syn.items()):
                while deq and (now - deq[0]) > window:
                    deq.popleft()
                count = len(deq)
                if count >= syn_threshold:
                    to_alert.append(("syn_flood", ip, count))
            for ip, deq in list(self.per_ip_udp.items()):
                while deq and (now - deq[0]) > window:
                    deq.popleft()
                count = len(deq)
                if count >= udp_threshold:
                    to_alert.append(("udp_flood", ip, count))
            for ip, deq in list(self.per_ip_icmp.items()):
                while deq and (now - deq[0]) > window:
                    deq.popleft()
                count = len(deq)
                if count >= icmp_threshold:
                    to_alert.append(("icmp_flood", ip, count))
            for ip, deq in list(self.per_ip_ports.items()):
                while deq and (now - deq[0][1]) > portscan_window:
                    deq.popleft()
                unique_ports = {p for p, t in deq}
                if len(unique_ports) >= portscan_threshold:
                    to_alert.append(("port_scan", ip, len(unique_ports)))

            for a in to_alert:
                self.alert_queue.put(a)

            for ip, expiry in list(self.blacklist.items()):
                if expiry and now >= expiry:
                    del self.blacklist[ip]
                    self.logger.info(f"Removed {ip} from blacklist after expiry")

    def _handle_alert(self, alert):
        t, ip, count = alert
        ts = datetime.utcnow().isoformat()
        message = f"{ts} ALERT {t.upper()} src={ip} count={count}"
        self.logger.warning(message)
        self._blacklist_ip(ip, reason=t)
        try:
            with open("nids_incidents.jsonl", "a") as fh:
                fh.write(json.dumps({"time": ts, "type": t, "src": ip, "count": count}) + "\n")
        except Exception:
            pass

    def _blacklist_ip(self, ip, reason=None):
        now = time.time()
        block = self.config.get("blacklist_block_seconds", 300)
        with self.lock:
            self.blacklist[ip] = now + block
        self.logger.info(f"Blacklisted {ip} for {block}s due to {reason}")

    def _analyze_packet(self, pkt):
        if not pkt:
            return
        if IP not in pkt:
            return
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        ts = time.time()
        if src in self.whitelist:
            return
        if src in self.blacklist:
            if ts < self.blacklist[src]:
                self.logger.info(f"Dropping packet from blacklisted {src}")
                return
            else:
                with self.lock:
                    del self.blacklist[src]

        with self.lock:
            self.per_ip_counters[src].append(ts)
            if TCP in pkt:
                t = pkt[TCP]
                flags = t.flags
                sport = int(t.sport)
                dport = int(t.dport)
                if flags & 0x02:
                    self.per_ip_syn[src].append(ts)
                self.per_ip_ports[src].append((dport, ts))
                if Raw in t and len(t[Raw].load) > 0:
                    payload = t[Raw].load
                    self._inspect_payload(src, payload)
                if self._tcp_anomalies(t):
                    self.alert_queue.put(("tcp_anomaly", src, 1))
            elif UDP in pkt:
                self.per_ip_udp[src].append(ts)
                udp = pkt[UDP]
                if Raw in udp and len(udp[Raw].load) > 0:
                    self._inspect_payload(src, udp[Raw].load)
            elif ICMP in pkt:
                self.per_ip_icmp[src].append(ts)
            else:
                pass

    def _inspect_payload(self, src, payload):
        try:
            if not payload:
                return
            if isinstance(payload, bytes):
                s = None
                try:
                    s = payload.decode("utf-8", errors="ignore")
                except Exception:
                    s = str(payload)
                for sig in self.config.get("signature_strings", []):
                    if sig in s:
                        self.signature_hits[src] += 1
                        self.logger.warning(f"Signature match for {src}: {sig} (hits={self.signature_hits[src]})")
                        if self.signature_hits[src] > 3:
                            self.alert_queue.put(("signature_repeat", src, self.signature_hits[src]))
            else:
                pass
            if len(payload) > 1200:
                self.alert_queue.put(("large_payload", src, len(payload)))
            ent = self._shannon_entropy(payload)
            if ent > 7.5:
                self.alert_queue.put(("high_entropy_payload", src, int(ent * 10)))
        except Exception:
            pass

    def _tcp_anomalies(self, tcp):
        flags = tcp.flags
        if flags == 0 or flags == 0xFF:
            return True
        if flags & 0x04 and flags & 0x02:
            return True
        return False

    def _shannon_entropy(self, data):
        if not data:
            return 0.0
        if isinstance(data, str):
            data = data.encode("utf-8", errors="ignore")
        if len(data) == 0:
            return 0.0
        counter = Counter(data)
        length = len(data)
        ent = 0.0
        for _, cnt in counter.items():
            p = cnt / length
            ent -= p * log2(p)
        return ent

def parse_args():
    p = argparse.ArgumentParser(prog="simple_nids.py")
    p.add_argument("-i", "--iface", help="interface to sniff", default=None)
    p.add_argument("-c", "--config", help="json config file", default=None)
    p.add_argument("--no-verbose", action="store_true", help="turn off console verbosity")
    return p.parse_args()

def load_config(path):
    try:
        with open(path, "r") as fh:
            conf = json.load(fh)
            return conf
    except Exception:
        return None

def main():
    args = parse_args()
    cfg = None
    if args.config:
        cfg = load_config(args.config)
    if args.no_verbose:
        if not cfg:
            cfg = {}
        cfg["verbose"] = False
    nids = SimpleNIDS(iface=args.iface, config=cfg)
    nids.start()

if __name__ == "__main__":
    main()
