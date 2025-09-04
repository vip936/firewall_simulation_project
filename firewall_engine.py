from enum import Enum
from datetime import datetime
import ipaddress

class Action(Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"

class Protocol(Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"

class Packet:
    def __init__(self, src_ip, dest_ip, src_port, dest_port, protocol):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_port = src_port
        self.dest_port = dest_port
        self.protocol = protocol
        self.timestamp = datetime.now()

    def __str__(self):
        return f"Packet(src={self.src_ip}:{self.src_port}, dest={self.dest_ip}:{self.dest_port}, proto={self.protocol}, time={self.timestamp.strftime('%H:%M:%S')})"

class FirewallRule:
    def __init__(self, rule_name, action, src_ip=None, dest_ip=None, src_port=None, dest_port=None, protocol=None):
        self.rule_name = rule_name
        self.action = action
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_port = src_port
        self.dest_port = dest_port
        self.protocol = protocol

    def matches(self, packet):
        if self.src_ip and packet.src_ip != self.src_ip:
            return False
        if self.dest_ip and packet.dest_ip != self.dest_ip:
            return False
        if self.src_port and packet.src_port != self.src_port:
            return False
        if self.dest_port and packet.dest_port != self.dest_port:
            return False
        if self.protocol and packet.protocol != self.protocol:
            return False
        return True

class Firewall:
    def __init__(self):
        self.rules = []
        self.allowed_packets = []
        self.blocked_packets = []

    def add_rule(self, rule):
        self.rules.append(rule)

    def remove_rule(self, rule_name):
        self.rules = [r for r in self.rules if r.rule_name != rule_name]

    def process_packet(self, packet):
        for rule in self.rules:
            if rule.matches(packet):
                if rule.action == Action.ALLOW:
                    self.allowed_packets.append(packet)
                    return Action.ALLOW, rule.rule_name
                elif rule.action == Action.BLOCK:
                    self.blocked_packets.append(packet)
                    return Action.BLOCK, rule.rule_name
        # Default allow if no rule matches
        self.allowed_packets.append(packet)
        return Action.ALLOW, "Default"

    def get_statistics(self):
        return {
            'total_packets': len(self.allowed_packets) + len(self.blocked_packets),
            'allowed_packets': len(self.allowed_packets),
            'blocked_packets': len(self.blocked_packets),
            'total_rules': len(self.rules)
        }
