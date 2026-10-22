"""
Deterministic Cisco ACL Evaluation Engine.
Evaluates IPv4 packets against Cisco Standard and Extended Access-Lists with
sequence ordering, wildcard bitmask calculations, protocol matching, and implicit deny.
"""

import ipaddress
from typing import Optional, Tuple, Dict, Any
from app.models.canonical import ACL, ACLRule


def ip_matches_wildcard(test_ip_str: str, base_ip_str: str, wildcard_str: str) -> bool:
    """Checks if test_ip satisfies (base_ip with wildcard mask)."""
    try:
        test_int = int(ipaddress.IPv4Address(test_ip_str))
        base_int = int(ipaddress.IPv4Address(base_ip_str))
        wild_int = int(ipaddress.IPv4Address(wildcard_str))
        mask_int = 0xFFFFFFFF ^ wild_int
        return (test_int & mask_int) == (base_int & mask_int)
    except Exception:
        return False


class ACLEvaluationResult:
    def __init__(
        self,
        permitted: bool,
        action: str,
        matched_rule: Optional[ACLRule] = None,
        is_implicit_deny: bool = False,
        explanation: str = ""
    ):
        self.permitted = permitted
        self.action = action
        self.matched_rule = matched_rule
        self.is_implicit_deny = is_implicit_deny
        self.explanation = explanation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "permitted": self.permitted,
            "action": self.action,
            "matched_rule_seq": self.matched_rule.sequence if self.matched_rule else None,
            "matched_rule_text": self.matched_rule.raw_text if self.matched_rule else None,
            "is_implicit_deny": self.is_implicit_deny,
            "explanation": self.explanation
        }


class ACLEngine:
    @staticmethod
    def evaluate(
        acl: ACL,
        src_ip: str,
        dst_ip: str,
        protocol: str = "ip",
        dst_port: Optional[int] = None
    ) -> ACLEvaluationResult:
        """
        Evaluates an IPv4 packet against the rules of an ACL in sequential order.
        Returns the first matching rule decision or implicit deny.
        """
        proto_lower = protocol.lower()

        for rule in acl.rules:
            # 1. Protocol check
            if rule.protocol != "ip" and rule.protocol.lower() != proto_lower:
                continue

            # 2. Source IP check
            if not ip_matches_wildcard(src_ip, rule.src_ip, rule.src_wildcard):
                continue

            # 3. Destination IP check
            if not ip_matches_wildcard(dst_ip, rule.dst_ip, rule.dst_wildcard):
                continue

            # 4. Destination Port check (if applicable)
            if dst_port is not None and rule.dst_port_op:
                if rule.dst_port_op == 'eq':
                    if dst_port not in rule.dst_ports:
                        continue
                elif rule.dst_port_op == 'range' and len(rule.dst_ports) >= 2:
                    p_min, p_max = min(rule.dst_ports), max(rule.dst_ports)
                    if not (p_min <= dst_port <= p_max):
                        continue

            # Matched rule!
            permitted = (rule.action == "PERMIT")
            return ACLEvaluationResult(
                permitted=permitted,
                action=rule.action,
                matched_rule=rule,
                is_implicit_deny=False,
                explanation=f"Traffic {rule.action.lower()}ted by rule {rule.sequence}: '{rule.raw_text}'"
            )

        # Implicit Deny if no rule matched
        return ACLEvaluationResult(
            permitted=False,
            action="DENY",
            matched_rule=None,
            is_implicit_deny=True,
            explanation="Traffic dropped by Cisco implicit deny (no matching ACL rules evaluated)."
        )
