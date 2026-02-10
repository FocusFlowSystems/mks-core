"""
MENDELSOHN KERNEL STANDARD (MKS) v2.0
Reference Implementation: SPR_Native
Author: Focus Flow Systems

OBJECTIVE:
A normative architecture for building reliable, auditable Multi-Agent Systems.
It redefines AI agents not as tools, but as institutional actors (Kernels)
subject to a strict 'Culture Stack' of Axioms and Logic Gates.
"""

import datetime
import uuid
import enum
import json
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

# ==========================================
# 1.0 PROTOCOL LAYER (Data Structures)
# ==========================================

class MsgType(enum.Enum):
    WORKER_OUTPUT = "WORKER_OUTPUT"
    AUDIT_REPORT = "AUDIT_REPORT"
    ROUTER_PLAN = "ROUTER_PLAN"
    VETO_SIGNAL = "VETO_SIGNAL"

class Verdict(enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNCERTAIN = "UNCERTAIN"

@dataclass
class MKS_Message:
    """
    3.1 MKS_MESSAGE_SCHEMA
    Strict envelope for Kernel communication. No unstructured chat.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    sender_kernel_id: str = "UNKNOWN"
    target_kernel_id: str = "BROADCAST"
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    msg_type: MsgType = MsgType.WORKER_OUTPUT
    gov_token: str = "SHA256_HASH_PROOF"
    
    # The Content
    payload: Dict[str, Any] = field(default_factory=dict)     # The "Data"
    logic_trace: Dict[str, Any] = field(default_factory=dict) # The "Why"
    
    # Signals for the Orchestrator
    signals: Dict[str, Any] = field(default_factory=lambda: {"confidence": "HIGH", "flags": []})

    def to_json(self):
        return json.dumps(self.__dict__, default=str, indent=2)

@dataclass
class Gate:
    """
    2.1 KERNEL_SPECIFICATION (Logic Circuits)
    Deterministic checks evaluated by the Orchestrator.
    """
    rule_id: str
    priority: int          # 0=Global/Supreme, 1=Domain, 2=Local
    condition_expr: str    # DSL String: "$payload.metric > 100"
    actions: List[str]     # ["FLAG(RISK)", "STOP"]

@dataclass
class AuthorityRule:
    """
    4.2 AUTHORITY_GRAPH
    Defines the Chain of Command and Veto powers.
    """
    rule_id: str
    source_kernel_id: str  # The Boss (e.g., SENIOR_PASTOR_KERNEL)
    target_kernel_id: str  # The Subordinate (e.g., RESEARCH_ASSISTANT)
    action: str            # "VETO" | "APPROVE"
    priority: int
    condition_expr: str
    response_protocol: str # "REDRAFT" | "STOP" | "ESCALATE"

@dataclass
class AuditReport:
    """
    5.2 AUDIT_REPORT_SCHEMA
    Output from the Immune System's Critic.
    """
    verdict: Verdict
    violations: List[str]
    feedback: str
    recommended_action: str

# ==========================================
# 2.0 LOGIC ENGINE (The DSL Parser)
# ==========================================

class LogicEngine:
    """
    Parses string-based DSL conditions into Python boolean evaluations.
    Safely executes conditions like "$payload.reading_grade_level > 12".
    """
    @staticmethod
    def evaluate(condition_expr: str, msg: MKS_Message) -> bool:
        # Create a safe context dictionary for evaluation
        # In production, use AST parsing for security. This is a reference mock.
        safe_context = {
            "$payload": msg.payload,
            "$signals": msg.signals,
            "TRUE": True,
            "FALSE": False
        }
        
        try:
            expr_safe = condition_expr
            
            # 1. Map Payload keys
            for key, value in msg.payload.items():
                placeholder = f"$payload.{key}"
                if placeholder in expr_safe:
                    # Handle Strings vs Numbers
                    if isinstance(value, str):
                        expr_safe = expr_safe.replace(placeholder, f"'{value}'")
                    else:
                        expr_safe = expr_safe.replace(placeholder, str(value))
            
            # 2. Map Signal keys
            for key, value in msg.signals.items():
                placeholder = f"$signals.{key}"
                if placeholder in expr_safe:
                    if isinstance(value, str):
                        expr_safe = expr_safe.replace(placeholder, f"'{value}'")
                    else:
                        expr_safe = expr_safe.replace(placeholder, str(value))

            # 3. Last resort cleanup (for boolean logic)
            expr_safe = expr_safe.replace("TRUE", "True").replace("FALSE", "False")
            
            # Evaluate
            return eval(expr_safe, {"__builtins__": {}}, {})
            
        except Exception as e:
            print(f"   [LogicEngine Error] Could not parse '{condition_expr}': {e}")
            return False

# ==========================================
# 3.0 AUTHORITY GRAPH (Conflict Resolution)
# ==========================================

class AuthorityGraph:
    def __init__(self):
        self.rules: List[AuthorityRule] = []

    def add_rule(self, rule: AuthorityRule):
        self.rules.append(rule)

    def check_permissions(self, msg: MKS_Message) -> Dict[str, str]:
        """
        Determines if a Kernel's message is allowed to proceed.
        Returns: {'status': 'ALLOWED' | 'VETOED', 'reason': str}
        """
        # 1. Filter relevant rules
        relevant = [r for r in self.rules if r.target_kernel_id == msg.sender_kernel_id or r.target_kernel_id == "ALL"]
        
        # 2. Sort by Priority (0 is Supreme)
        relevant.sort(key=lambda x: x.priority)

        for rule in relevant:
            is_triggered = LogicEngine.evaluate(rule.condition_expr, msg)
            
            if is_triggered:
                print(f"   [Authority] Rule Triggered: {rule.rule_id} by {rule.source_kernel_id}")
                if rule.action == "VETO":
                    return {'status': 'VETOED', 'reason': f"{rule.response_protocol}: {rule.rule_id}"}
                elif rule.action == "APPROVE":
                    return {'status': 'ALLOWED', 'reason': "Explicit Approval"}

        return {'status': 'ALLOWED', 'reason': "No Veto Found"}

# ==========================================
# 4.0 ORCHESTRATOR (The Runtime)
# ==========================================

class Orchestrator:
    def __init__(self):
        self.active_gates: List[Gate] = []
        self.authority_graph = AuthorityGraph()
        self.telemetry_log: List[str] = []

    def log(self, text: str):
        print(f"[Orchestrator] {text}")
        self.telemetry_log.append(text)

    def register_gate(self, gate: Gate):
        self.active_gates.append(gate)

    def process_message(self, msg: MKS_Message) -> Dict[str, Any]:
        self.log(f"Processing MSG {msg.id[:8]} from {msg.sender_kernel_id}")

        # Step 1: Governance Gates (The "Circuit Breakers")
        # Sort gates by priority (Global > Domain > Local)
        sorted_gates = sorted(self.active_gates, key=lambda g: g.priority)
        
        for gate in sorted_gates:
            if LogicEngine.evaluate(gate.condition_expr, msg):
                self.log(f"GATE TRIGGERED: {gate.rule_id} (Priority {gate.priority})")
                
                # Execute Gate Actions
                for action in gate.actions:
                    if "STOP" in action:
                        self.log("-> STOP Signal Received.")
                        return {"status": "STOP", "feedback": f"Violated Gate {gate.rule_id}"}
                    
                    if "FLAG" in action:
                        try:
                            flag = action.split("(")[1][:-1]
                            msg.signals['flags'].append(flag)
                            self.log(f"-> Flag Applied: {flag}")
                        except IndexError:
                            pass
                            
                    if "TRIGGER" in action:
                        target = action.split("(")[1][:-1]
                        self.log(f"-> Triggering Downstream: {target}")

        # Step 2: Authority Graph (The "Boss" Check)
        auth_result = self.authority_graph.check_permissions(msg)
        if auth_result['status'] == 'VETOED':
            self.log(f"AUTHORITY VETO: {auth_result['reason']}")
            return {"status": "VETO", "feedback": auth_result['reason']}

        # Step 3: Success
        self.log(f"Message Routed Successfully to {msg.target_kernel_id}")
        return {"status": "DELIVERED", "msg": msg}

# ==========================================
# 5.0 IMMUNE SYSTEM (Generator-Critic)
# ==========================================

class ImmuneSystem:
    def __init__(self, orchestrator: Orchestrator):
        self.orchestrator = orchestrator
        self.max_retries = 3

    def run_task(self, worker_mock, auditor_mock, task_context: str):
        """
        Simulates the Loop: Worker -> Auditor -> Orchestrator
        """
        feedback_history = []
        
        for attempt in range(self.max_retries):
            print(f"\n--- Cycle {attempt + 1}/{self.max_retries} ---")
            
            # 1. Worker Generates
            draft_msg = worker_mock.generate(task_context, feedback_history)
            print(f"[Worker] Draft Stats: Readability={draft_msg.payload.get('readability_grade')} | Orthodoxy={draft_msg.payload.get('orthodoxy_check')}")
            
            # 2. Auditor Critiques
            audit = auditor_mock.critique(draft_msg)
            
            # 3. Decision Tree
            if audit.verdict == Verdict.PASS:
                print(f"[Auditor] VERDICT: PASS")
                # 4. Final System Check (Orchestrator Gates)
                final_result = self.orchestrator.process_message(draft_msg)
                
                if final_result['status'] == 'DELIVERED':
                    print("\n[SUCCESS] Task Completed and Delivered.")
                    return draft_msg
                else:
                    # Orchestrator rejected it (e.g., Gate Violation)
                    feedback = final_result['feedback']
                    print(f"[REJECT] Orchestrator blocked: {feedback}")
                    feedback_history.append(feedback)
            
            else:
                # Auditor rejected it
                print(f"[Auditor] VERDICT: FAIL. Violations: {audit.violations}")
                feedback_history.append(audit.feedback)

        print("\n[FAILURE] Max Retries Exceeded. Task Aborted.")
        return None

# ==========================================
# 6.0 SIMULATION (Wind Tunnel)
# ==========================================

class MockWorkerKernel:
    def __init__(self, role):
        self.role = role
    
    def generate(self, context, feedback) -> MKS_Message:
        # SIMULATION LOGIC:
        
        # Attempt 1: Heretical Statement (Good readability, bad theology)
        payload = {"readability_grade": 8.0, "orthodoxy_check": False} 
        
        if len(feedback) == 1:
            # Attempt 2: Fixed Theology, but Too Complex (PhD level language)
            payload = {"readability_grade": 16.0, "orthodoxy_check": True}
        
        if len(feedback) >= 2:
            # Attempt 3: Fixed Theology AND Simple Language (Success)
            payload = {"readability_grade": 8.5, "orthodoxy_check": True}

        return MKS_Message(
            sender_kernel_id=self.role,
            target_kernel_id="CONTENT_CMS",
            payload=payload,
            logic_trace={"reasoning": "Synthesizing theological concepts for Sunday service."},
            signals={"confidence": "HIGH", "flags": []}
        )

class MockAuditorKernel:
    def critique(self, msg: MKS_Message) -> AuditReport:
        violations = []
        # Simulate Axiom Check: !ORTHODOXY: Must align with Statement of Faith
        if msg.payload.get("orthodoxy_check") is False:
            violations.append("AXIOM_VIOLATION: Statement conflicts with Nicene Creed")
        
        if violations:
            return AuditReport(Verdict.FAIL, violations, "Ensure doctrinal alignment.", "REDRAFT")
        return AuditReport(Verdict.PASS, [], "Theologically sound.", "NONE")

def main():
    print("==========================================")
    print("   MENDELSOHN KERNEL STANDARD (MKS) v2.0  ")
    print("   Status: Normative | Mode: Wind Tunnel  ")
    print("==========================================\n")
    
    # 1. Initialize Runtime
    system = Orchestrator()
    
    # 2. Define Culture Stack (Gates)
    # Domain Gate: Accessibility. If reading level > 12 (High School), Redraft.
    gate_accessibility = Gate(
        rule_id="ACCESSIBILITY_LIMIT",
        priority=1, # Domain Level
        condition_expr="$payload.readability_grade > 12",
        actions=["STOP(TOO_COMPLEX)"]
    )
    system.register_gate(gate_accessibility)

    # 3. Define Authority (Veto Powers)
    # Doctrinal Veto: If orthodoxy is False, STOP immediately.
    veto_doctrine = AuthorityRule(
        rule_id="DOCTRINAL_VETO",
        source_kernel_id="THEOLOGY_CORE",
        target_kernel_id="ALL",
        action="VETO",
        priority=0, # Global/Supreme
        condition_expr="$payload.orthodoxy_check == False", 
        response_protocol="STOP_AND_REDRAFT"
    )
    system.authority_graph.add_rule(veto_doctrine)

    # 4. Run Immune System Loop
    immune_sys = ImmuneSystem(system)
    worker = MockWorkerKernel("PULPIT_CO_PILOT_ALPHA")
    auditor = MockAuditorKernel()

    print("[SCENARIO] Agent attempting to write a theological essay...")
    final_result = immune_sys.run_task(worker, auditor, "Explain Trinity")

    if final_result:
        print(f"\nFINAL OUTPUT PAYLOAD: {final_result.payload}")

if __name__ == "__main__":
    main()
