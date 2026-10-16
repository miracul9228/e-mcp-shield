import json
from typing import Dict, Any, List

class EMCPShieldRouter:
    """
    對應階段五 (5.1 & 5.3)：純模型驅動的雙閾值動態路由器與因果子圖打包器[cite: 5]
    """
    def __init__(self, theta_low: float = 0.3, theta_high: float = 0.75):
        self.theta_low = theta_low
        self.theta_high = theta_high

    def pack_causal_subgraph_context(self, current_packet: Dict[str, Any], history_packets: List[Dict[str, Any]]) -> str:
        """
        階段 5.1：因果子圖上下文打包器 (Causal Subgraph Context Packer)[cite: 5]
        往前追溯歷史軌跡，找出可疑的上游污染源與描述，打包給 SLM。
        """
        context_str = "[Causal Subgraph Context]\n"
        if len(history_packets) > 0:
            context_str += "Previous suspected operations:\n"
            # 簡化版：提取前序步驟的工具名稱與回傳結果長度作為上下文
            for pkt in history_packets[-2:]:  
                context_str += f"- Step {pkt.get('step_id')}: Tool [{pkt.get('tool_name')}] returned {len(str(pkt.get('result', '')))} chars.\n"
        else:
            context_str += "No previous operations.\n"
            
        context_str += f"\n[Current Target]\nTool: {current_packet.get('tool_name')}\nParams: {json.dumps(current_packet.get('params'))}\n"
        return context_str

    def route_packet(self, gnn_score: float, current_packet: Dict[str, Any], history_packets: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        階段 5.3：雙閾值動態路由[cite: 5]
        """
        history_packets = history_packets or []
        
        if gnn_score < self.theta_low:
            return {
                "decision": "Pass",
                "zone": "Green",
                "reason": f"GNN Score {gnn_score:.4f} < {self.theta_low}. Safe operation.",
                "latency_penalty": "1ms"
            }
        elif gnn_score >= self.theta_high:
            return {
                "decision": "Block",
                "zone": "Red",
                "reason": f"GNN Score {gnn_score:.4f} >= {self.theta_high}. High-risk topology blocked instantly.",
                "latency_penalty": "2ms"
            }
        else:
            # 進入 Gray Zone，喚醒 SLM (這裡以模擬方式呈現)
            context = self.pack_causal_subgraph_context(current_packet, history_packets)
            # 這裡假裝呼叫了本地端 Llama-3-8B 進行推論
            slm_decision = "Block" if "CANARY" in str(current_packet.get("params")) else "Pass"
            
            return {
                "decision": slm_decision,
                "zone": "Gray",
                "reason": f"GNN Score {gnn_score:.4f} triggered SLM Deep Adjudication.",
                "context_passed_to_slm": context,
                "latency_penalty": "850ms"
            }

if __name__ == "__main__":
    router = EMCPShieldRouter(theta_low=0.3, theta_high=0.75)
    
    # 測試 Green Zone (正常低風險)
    res_green = router.route_packet(0.12, {"tool_name": "read_file", "params": {"path": "readme.md"}})
    print("[Router Test - Green Zone]:", res_green["decision"], "-", res_green["reason"])
    
    # 測試 Red Zone (高風險圖拓樸)
    res_red = router.route_packet(0.88, {"tool_name": "http_post_request", "params": {"url": "evil.com"}})
    print("[Router Test - Red Zone]:", res_red["decision"], "-", res_red["reason"])
    
    # 測試 Gray Zone (模糊地帶，喚醒 SLM 並打包上下文)
    res_gray = router.route_packet(0.45, {"tool_name": "write_file", "params": {"path": "test.txt", "content": "CANARY"}})
    print("[Router Test - Gray Zone]:", res_gray["decision"], "-", res_gray["reason"])
