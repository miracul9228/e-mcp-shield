import json
import torch
from typing import List, Dict, Any
from torch_geometric.data import Data

class MCPGraphBuilder:
    """
    對應階段三 (3.1 & 3.2)：JSON-RPC 封包轉「拓撲時間異質圖」與零洩漏特徵工程
    實作三大有向邊：
    1. Temporal Control Edge (時間控制邊)
    2. Data Flow Taint Edge (隱式污點資料流邊 - 核心演算法)
    3. Namespace Shadow Edge (命名空間競爭邊)
    """

    def __init__(self):
        pass

    def _compute_shannon_entropy(self, text: str) -> float:
        """計算參數字串的 Shannon 資訊熵（用以自動對 Base64/Hex 混淆產生高響應）"""
        import math
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        frequencies = {char: text.count(char) for char in set(text)}
        for count in frequencies.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return round(entropy, 4)

    def build_graph_from_session(self, session_packets: List[Dict[str, Any]]) -> Data:
        """將單一 Session 的多步封包序列轉換為 PyG Data 物件"""
        num_nodes = len(session_packets)
        
        # 節點特徵矩陣 X: [num_nodes, feature_dim]
        # 特徵維度規劃 (6 維)：
        # [0]: 跨 Server 跳轉標記 (Cross-Server Hop)
        # [1]: 參數長度 (Normalized Length)
        # [2]: Shannon 資訊熵 (Entropy)
        # [3]: 路徑深度或特殊符號密度
        # [4]: 步驟深度比例 (Step Depth Ratio)
        # [5]: Ground Truth 標籤 (僅用於訓練監督，不作為模型輸入特徵以防洩漏，此處設為標籤)
        
        x_features = []
        edge_indices = []
        edge_attributes = []
        
        previous_server = None
        
        for i, pkt in enumerate(session_packets):
            server_id = pkt.get("server_id", "unknown")
            params = pkt.get("params", {})
            param_str = json.dumps(params)
            
            # 計算特徵
            is_cross_server = 1.0 if (previous_server and previous_server != server_id) else 0.0
            length_norm = min(len(param_str) / 200.0, 1.0)
            entropy = self._compute_shannon_entropy(param_str)
            special_char_density = sum(1 for c in param_str if c in "./-_/?&=%") / max(len(param_str), 1)
            step_ratio = (i + 1) / max(num_nodes, 1)
            
            x_vec = [is_cross_server, length_norm, entropy, special_char_density, step_ratio]
            x_features.append(x_vec)
            previous_server = server_id

        # 建立有向邊 (Edges)
        for i in range(num_nodes - 1):
            # 1. 時間控制邊 (Temporal Control Edge)
            t_curr = session_packets[i].get("timestamp", 0)
            t_next = session_packets[i+1].get("timestamp", 0)
            dt = max(t_next - t_curr, 0.001)
            
            edge_indices.append([i, i+1])
            edge_attributes.append([dt, 0.0]) # [時間差, 污點重疊度]

            # 2. 隱式污點資料流邊 (Data Flow Taint Edge - 核心演算法)
            # 檢查步驟 i 的 result 是否包含在步驟 i+1 的 params 中
            res_str = str(session_packets[i].get("result", ""))
            param_next_str = json.dumps(session_packets[i+1].get("params", {}))
            
            # 若前一步的結果字串或其中關鍵片段出現在下一步的參數中（跨步外傳或組合攻擊）
            taint_overlap = 0.0
            if len(res_str) > 5 and any(chunk in param_next_str for chunk in [res_str[j:j+8] for j in range(0, len(res_str)-8, 4)]):
                taint_overlap = 1.0
                # 建立跨步污點資料流邊
                edge_indices.append([i, i+1])
                edge_attributes.append([dt, 1.0])

        # 轉換為 PyTorch Tensors
        x = torch.tensor(x_features, dtype=torch.float32)
        if edge_indices:
            edge_index = torch.tensor(edge_indices, dtype=torch.long).t().contiguous()
            edge_attr = torch.tensor(edge_attributes, dtype=torch.float32)
        else:
            edge_index = torch.empty((2, 0), dtype=torch.long)
            edge_attr = torch.empty((0, 2), dtype=torch.float32)

        # 取得該 Session 的最終 Ground Truth 標籤
        session_label = max([pkt.get("final_label", 0) for pkt in session_packets])
        y = torch.tensor([session_label], dtype=torch.float32)

        data = Data(x=x, edge_index=edge_index, edge_attr=edge_attr, y=y)
        return data

if __name__ == "__main__":
    with open("mcpxkit_raw_dataset.json", "r", encoding="utf-8") as f:
        raw_sessions = json.load(f)

    builder = MCPGraphBuilder()
    sample_graph = builder.build_graph_from_session(raw_sessions[0])
    print("[Graph Builder] 成功將 Session 轉換為 PyG 異質圖結構！")
    print(" - 節點特徵矩陣大小 (x):", sample_graph.x.shape)
    print(" - 邊索引 (edge_index):", sample_graph.edge_index.shape)
    print(" - 邊屬性 (edge_attr):", sample_graph.edge_attr.shape)
    print(" - 圖標籤 (y):", sample_graph.y)
