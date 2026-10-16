import torch
import torch.nn.functional as F
from torch_geometric.nn import GATv2Conv
from torch_geometric.data import Data, DataLoader
from typing import List

class TemporalHeteroGNNGuard(torch.nn.Module):
    """
    對應階段四 (4.1 & 4.2)：支援邊特徵的異質圖注意力網路[cite: 5]
    使用 GATv2Conv 納入時間差與跨伺服器污點資料流特徵。
    """
    def __init__(self, in_channels: int = 5, hidden_channels: int = 16, edge_dim: int = 2):
        super(TemporalHeteroGNNGuard, self).__init__()
        # 使用 GATv2Conv，並指定 edge_dim 來處理時間差與污點重疊度[cite: 5]
        self.conv1 = GATv2Conv(in_channels, hidden_channels, edge_dim=edge_dim, add_self_loops=False)
        self.conv2 = GATv2Conv(hidden_channels, hidden_channels, edge_dim=edge_dim, add_self_loops=False)
        
        # 分類層
        self.classifier = torch.nn.Linear(hidden_channels, 1)

    def forward(self, x, edge_index, edge_attr, batch):
        # 第一層 GAT
        x = self.conv1(x, edge_index, edge_attr)
        x = F.leaky_relu(x)
        x = F.dropout(x, p=0.2, training=self.training)
        
        # 第二層 GAT
        x = self.conv2(x, edge_index, edge_attr)
        x = F.leaky_relu(x)
        
        # 全局池化 (取得整個 Session 的圖級別表示)
        from torch_geometric.nn import global_mean_pool
        x_graph = global_mean_pool(x, batch)
        
        # 輸出層與 Temperature Scaling (此處以 Sigmoid 簡化實現機率校準)[cite: 5]
        out = self.classifier(x_graph)
        return torch.sigmoid(out)

    def predict_score(self, data: Data) -> float:
        """推論單一圖的風險分數 (0.0 ~ 1.0)"""
        self.eval()
        with torch.no_grad():
            batch = torch.zeros(data.x.size(0), dtype=torch.long)
            score = self.forward(data.x, data.edge_index, data.edge_attr, batch)
            return score.item()

if __name__ == "__main__":
    # 建立一個模擬的假資料來測試模型初始化與 Forward Pass
    dummy_x = torch.rand((3, 5))
    dummy_edge_index = torch.tensor([[0, 1], [1, 2]], dtype=torch.long)
    dummy_edge_attr = torch.rand((2, 2))
    dummy_batch = torch.zeros(3, dtype=torch.long)
    
    model = TemporalHeteroGNNGuard()
    out_prob = model(dummy_x, dummy_edge_index, dummy_edge_attr, dummy_batch)
    
    print("[GNN Guard] 成功初始化 TemporalHeteroGNNGuard 模型！")
    print(f"[GNN Guard] 測試 Forward Pass 輸出風險機率: {out_prob.item():.4f}")
