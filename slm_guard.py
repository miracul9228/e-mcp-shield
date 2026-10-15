import os
import re
import json
import time
import warnings
from typing import Dict, Any, Optional

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

# 過濾 huggingface_hub 舊版相容性提示警告
warnings.filterwarnings("ignore", category=FutureWarning)


class SLMGuard:
    def __init__(
        self,
        model_id: str = "meta-llama/Meta-Llama-3-8B-Instruct",
        hf_token: Optional[str] = None,
    ):
        self.model_id = model_id
        self.hf_token = hf_token or os.environ.get("HUGGING_FACE_HUB_TOKEN", None)

        print(f"[SLMGuard] 正在初始化 4-bit 量化模型: {self.model_id} ...")
        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
        )

        self.tokenizer = AutoTokenizer.from_pretrained(
            self.model_id, token=self.hf_token
        )
        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_id,
            quantization_config=quantization_config,
            device_map=None,
            torch_dtype=torch.float16,
            token=self.hf_token,
        )

        # 永久消除 Greedy Decoding 下的 temperature / top_p 警告
        self.model.generation_config.temperature = None
        self.model.generation_config.top_p = None
        self.model.generation_config.pad_token_id = self.tokenizer.eos_token_id

        self.terminators = [
            self.tokenizer.eos_token_id,
            self.tokenizer.convert_tokens_to_ids("<|eot_id|>"),
        ]

        vram_gb = torch.cuda.memory_allocated(0) / (1024 ** 3)
        print(f"[SLMGuard] 載入完成！目前顯卡記憶體佔用: {vram_gb:.2f} GB")

    def _parse_json_safely(self, raw_text: str) -> Dict[str, Any]:
        """從模型輸出中擷取 JSON，若解析失敗則啟動 Fail-Safe 預設攔截"""
        try:
            match = re.search(r"\{.*\}", raw_text, re.DOTALL)
            if match:
                parsed = json.loads(match.group(0))
                return {
                    "safe": bool(parsed.get("safe", False)),
                    "risk_level": str(parsed.get("risk_level", "HIGH")).upper(),
                    "reason": str(parsed.get("reason", "No reason provided")),
                }
        except Exception as e:
            return {
                "safe": False,
                "risk_level": "HIGH",
                "reason": f"JSON parse error ({e}). Raw: {raw_text[:60]}",
            }

        return {
            "safe": False,
            "risk_level": "HIGH",
            "reason": f"Unstructured output blocked. Raw: {raw_text[:60]}",
        }

    def inspect_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        user_intent: str = "",
        gnn_anomaly_score: Optional[float] = None,
    ) -> Dict[str, Any]:
        """評估單次 MCP 工具調用的安全性"""
        system_prompt = (
            "你是一個專門防禦 MCP (Model Context Protocol) 工具調用的資安護欄。"
            "請分析使用者的工具調用請求，檢測是否包含系統破壞、目錄穿越(Path Traversal)、"
            "指令注入(Command Injection)、機密外洩或越權存取。"
            "請嚴格只以 JSON 格式輸出判斷結果，不要包含任何額外解釋，格式如下：\n"
            '{"safe": boolean, "risk_level": "LOW"|"MEDIUM"|"HIGH"|"CRITICAL", "reason": "簡短原因(20字內)"}'
        )

        user_content = f"Tool: {tool_name}\nArguments: {json.dumps(arguments, ensure_ascii=False)}"
        if user_intent:
            user_content = f"User Intent: {user_intent}\n" + user_content
        if gnn_anomaly_score is not None:
            user_content += f"\nGNN Structural Anomaly Score: {gnn_anomaly_score:.2f}"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ]

        input_ids = self.tokenizer.apply_chat_template(
            messages, add_generation_prompt=True, return_tensors="pt"
        ).to(self.model.device)

        start_time = time.perf_counter()
        with torch.no_grad():
            outputs = self.model.generate(
                input_ids,
                max_new_tokens=128,
                eos_token_id=self.terminators,
                pad_token_id=self.tokenizer.eos_token_id,
                do_sample=False,
            )
        latency_ms = (time.perf_counter() - start_time) * 1000.0

        response_tokens = outputs[0][input_ids.shape[-1] :]
        raw_output = self.tokenizer.decode(
            response_tokens, skip_special_tokens=True
        ).strip()

        result = self._parse_json_safely(raw_output)
        result["latency_ms"] = round(latency_ms, 2)
        result["raw_output"] = raw_output
        return result
