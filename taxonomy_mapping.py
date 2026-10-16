from typing import Dict, List, Any

class MCPAttackTaxonomyMapping:
    """
    對應階段零 (0.1)：建立 MCPXKIT 28 種攻擊之「協定層特徵映射表」
    明確界定 Protocol Observability（協定層可觀測性）
    """
    
    TAXONOMY_CATEGORIES = {
        "Metadata_Registration_Phase": {
            "description": "發生於 tools/list 階段，伺服器註冊與描述階段的攻擊 (共 6 種)",
            "attacks": [
                "Tool poison attack",
                "Shadowing attack",
                "Malicious tool competition",
                "Tool preference manipulation",
                "Functional obfuscation",
                "Rug pull attack"
            ]
        },
        "Runtime_Execution_Phase": {
            "description": "發生於 tools/call 與 resources/read 階段的動態跨步與協同攻擊 (共 16 種)",
            "attacks": [
                "Multi-tool cooperation",
                "Infectious attack",
                "Webpage poison",
                "MCP tool returned information poisoning",
                "Remote Code Execution (RCE)",
                "Command Injection",
                "Token theft and account takeover",
                "Prompt leakage",
                "Goal hijack",
                "Jailbreak",
                "Hallucination",
                "Backdoor attack",
                "Malicious modification",
                "Remote listen attack",
                "Malicious tool enforcement attack",
                "Malicious project installment"
            ]
        },
        "Host_OS_Out_Of_Scope": {
            "description": "屬於系統底層越權或安裝期問題，需配合維度二 (System State) 或屬於協定外範圍 (共 6 種)",
            "attacks": [
                "Privilege escalation",
                "Sandbox escape",
                "Installer spoofing",
                "Data injection on server",
                "Server code leakage",
                "Malicious tool generation attack"
            ]
        }
    }

    @classmethod
    def get_observability_tier(cls, attack_name: str) -> str:
        for tier, info in cls.TAXONOMY_CATEGORIES.items():
            if attack_name in info["attacks"]:
                return tier
        return "Unknown"

if __name__ == "__main__":
    print("[Taxonomy Mapping] 成功載入 MCPXKIT 28 種攻擊協定層映射表！")
    for tier, info in MCPAttackTaxonomyMapping.TAXONOMY_CATEGORIES.items():
        print(f" - {tier}: 包含 {len(info['attacks'])} 種攻擊")
