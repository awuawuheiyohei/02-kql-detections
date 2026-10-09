# KQL Detection Rules（Microsoft Sentinel 风格检测规则集）

> **一句话**：20+ 条 KQL 检测规则，覆盖 Microsoft Sentinel / Log Analytics 数据模型 + MITRE ATT&CK 战术映射 + 误报调优说明
> **面试用途**：可直接展示给招聘方 —— 证明检测工程能力 + 告警调优思路，而不是"装过 Sentinel"
> **说明**：这些是**规则设计与调优实践**，不是 Azure 生产部署（见下方"诚实声明"）

---

## ⚠️ 诚实声明

**这个项目是什么**：
- ✅ KQL 查询逻辑设计
- ✅ MITRE ATT&CK 战术映射
- ✅ 误报来源分析与调优建议
- ✅ 多数据源关联分析（SigninLogs / AuditLogs / OfficeActivity / CloudAppEvents）

**这个项目不是什么**：
- ❌ 不是 Azure 生产部署
- ❌ 没有真实的 Sentinel 工作区
- ❌ 没有真实数据源（`data/` 里是**手工构造的合成样本**，用于验证查询语法）

**面试时怎么说**：
> "这是我在自学 Sentinel 时写的检测规则集。我没有生产环境的 Sentinel 经验，但我把数据模型、ATT&CK 映射和误报调优都系统过了一遍 —— 这是我理解检测工程的方式：先想清楚攻击者会做什么，再设计查询，最后假设分析师会看到什么噪声。"

这个回答比"我部署过 Sentinel"可信得多，而且展示的是**思考能力**而非工具经验。

---

## 检测规则清单（6 个核心 + 示例 6 个）

### 🔴 高优先级（Tier 1 - 直接威胁）

| 规则 ID | 名称 | ATT&CK 战术 | 数据源 |
|---|---|---|---|
| KQL-001 | Suspicious Sign-In Pattern（不可能旅行）| TA0006 Credential Access | SigninLogs |
| KQL-002 | Privileged Account 异常角色授予 | TA0005 Privilege Escalation | AuditLogs |
| KQL-003 | Mass Device Authentication Failure | TA0006 Credential Access | SigninLogs |
| KQL-006 | MFA 疲劳攻击检测 | TA0006 Credential Access | SigninLogs |

### 🟡 中优先级（Tier 2 - 风险指标）

| 规则 ID | 名称 | ATT&CK 战术 | 数据源 |
|---|---|---|---|
| KQL-004 | Data Exfiltration 批量下载 | TA0010 Exfiltration | OfficeActivity |
| KQL-005 | Shadow IT 未授权云服务 | TA0002 Initial Access | CloudAppEvents |

---

## 规则结构模板（每条都遵循）

```kql
// 规则名称 + ID
// 战术映射
// 检测逻辑（一句话）
// 数据源
// 误报场景     ← 关键：体现你理解分析师的痛点
// 调优建议     ← 关键：体现你做过调优而不是抄规则
let TimeWindow = 4h;
let Threshold = ...;
// 查询逻辑
| extend ...        // 特征工程
| summarize ...     // 聚合
| where ...         // 阈值过滤
| extend Severity   // 告警分级
| project ...       // 输出结构化告警
```

**为什么这么设计**：
1. **`let` 开头** —— 参数可调，不用改查询体
2. **`extend` 特征工程先行** —— 把复杂判断抽出来，可读性高
3. **`summarize` 后再 `where`** —— 先聚合再过滤，性能比逐行 where 好（Sentinel 的关键优化点）
4. **输出结构化字段**（RiskScore / AlertSeverity / RecommendedAction）—— 便于分析师 triage 和自动化响应编排

---

## 6 条规则的深度说明

### KQL-001：不可能旅行（Impossible Travel）

**检测逻辑**：同一账号 4 小时内从 3+ 个城市登录

**为什么重要**：这是**检测凭据共享**（账号泄露后转卖）最经典的信号。

**误报来源**：
- VPN 出口 IP 池（同一个用户走不同节点，看起来像"瞬移"）
- 跨国出差（真实的地理移动）
- 企业代理

**调优思路**：
```
1. 建立 ASN 级别的 VPN / 代理出口白名单
   —— 不要按 IP 白名单（变化太频繁），按 ASN
2. 对 PIM eligible 账号提升告警等级
   —— 高权限账号的异常登录价值更大
3. 引入"地理速度"计算（km/h），比"城市数"更精确
   —— 从北京到新加坡 4 小时 = 4000+ km/h，人体不可能
```

**面试可讲**：
> "Impossible travel 规则的难点不是写查询，是**降噪**。原始规则一天能出几千条告警，分析师会直接关掉。我做的第一件事是建立 ASN 白名单 —— 因为 VPN 出口 IP 每天变，按 IP 白名单维护不动。第二件事是引入地理速度而非城市数，因为'3 个城市'可能是用户用了 3 个代理节点，但'北京到新加坡 4 小时'一定是泄露。"

---

### KQL-003：批量设备认证失败（真实事故场景）

**检测逻辑**：30 分钟内 20+ 次认证失败，涉及多台设备

**为什么这条最重要**：这条规则**直接来自我在克诺尔的真实事故经验**（证书过期导致 Intune 设备批量无法认证）。

**检测逻辑的进化过程**：
```
v1（我踩的坑）：靠用户报障才知道出问题了
v2：Intune compliance dashboard 人工检查
v3（这条规则）：SigninLogs 里批量失败模式 → 自动告警
```

**根因判断逻辑**（这条规则的亮点）：
```kql
// 根据错误码组合推断根因
array_has_any(ErrorBreakdown, dynamic(["700016"])) → "Certificate Chain Issue"
array_has_any(ErrorBreakdown, dynamic(["7000222"])) → "Expired Token / Certificate"
```
然后给出**对应的处置建议** —— 不是只报"出问题了"，而是"这批错误码指向证书链，建议检查 CRL 分发点可达性"。

**面试可讲**：
> "这条规则是我自己事故的产物。2025 年我们遇到过一批设备突然全部无法认证，我当时的处理是逐个看日志。现在我会先写这条规则 —— 30 分钟内 20+ 次认证失败并且错误码集中在 700016 或 7000222，就直接告警并给出根因假设。**规则的价值不是抓攻击者，是让下一次事故在 30 分钟内被发现，而不是 4 小时后被用户报障。**"

---

### KQL-006：MFA 疲劳攻击

**检测逻辑**：1 小时内 5+ 次 MFA 失败，随后有成功登录

**为什么重要**：MFA 疲劳是**绕过 MFA 的主要手段** —— 攻击者不停推送 MFA 通知，用户被烦到直接点"是"。

**检测思路**：
```
不只检测"失败很多次"
还要检测"失败后跟着成功" —— 这才是疲劳攻击的模式
普通的密码猜测会一直失败；MFA 疲劳会逼出一次成功
```

**调优**：
- 排除已注册 MFA 的可信设备
- 关联 Device ID，攻击者不会在用户设备上操作

---

## 数据源说明

| 表名 | 内容 | 许可证 |
|---|---|---|
| `SigninLogs` | Entra ID / Azure AD 登录日志 | Entra ID P1/P2 |
| `AuditLogs` | Entra ID 审计日志（角色分配、策略变更）| Entra ID P1/P2 |
| `OfficeActivity` | Microsoft 365 审计日志 | Microsoft 365 E5 |
| `CloudAppEvents` | 云应用活动（Shadow IT 检测）| Defender for Cloud Apps |

---

## 如何验证这些查询（不需要 Azure 订阅）

我在 `scripts/` 里提供了一个**本地验证器**：

```bash
# 用合成数据验证 KQL 的聚合逻辑是否正确
python3 scripts/validate_rules.py
```

它会：
1. 加载 `data/sample-signinlogs.json`（合成数据）
2. 用 Python 实现同样的聚合逻辑
3. 输出预期的检测结果，对照 KQL 逻辑验证

**这不是完整的 KQL 引擎**，但能验证：
- 聚合维度是否正确
- 阈值设置是否合理
- 分级逻辑是否按预期工作

---

## 项目结构

```
02-kql-detections/
├── README.md                    # 本文件
├── queries/
│   ├── detection-rules.kql      # 6 条核心规则
│   └── README.md                # 规则索引表
├── data/
│   ├── sample-signinlogs.json   # 合成登录日志
│   └── sample-auditlogs.json    # 合成审计日志
├── scripts/
│   └── validate_rules.py        # 本地逻辑验证器
├── tests/
│   └── test_rules.py            # 检测逻辑单元测试
├── docs/
│   ├── detection-methodology.md  # 检测工程方法论
│   └── false-positive-analysis.md # 误报分析深度文档
└── ATTACK-MAPPING.md           # 完整 ATT&CK 覆盖表
```

---

## 下一步（如果要深入）

| 方向 | 内容 |
|---|---|
| ASIM 规则 | Microsoft Sentinel 的标准化查询格式（比裸 KQL 更可移植）|
| Sentinel SOAR Playbook | 告警 → 自动处置工作流（KQL 检测规则 + Logic App）|
| UEBA 分析 | 用户 / 实体行为分析基线 |
| 真实数据验证 | 拿到 Entra ID P2 trial 后用真实数据跑 |

---

**最后更新**：2026-10-10
**关联项目**：`02-siem-edr-detection`（Sigma 规则库 + ATT&CK 映射）
**面试话术**：见上方"诚实声明"—— 强调**检测工程思维**而非工具部署
