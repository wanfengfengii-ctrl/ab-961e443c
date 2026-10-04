# sbom-license-gate

受控软件进入隔离生产网前的 **SBOM 许可证合规评估服务**。调用方提交根组件、组件清单
（以 `bomRef` 唯一标识，最多 200 个）、依赖引用、SPDX 许可证表达式与许可证政策，服务
对**根组件可达闭包**内的全部组件（含传递依赖）作出合规 / 拒绝裁决。

纯 Python 标准库实现，零第三方依赖，镜像构建无需网络。

## 快速开始

```bash
# 构建并启动服务（宿主机端口可通过 HOST_PORT 配置，默认 8080）
HOST_PORT=8080 docker compose up --build app

# 健康检查
curl http://localhost:8080/health
```

### 一键验证（verify 一次性服务）

`verify` 服务等待 `app` 健康检查后，依次执行：单元测试 → 构建校验
（字节码编译 + 进程内评估自检）→ 合规与拒绝场景的 API 冒烟，汇总为单一退出码后自行退出：

```bash
docker compose run --rm verify        # 退出码即验证结果（0 = 全部通过）
# 或
docker compose up verify --exit-code-from verify --abort-on-container-exit
docker compose down
```

本地（无 Docker）等价流程：

```bash
python3 -m unittest discover -s tests -t . -v   # 单元测试
PORT=8000 python3 -m app.server &               # 启动服务
APP_URL=http://127.0.0.1:8000 sh scripts/verify.sh
```

## API

### `GET /health`

返回 `200 {"status": "ok"}`，供 Docker 健康检查与编排探针使用。

### `POST /api/sboms/evaluate`

**请求体**

```json
{
  "root": "pkg:app",
  "components": [
    {"bomRef": "pkg:app", "licenses": [{"expression": "MIT"}]},
    {"bomRef": "pkg:lib", "licenses": [{"expression": "GPL-3.0-only OR Apache-2.0"}]},
    {"bomRef": "pkg:bad", "licenses": [{"expression": "GPL-3.0-only"}]}
  ],
  "dependencies": [
    {"ref": "pkg:app", "dependsOn": ["pkg:lib", "pkg:bad"]}
  ],
  "policy": {
    "allowedLicenses": ["MIT", "Apache-2.0"],
    "deniedLicenses": ["GPL-3.0-only"],
    "allowedExceptions": [
      {"license": "GPL-2.0-only", "exception": "Classpath-exception-2.0"}
    ]
  }
}
```

| 字段 | 说明 |
| --- | --- |
| `root` | 根组件的 `bomRef`（必填，必须存在于 `components`） |
| `components` | 组件数组（必填，≤ 200），`bomRef` 唯一；`licenses[]` 支持 `{"expression": "..."}`、`{"license": {"id": "..."}}` 或纯字符串 |
| `dependencies` | 依赖边（可选）：`ref` 依赖 `dependsOn[]` 中的 `bomRef` |
| `policy.allowedLicenses` | 允许许可证列表（大小写不敏感） |
| `policy.deniedLicenses` | 拒绝许可证列表，**优先于允许列表** |
| `policy.allowedExceptions` | 明确允许的 `{license, exception}` 组合（`WITH` 必须命中才合规） |

**裁决语义**

- 仅覆盖从 `root` 经依赖引用可达的闭包；不可达组件不影响裁决；依赖环只遍历一次，不产生重复结果。
- 表达式支持标识符、括号、`AND`、`OR`、`WITH` 与 `+` 后缀；`AND` 优先于 `OR`。
- `AND` 各项均须合规；`OR` 至少一支合规；组件的多个 `licenses[]` 条目之间为析取（任选其一）。
- 许可证项合规条件：未被拒绝 **且** 在允许列表中 **且**（如带 `WITH`）`(license, exception)` 组合被政策明确允许。
- 结果确定：组件按 `bomRef` 排序输出；见证取满足政策的最小组合（项数最少，其次字典序），**输入顺序变化不改变裁决**。

**合规响应（200）** —— 稳定列出每个可达组件采用的许可证见证：

```json
{
  "status": "compliant",
  "root": "pkg:app",
  "summary": {"reachableComponents": 2, "compliantComponents": 2, "violations": 0},
  "components": [
    {"bomRef": "pkg:app", "witness": "MIT", "expressions": ["MIT"]},
    {"bomRef": "pkg:lib", "witness": "Apache-2.0", "expressions": ["GPL-3.0-only OR Apache-2.0"]}
  ],
  "violations": []
}
```

**拒绝响应（200）** —— 指出无法满足政策的组件及原因（`components` 仍列出合规项的见证）：

```json
{
  "status": "non_compliant",
  "summary": {"reachableComponents": 3, "compliantComponents": 2, "violations": 1},
  "components": ["..."],
  "violations": [
    {
      "bomRef": "pkg:bad",
      "expressions": ["GPL-3.0-only"],
      "reasons": [{"code": "LICENSE_DENIED", "message": "license 'GPL-3.0-only' is denied by policy"}]
    }
  ]
}
```

原因码：`LICENSE_DENIED`（被拒绝）、`LICENSE_NOT_ALLOWED`（不在允许列表）、
`EXCEPTION_NOT_ALLOWED`（`WITH` 组合未被政策允许）、`NO_LICENSE`（未声明许可证）。

**校验失败（400）** —— 缺失引用、表达式错误与非法例外按字段返回：

```json
{
  "status": "invalid",
  "errors": [
    {"field": "root", "code": "MISSING_REFERENCE", "message": "root references unknown bomRef 'ghost'"},
    {"field": "components[0].licenses[0].expression", "code": "EXPRESSION_PARSE_ERROR", "message": "expected ')' at position 8"},
    {"field": "components[1].licenses[0].expression", "code": "INVALID_EXCEPTION", "message": "unknown exception 'Foo' at position 9"},
    {"field": "dependencies[0].dependsOn[1]", "code": "MISSING_REFERENCE", "message": "unknown bomRef 'pkg:x'"}
  ]
}
```

校验错误码：`REQUIRED`、`INVALID_TYPE`、`INVALID_VALUE`、`DUPLICATE_BOM_REF`、
`TOO_MANY_COMPONENTS`（> 200）、`MISSING_REFERENCE`、`EXPRESSION_PARSE_ERROR`、
`INVALID_EXCEPTION`（`WITH` 后缺失或非 SPDX 已知例外）。非法 JSON 返回
`INVALID_JSON`；未知路径 `404`，方法错误 `405`。

## 配置

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `HOST_PORT` | `8080` | 宿主机映射端口（compose） |
| `PORT` | `8000` | 容器内服务监听端口 |
| `APP_URL` | `http://app:8000` | verify / 冒烟脚本的目标地址 |

## 项目结构

```
app/
  spdx_expr.py        SPDX 表达式词法/语法分析（AND/OR/WITH/括号/+）
  spdx_exceptions.py  SPDX 例外标识符快照（用于非法例外校验）
  evaluate.py         字段校验、可达闭包、政策裁决与见证选择
  server.py           HTTP API（/health、/api/sboms/evaluate）
tests/                单元测试（解析、语义、API）
scripts/
  smoke.py            合规/拒绝/确定性/校验冒烟
  verify.sh           一次性验证入口（退出码汇总）
Dockerfile            零依赖镜像（非 root 运行，内置 HEALTHCHECK）
docker-compose.yml    app（健康检查、可配端口）+ verify（一次性）
```
