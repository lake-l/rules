# 公开规则自动发布

`publish-cloudflare.yml` 将经过 Mihomo 校验的公开规则片段发给已登记的 Cloudflare Worker。main 的规则快照更新、固定直连规则更新、每日同步成功或手动运行会触发发布。

Worker origin 只保存在本仓库 Actions 的加密 Secret `CLOUDFLARE_PUBLISH_ORIGIN`，不写入公开文件或运行日志。值只能是 `https://主机.workers.dev`，不能带路径或查询参数；未设置时工作流报错并保留原订阅。禁止提交机场订阅地址、订阅访问密钥、Cloudflare API Token、完整配置或迁移模板。

工作流使用 GitHub OIDC 短期身份，无需设置 Cloudflare 管理密钥。Worker 校验签名、仓库与所有者数字 ID、main 分支、指定工作流、受众及有效期。GitHub 只收到受管理预设的标识与策略组名称；节点、机场地址、DNS、个人规则和完整配置保留在账号自己的 KV。

首次需在私有 KV 建立经过本机 Mihomo 校验的配置模板，并部署支持 OIDC 的 Worker。模板只识别完整匹配的预设块；修改过的块和个人规则固定保留，禁用块不重新加入。手动替换完整配置后需要重新绑定。

工作流失败会显示失败状态，Cloudflare 保留原订阅。旧快照、配置冲突、异常大量删规则及非规则 YAML 注入都不能覆盖当前版本。订阅下载链接和访问密钥无需更换。
