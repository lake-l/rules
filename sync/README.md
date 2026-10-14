# 规则同步维护

计划每天北京时间 03:17 运行，也可以在仓库 Actions → Sync upstream rules → Run workflow 手动运行。GitHub 定时任务可能延迟；公开仓库长期无活动时可能停用，需在 Actions 中重新启用。

1. `sources.json` 定义来源、固定分组与数量基准。仅抓取列出的公共规则文件；旧 ChinaCompanyIp 列表不再使用。
2. `overrides.json` 保存每组 add（补充）、remove（排除）、dropTypes（排除类型），每次同步重新应用。新增个人分流请使用个人规则文件；不要将订阅、节点密码或完整配置上传。
3. `regressions.json` 验证 Bilibili 国内/国际版、AI、国内下载、广告误拦与相似域名。上下游分类变化需检查含义后再修改测试。
4. 同步脚本拒绝空列表、网页内容、未知类型、异常网段和异常数量变化。明确不支持的 USER-AGENT / URL-REGEX 被排除；带 URL 路径的 DOMAIN 条目也被排除。规则过量删除会停止发布，不能直接提高阈值绕过检查。
5. 通过 Mihomo 1.19.32 配置校验后才提交更新。验证器下载使用固定版本和 SHA256；只提交 preset-*.yaml、snapshot.json、sync-status.json。custom-*、Stash、来源清单和修正清单不会自动重写。无内容变化不产生提交。

同步失败不会提交半套结果。已有文件继续可用，在 Actions 查看失败原因；需要回退时可恢复之前提交中的整套生成文件（包含 snapshot.json）。

`snapshot.json` 带内容版本校验，供订阅工坊远程版与完整内嵌版使用同一套规则。程序获取后需保存草稿/备份项目才能跨启动保留；内嵌配置需重新导出导入。客户端远程更新周期与仓库同步周期相互独立。

来源许可见 ../mihomo/studio-v1/SOURCES.txt 和 LICENSE-META-RULES.txt。数据经过分类、补充、排除与去重，保留对应上游许可和署名。
