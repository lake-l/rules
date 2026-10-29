# 订阅工坊 Mihomo 规则

用于订阅工坊 1.3.0 及更新版本的固定分组规则。

每个 YAML 文件均为 behavior: classical / format: yaml 的 payload；匹配出口与顺序由主配置中的 RULE-SET 决定。

客户端默认每 360 分钟直连下载规则。仓库通过 GitHub Actions 每天北京时间 03:17 计划同步上游（可能延迟），校验通过后自动提交；失败保留原版本。可在 Actions → Sync upstream rules → Run workflow 手动同步。

内置分类：

- 局域网：[preset-0.yaml](preset-0.yaml)
- 广告与跟踪拦截：[preset-1.yaml](preset-1.yaml)
- B站国际版：[preset-biliintl.yaml](preset-biliintl.yaml)
- 国内服务与下载：[preset-cn-services.yaml](preset-cn-services.yaml)
- AI 服务：[preset-2.yaml](preset-2.yaml)
- YouTube：[preset-3.yaml](preset-3.yaml)
- Netflix：[preset-4.yaml](preset-4.yaml)
- Disney+：[preset-5.yaml](preset-5.yaml)
- Telegram：[preset-6.yaml](preset-6.yaml)
- 社交平台：[preset-7.yaml](preset-7.yaml)
- OneDrive：[preset-8.yaml](preset-8.yaml)
- 开发工具：[preset-9.yaml](preset-9.yaml)
- 游戏平台：[preset-10.yaml](preset-10.yaml)
- 其他海外媒体：[preset-11.yaml](preset-11.yaml)
- Google 服务：[preset-12.yaml](preset-12.yaml)
- Microsoft 服务：[preset-13.yaml](preset-13.yaml)
- Apple 服务：[preset-14.yaml](preset-14.yaml)
- 国内网站：[preset-15.yaml](preset-15.yaml)
- 国内 IP 兜底：[preset-cn-ip.yaml](preset-cn-ip.yaml)

个人/订阅规则可选择“全部规则”，导出规则包后只上传新增 custom- 文件。此类文件名标识导出时内容，保持旧文件可避免旧配置链接失效；编辑已引用文件可以让客户端定期获取修改。

修改与许可：规则经过分类、去重。MetaCubeX 数据的 GPLv3 许可见 LICENSE-META-RULES.txt；ZJU-Rule 衍生部分遵循 CC-BY-SA 4.0：https://creativecommons.org/licenses/by-sa/4.0/ 。各上游的许可与署名继续适用。

自动同步的来源、修正和使用方法见 [维护说明](../../docs/rule-maintenance-guide.txt)。`snapshot.json` 是两种导出共用的完整规则快照；订阅工坊 1.4.0 可用“获取最新规则”更新。请维护 `sync/overrides.json`，直接修改生成的 preset 文件会被后续同步覆盖；custom-* 文件不受同步影响。


2026-10-20：已修正 B站直播漏项、上海迪士尼业务分类、123云盘备用入口和 Windows Update 端点，移除已确认的业务/推送整域误拦。最终国内 IP 兜底可解析未命中的域名。全部修正在同步输入中持久保存并经过回归检查；程序内置快照同步更新至1.5.0。请重新生成配置以应用机场 CIDR 的国内网段排除，客户端已导入的远程规则可手动刷新，旧连接需重建。
