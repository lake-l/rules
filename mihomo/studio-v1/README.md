# 订阅工坊 Mihomo 规则

用于订阅工坊 1.3.0 的固定分组规则。

每个 YAML 文件均为 behavior: classical / format: yaml 的 payload；匹配出口与顺序由主配置中的 RULE-SET 决定。

默认每360 分钟由 Mihomo 直连更新，Git 仓库不会自动抓取上游；只有这里的文件被更新后，客户端才会收到新规则。

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
