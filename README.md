# proxyCheck

用于解析订阅节点并做可用性检测的脚本集合。
- 仅适用SS节点机场
- 仅检测chatGPT能否可用
- 机场订阅检测：provide_check.sh 机场订阅 AAA （AAA字符串是节点标识结果的前缀）

**macOS 额外工具**
以下工具在 macOS 上需要自行安装（脚本会用到）：
- `ss-local`（来自 `shadowsocks-libev` 或 `shadowsocks-rust`）
- `jq`
- `python3`

macOS 自带无需安装：
- `curl`
- `nc`
- `base64`
- `awk`
