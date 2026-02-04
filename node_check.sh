#根据订阅地址，解析出订阅节点
result=result.csv
#rm -v result.csv
TEST=1
#读取命令行参数
#echo "$1"
#
# ss:// 协议格式标注（给不熟悉协议时使用）
# 基本格式（常见的一种）：
#   ss://BASE64_ENCODED(userinfo)@host:port#tag
# 其中：
# - BASE64_ENCODED(userinfo) 里通常是 "method:password" 的 base64 编码
#   例：明文 userinfo = "aes-128-gcm:934e436f-132b-4c38-acca-c2ab1f19a3ff"
#   base64 后得到一串编码（可能需要补齐 '='）
# - host:port 是服务器域名/IP 和端口
# - #tag 是节点说明（URL 编码的文本）
#
# 示例：
# ss://YWVzLTEyOC1nY206OTM0ZTQzNmYtMTMyYi00YzM4LWFjY2EtYzJhYjFmMTlhM2Zm@sg01.etonfast.top:31013#%F0%9F%87%B8%F0%9F%87%AC%20SGD%20Gcore%20x0.5
# 解析思路：
# - protocol = "ss"
# - phrase_e = "YWVzLTEyOC1nY206OTM0ZTQzNmYtMTMyYi00YzM4LWFjY2EtYzJhYjFmMTlhM2Zm" (base64)
# - phrase   = base64 解码后得到 "method:password"
# - domain   = "sg01.etonfast.top"
# - port     = "31013"
# - description = "# 后面的 URL 编码文本"
#url='ss://YWVzLTEyOC1nY206OTM0ZTQzNmYtMTMyYi00YzM4LWFjY2EtYzJhYjFmMTlhM2Zm@sg01.etonfast.top:31013#%F0%9F%87%B8%F0%9F%87%AC%20SGD%20Gcore%20x0.5'

# vmess / trojan 协议格式标注（简要）
  #
  # vmess（V2Ray 旧格式，base64 JSON）：
  #   vmess://BASE64_ENCODED(JSON)
  # JSON 常见字段：
  #   {
  #     "v": "2",          # 版本
  #     "ps": "节点名",     # 备注
  #     "add": "host",     # 域名或IP
  #     "port": "443",     # 端口
  #     "id": "UUID",      # 用户ID
  #     "aid": "0",        # 额外ID（旧字段，常为0）
  #     "net": "ws",       # 传输方式: tcp/ws/grpc等
  #     "type": "none",    # 伪装类型
  #     "host": "example.com",   # 伪装域名(常用于ws)
  #     "path": "/path",   # ws路径
  #     "tls": "tls"       # tls/空
  #   }
  #
  # trojan（常见格式）：
  #   trojan://password@host:port?security=tls&type=tcp&sni=example.com#tag
  # 说明：
  # - password 是连接口令
  # - host:port 是服务器域名/IP 和端口
  # - 参数常见：
  #   security=tls / type=tcp|ws / sni=域名 / alpn=h2,http/1.1 / allowInsecure=0
  # - #tag 是节点说明（URL 编码文本）
  #
 # vless 协议格式标注（简要）
  #
  # vless（URL 格式，UUID 鉴权）：
  #   vless://UUID@host:port?encryption=none&security=tls&type=ws&host=example.com&path=/path#tag
  #
  # vless://cd05d0ba-afdb-41df-a185-d27579902456@0.0.0.0:443\?type=tcp\&encryption=none\&host=\&path=\&security=tls\&flow=xtls-rprx-vision\&sni=new.download.the-best-airport.com#%E6%82%A8%E6%AD%A3%E5%9C%A8%E4%BD%BF%E7%94%A8%E7%9A%84%E6%98%AF%E6%9C%80%E6%96%B0%E5%AE%A2%E6%88%B7%E7%AB%AF
  # 说明：
  # - UUID 是用户ID（必填）
  # - host:port 是服务器域名/IP 和端口
  # - 常见参数：
  #   encryption=none        # vless 通常为 none
  #   security=tls|reality|none
  #   type=tcp|ws|grpc|kcp|quic
  #   host=伪装域名          # ws/grpc 常用
  #   path=/path             # ws 路径
  #   sni=域名               # tls/reality 常用
  #   fp=chrome|firefox      # reality 指纹
  #   alpn=h2,http/1.1
  #   flow=xtls-rprx-vision  # 仅特定场景
  # - #tag 是节点说明（URL 编码文本）
  #


url=$1

#yaml节点输出，自定义标记
MARK=$2
echo ""
#协议类型
protocol=$(echo $url | awk -F'://' '{print $1}')
echo "协议类型：$protocol"

#密码
phrase_e=$(echo $url | awk -F '[//@]' '{print $3}')
#echo "密码：$phrase"

# 检查 base64 是否对齐
# base64 编码后的字符串长度必须是 4 的倍数
# 如果不是，则需要补齐 =

b64=$phrase_e
len=${#b64}


echo "len = $len"
if (( len % 4 == 0 )); then
    echo "✅ base64 已对齐"
else
    pad=$((4 - len % 4))
    echo "❌ base64 未对齐，需要补齐 $pad 个 ="

    # 补齐 base64 编码
    for (( i = 0; i < pad; i++ )); do
        b64+="="
    done
    echo "✅ 补齐后的 base64 编码：$b64"
fi

#将phrase解码
phrase=$(echo ${b64} | base64 -d)

#echo "密码：$phrase"

#根据phrase，提取出密钥和加密方法
key=$(echo $phrase | awk -F':' '{print $2}')
#echo "密钥：$key"
method=$(echo $phrase | awk -F':' '{print $1}')
#echo "加密方法：$method"

#域名
domain=$(echo $url | awk -F'@' '{print $2}' | awk -F':' '{print $1}')
#echo "域名：$domain"

#端口
port=$(echo $url | awk -F':' '{print $3}' | awk -F'#' '{print $1}')
#echo "端口：$port"

#节点说明
description=$(echo $url | awk -F'#' '{print $2}' )
#echo "节点说明：$description"

description=$(python3 -c "import urllib.parse; print(urllib.parse.unquote('$description'))")
#echo "节点说明：$description"

if TEST=1; then
echo "测试节点："
echo "协议类型：$protocol"
echo "加密前密钥：$phrase_e"
echo "密码：$phrase"
echo "密钥：$key"
echo "加密方法：$method"
echo "域名：$domain"
echo "端口：$port"
echo "节点说明：$description"
fi
#使用nc命令测试节点

#如果nc根本不能鉴别节点是否可用，可以考虑先使用ss-local开启代理，然后使用curl测试能否访问Google


echo "尝试连接"
echo "${description} ss-local -s $domain -p $port -k $key -m $method -l 1080 -v " 
echo "${description} ss-local -s $domain -p $port -k $key -m $method -l 1080 -v " >> node_link_info.txt
ss-local -s $domain -p $port -k $key -m $method -l 1080 -v > /dev/null  &
PID=$!
sleep 2



#check by curl to google

curl -x socks5h://127.0.0.1:1080 -LsS -o /dev/null \
  --connect-timeout 5 --max-time 10 \
  -w 'exit=%{exitcode} http=%{http_code}\n' \
  https://www.google.com

rc=$?
if [ $rc -eq 0 ]; then
    echo "$description 节点可用"
    google_status="Google✅"
    #使用curl获得代理服务器的IP地址
    server_ip=$(curl -s -x socks5h://127.0.0.1:1080 https://api.ip.sb/ip -A Mozilla --connect-timeout 5 --max-time 10)

    #添加状态码


    # #判断服务器是否可用策略：以能不能访问Google为准
    # curl -x socks5h://127.0.0.1:1080 -LsS -o /dev/null \
    # --connect-timeout 5 --max-time 10 \
    # -w 'exit=%{exitcode} http=%{http_code}\n' \
    # https://www.google.com


    # rc=$?
    # echo "DebugInfo: curl 返回状态码：$rc, 代理服务器IP地址：$server_ip"
    # #如果状态码不等于0，说明代理服务器可用
    # if [ $rc -ne 0 ]; then
        echo "代理服务器的IP地址：$server_ip"

        #根据IP查询地址
        server_info=$(curl -s https://api.ip.sb/geoip/{$server_ip} -A Mozilla --connect-timeout 5 --max-time 10)
        # | jq -r ".city")

        server_country=$(echo $server_info | jq -r ".country")
        server_city=$(echo $server_info | jq -r ".city")
        #google跳转地址

        # google=$(curl -x socks5h://127.0.0.1:1080 -Ls -o /dev/null -w '%{url_effective}\n' https://www.google.com --connect-timeout 5 --max-time 10) 

        echo "代理服务器地理位置：$server_country:$server_city"
        #echo "Google跳转地址：$google"
        
        # echo "按任意键退出"
        # read 

        # check openAI access

        ret=$(curl -x socks5h://127.0.0.1:1080 -LsS https://chatgpt.com --connect-timeout 5 --max-time 10
)  
        if grep "Sorry, you have been blocked" <<< "$ret" ; then
            echo "无法访问ChatGPT网站，可能被OpenAI封锁"
            chatGPT_status="chatGPT❌"
        else
            chatGPT_status="chatGPT✅"
        fi
        # #read  

        #printf "%s,%s,%s\n" $description $server_country $server_city >> $result
        echo "FinalResult==>节点$description,$google_status,Country:$server_country,City$server_city,$chatGPT_status<=="
        echo "节点$description,$google_status,Country:$server_country,City$server_city,$chatGPT_status" >> $result


    #else
        
   # fi

    

else
    echo "$description,❌,代理服务器不可用,状态码：$rc" | tee -a $result
fi

final_node_name="${MARK}${chatGPT_status}_${description}"
SS_NODE_server=$domain
SS_NODE_port=$port
SS_NODE_password=$key
SS_NODE_cipher=$method

yaml_node="\
  - name: ${final_node_name}
    type: ss
    server: ${SS_NODE_server}
    port: ${SS_NODE_port}
    cipher: ${SS_NODE_cipher}
    password: "\"${SS_NODE_password}\""
    udp: true"


#只将chatGPT可以正常访问的节点进行输出
if [ "$chatGPT_status" = "chatGPT✅" ]; then
echo "$yaml_node" | tee -a yaml_nodes.txt
fi
#关闭代理服务器
kill -9 $PID
    

#等待10秒


#关闭后台进场
