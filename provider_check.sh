#输入数据：
# 1. 机场提供订阅地址

# 计算过程：
# 1. 从订阅地址中提取出原始数据，并解码获得每一个节点信息
# 2. 调用proxy_ss.sh脚本，传入节点信息；proxy_ss.sh脚本会将节点信息进行解析ss://协议格式，并使用ss-local命令连接到节点，并测试连接是否成功，获得国家信息
url=$1
MARK=$2
for line in $(curl -s "$url" | base64 -d)
do
# echo  "原始数据："
# printf "%q\n" "$line "

# 取出\r 之前的数据
node="${line%%$'\r'*}"



echo  "机场节点："
printf "%q\n" "$node"


./node_check.sh $node $MARK
done