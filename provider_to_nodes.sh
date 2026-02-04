#输入数据：
# 1. 机场提供订阅地址 $1

# 计算过程：
# 1. 从订阅地址中提取出原始数据，并解码获得每一个节点信息

url=$1
for line in $(curl -s "$url" | base64 -d)
do
# echo  "原始数据："
# printf "%q\n" "$line "

# 取出\r 之前的数据
clean_line="${line%%$'\r'*}"



#echo  "机场节点："
printf "%q\n" "$clean_line"



done