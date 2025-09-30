BUILDVH=../../tools/build_vendorheader
BINCTL=../../tools/headertool.py

# construct all vendor headers
# 构建所有供应商头
for fn in *.json; do
    name=$(echo $fn | sed 's/vendor_\(.*\)\.json/\1/')                                  # 提取文件名中的名称部分
    $BUILDVH vendor_${name}.json vendor_${name}.toif vendorheader_${name}_unsigned.bin  # 生成未签名的供应商头
done

# sign dev vendor header
cp -a vendorheader_unsafe_unsigned.bin vendorheader_unsafe_signed_dev.bin
$BINCTL -D vendorheader_unsafe_signed_dev.bin

# # 修改为处理现有的 JSON 文件
# $BUILDVH vendor_onekey_test.json vendor_onekey_test.toif vendorheader_onekey_test_unsigned.bin

# # 签名 dev vendor header
# cp -a vendorheader_onekey_test_unsigned.bin vendorheader_onekey_test_signed_dev.bin
# $BINCTL -D vendorheader_onekey_test_signed_dev.bin
