#!/usr/bin/env python3
import click

from trezorlib import cosi, firmware
from trezorlib._internal import firmware_headers

from typing import List, Tuple


try:
    import Pyro4

    Pyro4.config.SERIALIZER = "marshal"
except ImportError:
    Pyro4 = None

PORT = 5001

# =========================== signing =========================


def sign_with_privkeys(digest: bytes, privkeys: List[bytes]) -> bytes:
    """
    使用私钥列表对摘要进行签名。

    :param digest: 要签名的摘要
    :param privkeys: 用于签名的私钥列表
    :raises click.ClickException: 如果签名失败
    :return: 生成的签名
    """
    print('privkeys:', [sk.hex() for sk in privkeys])
    pubkeys = [cosi.pubkey_from_privkey(sk) for sk in privkeys] # 从私钥生成公钥
    print('pubkeys:', [pk.hex() for pk in pubkeys])
    nonces = [cosi.get_nonce(sk, digest, i) for i, sk in enumerate(privkeys)] # 为每个私钥生成随机数

    global_pk = cosi.combine_keys(pubkeys) # 组合公钥
    global_R = cosi.combine_keys(R for r, R in nonces) # 组合随机数

    # 计算部分签名
    sigs = [
        cosi.sign_with_privkey(digest, sk, global_pk, r, global_R)
        for sk, (r, R) in zip(privkeys, nonces)
    ]

    # 计算全局签名
    signature = cosi.combine_sig(global_R, sigs)
    try:
        cosi.verify_combined(signature, digest, global_pk) # 验证签名
    except Exception as e:
        raise click.ClickException("Failed to produce valid signature.") from e

    return signature # 返回生成的签名


def parse_privkey_args(privkey_data: List[str]) -> Tuple[int, List[bytes]]:
    """
    解析私钥参数。

    :param privkey_data: 私钥参数列表
    :raises click.ClickException: 如果无法解析私钥
    :return: 一个包含签名掩码和私钥列表的元组
    """
    privkeys = [] # 私钥列表
    sigmask = 0 # 签名掩码
    for key in privkey_data: # 解析每个私钥参数
        try:
            idx, key_hex = key.split(":", maxsplit=1) # 分割索引和十六进制私钥
            privkeys.append(bytes.fromhex(key_hex)) # 将十六进制私钥转换为字节并添加到列表中
            sigmask |= 1 << (int(idx) - 1) # 更新签名掩码
        except ValueError:
            click.echo(f"Could not parse key: {key}")
            click.echo("Keys must be in the format: <key index>:<hex-encoded key>")
            raise click.ClickException("Unrecognized key format.")
    return sigmask, privkeys    # 返回签名掩码和私钥列表


def process_remote_signers(fw, addrs: List[str]) -> Tuple[int, List[bytes]]:
    """
    远程签名

    :param fw: 固件对象
    :param addrs: 远程签名者地址列表
    :raises click.ClickException: 如果签名者数量不足
    :raises click.ClickException: 如果无法连接到签名者
    :return: 签名掩码和签名列表
    """
    if len(addrs) < fw.sigs_required:
        raise click.ClickException(
            f"Not enough signers (need at least {fw.sigs_required})"
        )

    digest = fw.digest()
    name = fw.NAME

    def mkproxy(addr):
        return Pyro4.Proxy(f"PYRO:keyctl@{addr}:{PORT}")

    sigmask = 0
    pks, Rs = [], []
    for addr in addrs:
        click.echo(f"Connecting to {addr}...")
        with mkproxy(addr) as proxy:
            pk, R = proxy.get_commit(name, digest)
        if pk not in fw.public_keys:
            raise click.ClickException(
                f"Signer at {addr} commits with unknown public key {pk.hex()}"
            )
        idx = fw.public_keys.index(pk)
        click.echo(
            f"Signer at {addr} commits with public key #{idx + 1}: {pk.hex()}"
        )
        sigmask |= 1 << idx
        pks.append(pk)
        Rs.append(R)

    # compute global commit
    global_pk = cosi.combine_keys(pks)
    global_R = cosi.combine_keys(Rs)

    # collect signatures
    sigs = []
    for addr in addrs:
        click.echo(f"Waiting for {addr} to sign... ", nl=False)
        with mkproxy(addr) as proxy:
            sig = proxy.get_signature(name, digest, global_R, global_pk)
        sigs.append(sig)
        click.echo("OK")

    for addr in addrs:
        with mkproxy(addr) as proxy:
            proxy.finish()

    # compute global signature
    return sigmask, cosi.combine_sig(global_R, sigs)


# ===================== CLI actions =========================


def do_replace_vendorheader(fw, vh_file) -> None:
    """
    替换固件的供应商头

    :param fw: 固件对象
    :type fw: firmware_headers.FirmwareImage
    :param vh_file:  供应商头文件对象
    :type vh_file: 
    :raises click.ClickException: 
    :raises click.ClickException: 
    """
    if not isinstance(fw, firmware_headers.FirmwareImage):
        raise click.ClickException("Invalid image type (must be firmware).")

    vh = firmware.VendorHeader.parse(vh_file.read())
    if vh.header_len != fw.fw.vendor_header.header_len:
        raise click.ClickException("New vendor header must have the same size.")

    fw.fw.vendor_header = vh


@click.command()
@click.option("-n", "--dry-run", is_flag=True, help="Do not save changes.") # -n参数表示不保存更改
@click.option("-h", "--rehash", is_flag=True, help="Force recalculate hashes.") # -h参数表示强制重新计算哈希值 
@click.option("-v", "--verbose", is_flag=True, help="Show verbose info about headers.") # -v参数表示显示详细的头信息
@click.option("-S","--sign-private", "privkey_data", metavar="INDEX:PRIVKEY_HEX", multiple=True, help="Private key to use for signing. Can be repeated.", ) # -S参数表示用于签名的私钥，可以重复使用
@click.option("-D", "--sign-dev-keys", is_flag=True, help="Sign with development header keys.") # -D参数表示使用开发头密钥进行签名
@click.option("-s", "--signature", "insert_signature", nargs=2, metavar="INDEX:INDEX:INDEX... SIGNATURE_HEX", help="Insert external signature.", ) # -s参数表示插入外部签名
@click.option("-V", "--replace-vendor-header", type=click.File("rb")) # -V参数表示替换供应商头
@click.option("-d", "--digest", "print_digest", is_flag=True, help="Only output header digest for signing and exit.", ) # -d参数表示仅输出头摘要以进行签名并退出
@click.option("-r", "--remote", metavar="IPADDR", multiple=True, help="IP address of remote signer. Can be repeated.",) # -r参数表示远程签名者的IP地址，可以重复使用
@click.argument("firmware_file", type=click.File("rb+"))

def cli(
    firmware_file,
    verbose,
    rehash,
    dry_run,
    privkey_data,
    sign_dev_keys,
    insert_signature,
    replace_vendor_header,
    print_digest,
    remote,
):
    """
    Manage trezor-core firmware headers.  
    管理 trezor-core 固件头部信息的工具。

    This tool supports three types of files:  
    该工具支持三类文件:
    
    - **TRZV**: raw vendor headers (原始厂商头部)  
    - **TRZB**: bootloader images (引导加载器镜像)  
    - **TRZV+TRZF**: firmware images prefixed with a vendor header (带厂商头部的固件镜像)

    Run with no options on a file to dump information about that file.  
    不带任何选项运行时，会输出文件的详细信息。

    Run with ``-d`` to print the header digest and exit.  
    使用 ``-d`` 参数打印头部摘要并退出。无论代码哈希是否已填充，该功能均可正常运行。

    Run with ``-h`` to recalculate and fill in code hashes.  
    使用 ``-h`` 参数可重新计算并填充代码哈希。

    Example: Insert an external signature  
    示例: 插入外部签名  

    .. code-block:: bash
        ./headertool.py firmware.bin -s 1:2:3 ABCDEF<...signature in hex format>
    - ``1:2:3`` 表示生成签名所使用的密钥索引 (基于 1 的索引)。  

    Example: Sign with local private keys  
    示例: 使用本地私钥进行签名  

    .. code-block:: bash
        ./headertool.py firmware.bin -S 1:ABCDEF<...hex private key> -S 2:1234<...hex private key>
    - 每个 ``-S`` 参数的格式为 ``index:privkey``，其中 ``index`` 与上述索引一致。  
    - 如果不想手动指定密钥，可以使用 ``-D`` 来替代，使用已知的开发密钥。  
    - 签名有效性在这两种情况下都 **不会被检查**。  

    Example: Sign with remote participants  
    示例: 使用远程参与者进行签名  

    .. code-block:: bash
        ./headertool.py firmware.bin -r 10.24.13.11 -r 10.24.13.190 ...
        
    - 每个参与者必须运行 `keyctl-proxy` 并配置在相同文件上。  
    - 签名者的公钥必须存在于已知签名者列表中，并会自动匹配到索引。  

    :param firmware_file: Firmware file to be processed. 要处理的固件文件。
    :param verbose: Enable verbose output. 是否启用详细输出。
    :param rehash: Recalculate and update code hashes. 是否重新计算代码哈希。
    :param dry_run: Perform a dry run without making changes. 仅执行模拟运行，不修改文件。
    :param privkey_data: Private key data for signing. 用于签名的私钥数据。
    :param sign_dev_keys: Use development keys for signing. 使用开发密钥进行签名。
    :param insert_signature: Insert an external signature. 插入外部签名。
    :param replace_vendor_header: Replace vendor header in firmware. 替换固件中的厂商头部。
    :param print_digest: Print header digest only. 仅打印头部摘要。
    :param remote: Remote participants for distributed signing. 远程签名参与者地址列表。

    :return: None
    """
    firmware_data = firmware_file.read()

    try:
        fw = firmware_headers.parse_image(firmware_data) # 解析固件文件
    except Exception as e:
        import traceback

        traceback.print_exc()
        magic = firmware_data[:4]
        raise click.ClickException(
            "Could not parse file (magic bytes: {!r})".format(magic)
        ) from e

    digest = fw.digest() # 计算摘要
    if print_digest:
        click.echo(digest.hex())
        return

    if replace_vendor_header: 
        do_replace_vendorheader(fw, replace_vendor_header)

    if rehash:
        fw.rehash()


    if sign_dev_keys: 
        # 使用开发密钥进行签名
        privkeys = fw.DEV_KEYS          # 获取开发密钥
        sigmask = fw.DEV_KEY_SIGMASK    # 获取签名掩码
    else:
        # 非开发密钥签名
        sigmask, privkeys = parse_privkey_args(privkey_data)

    signature = None

    if privkeys:
        click.echo("Signing with local private keys...", err=True)
        signature = sign_with_privkeys(digest, privkeys)

    # 插入外部签名
    if insert_signature:
        click.echo("Inserting external signature...", err=True)
        sigmask_str, signature = insert_signature # 解包插入的签名参数
        signature = bytes.fromhex(signature) # 将十六进制签名转换为字节
        sigmask = 0 # 重置签名掩码
        for bit in sigmask_str.split(":"): # 解析签名掩码字符串
            sigmask |= 1 << (int(bit) - 1)

    # 远程签名
    if remote:
        if Pyro4 is None:
            raise click.ClickException("Please install Pyro4 for remote signing.")
        click.echo(fw)
        click.echo(f"Signing with {len(remote)} remote participants.")
        sigmask, signature = process_remote_signers(fw, remote)

    # 如果有签名,则插入签名
    if signature:
        fw.rehash() # 确保哈希值是最新的
        fw.insert_signature(signature, sigmask) # 插入签名

    click.echo(fw.format(verbose))# 输出固件信息

    updated_data = fw.dump() # 导出更新后的固件数据
    if updated_data == firmware_data: # 检查是否有更改
        click.echo("No changes made", err=True)
    elif dry_run:
        click.echo("Not saving changes", err=True)
    else:
        firmware_file.seek(0) # 将文件指针移动到文件开头
        firmware_file.truncate(0) # 清空文件内容
        firmware_file.write(updated_data) # 写入更新后的固件数据


if __name__ == "__main__":
    cli()
