from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import hashlib
import time
import os

# ---------------------- 1. 生成 RSA 公私钥对 ----------------------
def generate_rsa_keys():
    """生成 RSA 公私钥对，保存到本地文件（方便复用）"""
    # 生成私钥（2048 位密钥长度，兼顾安全性和性能）
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # 标准公钥指数，确保安全性
        key_size=2048,
        backend=default_backend()
    )

    # 私钥保存到文件（PEM 格式，加密存储，密码可自定义，这里用 "rsa_password"）
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,  # 标准私钥格式
            encryption_algorithm=serialization.BestAvailableEncryption(b"rsa_password")  # 加密私钥
        ))

    # 从私钥提取公钥
    public_key = private_key.public_key()

    # 公钥保存到文件（PEM 格式，无需加密，可公开）
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo  # 标准公钥格式
        ))

    print("✅ RSA 公私钥对已生成：")
    print("   - 私钥：private_key.pem（需妥善保管，不可公开）")
    print("   - 公钥：public_key.pem（可公开给他人用于验证）\n")
    return private_key, public_key

# ---------------------- 2. 读取本地密钥（避免重复生成） ----------------------
def load_rsa_keys():
    """从本地文件读取公私钥（如果已生成，直接复用）"""
    if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
        return generate_rsa_keys()  # 若文件不存在，重新生成

    # 读取私钥（需输入之前设置的密码 "rsa_password"）
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=b"rsa_password",  # 与生成私钥时的密码一致
            backend=default_backend()
        )

    # 读取公钥
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

    print("✅ 已读取本地 RSA 公私钥对\n")
    return private_key, public_key

# ---------------------- 3. 计算 POW（4 个 0 开头哈希） ----------------------
def calculate_pow(nickname):
    """计算满足 4 个 0 开头哈希的 “昵称 + nonce”"""
    nonce = 0
    target_prefix = "0000"
    start_time = time.time()

    while True:
        content = f"{nickname}{nonce}"  # 拼接内容：昵称 + nonce
        sha256_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if sha256_hash.startswith(target_prefix):
            cost_time = time.time() - start_time
            print("=== POW 计算结果（4 个 0 开头哈希）===")
            print(f"花费时间：{cost_time:.2f} 秒")
            print(f"待签名内容：{content}")
            print(f"SHA256 哈希值：{sha256_hash}\n")
            return content  # 返回需签名的 “昵称 + nonce”

        nonce += 1

# ---------------------- 4. 私钥签名 ----------------------
def sign_with_private_key(private_key, content):
    """用 RSA 私钥对 “昵称 + nonce” 进行签名"""
    # 私钥签名：使用 PKCS#1 v1.5 填充（标准签名方案），结合 SHA256 哈希
    signature = private_key.sign(
        content.encode("utf-8"),  # 待签名内容（转字节流）
        padding.PKCS1v15(),  # 填充方案，确保安全性
        hashes.SHA256()  # 哈希算法，与 POW 一致
    )

    # 签名结果是字节流，转为十六进制字符串（方便查看和传输）
    signature_hex = signature.hex()
    print("=== 私钥签名结果 ===")
    print(f"签名（十六进制）：{signature_hex}\n")
    return signature  # 返回原始字节流签名（用于后续验证）

# ---------------------- 5. 公钥验证 ----------------------
def verify_with_public_key(public_key, content, signature):
    """用 RSA 公钥验证签名是否有效"""
    try:
        # 公钥验证：参数需与签名时完全一致（填充方案、哈希算法）
        public_key.verify(
            signature,  # 私钥生成的原始签名（字节流）
            content.encode("utf-8"),  # 待验证的内容（与签名内容一致）
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("=== 公钥验证结果 ===")
        print("✅ 签名验证成功！内容未被篡改，且确实由对应私钥签名")
        return True
    except Exception as e:
        print("=== 公钥验证结果 ===")
        print(f"❌ 签名验证失败：{str(e)}")
        return False

# ---------------------- 主流程执行 ----------------------
if __name__ == "__main__":
    # 替换为你的昵称（与之前 POW 一致）
    MY_NICKNAME = "Eheiet"

    # 1. 加载/生成 RSA 公私钥对
    private_key, public_key = load_rsa_keys()

    # 2. 计算 POW，得到待签名的 “昵称 + nonce”
    pow_content = calculate_pow(MY_NICKNAME)

    # 3. 私钥签名
    signature = sign_with_private_key(private_key, pow_content)

    # 4. 公钥验证
    verify_with_public_key(public_key, pow_content, signature)