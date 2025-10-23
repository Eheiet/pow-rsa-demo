# POW + RSA 演示项目

包含两个核心功能：
1. POW 工作量证明：寻找以 4 个/5 个 0 开头的 SHA256 哈希值
2. RSA 非对称加密：生成公私钥对，用私钥签名 POW 结果，用公钥验证签名

## 运行方法
1. 安装依赖：`pip install cryptography`
2. 运行 RSA 演示：`python rsa_demo.py`
