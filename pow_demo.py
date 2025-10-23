import hashlib
import time
def pow_demo(Eheiet, target_zeros):
    nonce =0
    target_prefix='0'*target_zeros
    start_time = time.time()
    while True:
        hash_content = f"{Eheiet}{nonce}"
        sha256_hash = hashlib.sha256(hash_content.encode('utf-8')).hexdigest()
        if sha256_hash.startswith(target_prefix) :
            end_time = time.time()
            time_cost = end_time - start_time
            return time_cost,hash_content,sha256_hash
        nonce += 1

if __name__ == '__main__':
    MY_NAME = "Eheiet"
    print("开始寻找4个0开头的hash值===")
    cost_4,content_4, hash_4 = pow_demo(MY_NAME, 4)
    print(f"花费时间{cost_4:.2f}秒")
    print(f"哈希内容{content_4}")
    print(f"哈希值{hash_4}\n")

    print("开始寻找5个0开头的hash值===")
    cost_5, content_5, hash_5 = pow_demo(MY_NAME, 5)
    print(f"花费时间{cost_5:.2f}秒")
    print(f"哈希内容{content_5}")
    print(f"哈希值{hash_5}")