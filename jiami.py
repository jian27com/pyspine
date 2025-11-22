import marshal
import zlib
import base64
import os
import sys
import subprocess
import tempfile
import shutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# 配置
SOURCE_FILE = "app.py"
OUTPUT_FILE = "jian27.py"
KEY_MODULE_NAME = "key_module"

def create_key_module():
    """创建密钥模块 - 使用AES密钥"""
    # 生成AES-256密钥
    key = os.urandom(32)
    hex_key = key.hex()
    
    # 密钥模块代码 - 纯ASCII
    key_module_code = '''def get_key():
    key_hex = "%s"
    return bytes.fromhex(key_hex)
''' % hex_key
    
    return key_module_code, key

def compile_to_pyd(module_code, module_name):
    """编译Python模块为pyd"""
    temp_dir = tempfile.mkdtemp()
    
    try:
        # 写入模块文件
        module_file = os.path.join(temp_dir, f"{module_name}.py")
        with open(module_file, 'wb') as f:
            f.write(module_code.encode('utf-8'))
        
        # 创建setup.py
        setup_code = '''from distutils.core import setup
from Cython.Build import cythonize

setup(
    ext_modules=cythonize("%s.py")
)
''' % module_name
        
        setup_file = os.path.join(temp_dir, "setup.py")
        with open(setup_file, 'wb') as f:
            f.write(setup_code.encode('utf-8'))
        
        # 编译pyd
        print(f"[+] 编译 {module_name}.pyd...")
        result = subprocess.run(
            [sys.executable, "setup.py", "build_ext", "--inplace"],
            cwd=temp_dir,
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"[-] 编译失败: {result.stderr}")
            return None
        
        # 查找生成的pyd文件
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith('.pyd') and module_name in file:
                    pyd_src = os.path.join(root, file)
                    pyd_dst = f"{module_name}.pyd"
                    shutil.copy2(pyd_src, pyd_dst)
                    print(f"[+] 生成 {pyd_dst}")
                    return pyd_dst
        
        return None
        
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def encrypt_source_code(key):
    """加密源代码 - 使用AES-CBC（修复版本）"""
    # 读取源代码
    with open(SOURCE_FILE, 'r', encoding='utf-8') as f:
        source_code = f.read()

    # 编译 → marshal → 压缩
    code_obj = compile(source_code, SOURCE_FILE, 'exec')
    marshaled = marshal.dumps(code_obj)
    compressed = zlib.compress(marshaled, level=9)

    # AES-CBC 加密 - 修复版本
    iv = os.urandom(16)
    
    # 先填充再加密
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(compressed) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    
    payload = base64.b64encode(iv + encrypted).decode('ascii')
    return payload

def create_loader_code(payload):
    """创建加载器代码 - 修复解密逻辑"""
    loader_code = '''import base64
import zlib
import marshal

try:
    # 从pyd模块导入密钥
    from %s import get_key
    KEY = get_key()
    
    # 解码payload
    d = base64.b64decode("%s")
    iv, ct = d[:16], d[16:]
    
    # 解密过程 - 修复版本
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
    
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # 先解密再去除填充
    decrypted_data = decryptor.update(ct) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    
    decompressed_data = zlib.decompress(unpadded_data)
    code_obj = marshal.loads(decompressed_data)
    exec(code_obj)
    
except Exception as e:
    print("执行出错:", e)
    input("按任意键退出...")
''' % (KEY_MODULE_NAME, payload)
    
    return loader_code

def main():
    print("[+] Python代码加密工具 - 高安全性版本")
    
    # 检查依赖
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
    except ImportError:
        print("[-] 请安装cryptography: pip install cryptography")
        return
    
    try:
        import Cython
    except ImportError:
        print("[-] 请安装Cython: pip install cython")
        return
    
    # 创建密钥模块
    print("[+] 生成密钥模块...")
    key_module_code, key = create_key_module()
    
    # 编译为pyd
    pyd_file = compile_to_pyd(key_module_code, KEY_MODULE_NAME)
    if not pyd_file:
        print("[-] PYD编译失败")
        return
    
    # 加密源代码
    print("[+] 加密源代码...")
    payload = encrypt_source_code(key)
    
    # 创建加载器
    print("[+] 创建加载器...")
    loader_code = create_loader_code(payload)
    
    # 写入输出文件
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(loader_code)
    
    print(f"[+] 完成! 输出文件: {OUTPUT_FILE}")
    print(f"[+] 密钥模块: {KEY_MODULE_NAME}.pyd")
    print("[+] 运行方式: python jian27.py")
    
    # 清理临时文件
    temp_files = [f"{KEY_MODULE_NAME}.c", "build"]
    for temp_file in temp_files:
        if os.path.exists(temp_file):
            shutil.rmtree(temp_file, ignore_errors=True)

if __name__ == "__main__":
    main()