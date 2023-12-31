import tkinter as tk
from tkinter import StringVar, Entry, Button, Label, font

# 定义盒
P10 = [2,4,1,6,3,9,0,8,7,5]  # 减1
P8 = [5,2,6,3,7,4,9,8]  # 减1
leftshift1 = [1,2,3,4,0]  # 减1
leftshift2 = [2,3,4,0,1]  # 减1
IP = [1,5,2,0,3,7,4,6]  # 减1
IP_inv = [3,0,2,4,6,1,7,5]  # 减1
EP = [3,0,1,2,1,2,3,0]  # 减1
Sbox1 = [[1,0,3,2],[3,2,1,0],[0,2,1,3],[3,1,0,2]]
Sbox2 = [[0,1,2,3],[2,3,1,0],[3,0,1,2],[2,1,0,3]]
P4 = [1,3,2,0]  # 减1

# 函数定义
def permute(block, table):
    return [block[x] for x in table]

def leftshift(block, table):
    return [block[x] for x in table]

def sbox(input, sbox):
    row = int(input[0] + input[3], 2)
    col = int(input[1] + input[2], 2)
    return format(sbox[row][col], '02b')

def f_func(R, subkey):
    # Expansion
    expanded = permute(R, EP)
    print(f"Expanded: {expanded}")
    
    # XOR with subkey
    xor_result = [str(int(expanded[i]) ^ int(subkey[i])) for i in range(8)]
    print(f"XOR with subkey {subkey}: {xor_result}")
    
    # S-Boxes
    left_xor = xor_result[:4]
    right_xor = xor_result[4:]
    left_sbox = sbox(left_xor, Sbox1)
    right_sbox = sbox(right_xor, Sbox2)
    print(f"Left S-box output: {left_sbox}, Right S-box output: {right_sbox}")
    
    combined = left_sbox + right_sbox
    print(f"Combined S-box output: {combined}")
    
    # P4 permutation
    output = permute(combined, P4)
    print(f"P4 output: {output}")
    return output

def generate_keys(key):
    p10_key = permute(key, P10)
    left = p10_key[:5]
    right = p10_key[5:]
    
    # First key
    left_ls1 = leftshift(left, leftshift1)
    right_ls1 = leftshift(right, leftshift1)
    key1 = permute(left_ls1 + right_ls1, P8)
    # Second key
    left_ls2 = leftshift(left_ls1, leftshift2)
    right_ls2 = leftshift(right_ls1, leftshift2)
    key2 = permute(left_ls2 + right_ls2, P8)
    return key1, key2

def sdes_encrypt(plaintext, key):
    print("====== ENCRYPTING ======")
    key1, key2 = generate_keys(key)
    print(f"Key1: {key1}, Key2: {key2}")
    
    ip_permuted = permute(plaintext, IP)
    print(f"IP Permuted: {ip_permuted}")
    L, R = ip_permuted[:4], ip_permuted[4:]
    print(f"Initial L: {L}, Initial R: {R}")
    
    # First round
    f_output = f_func(R, key1)
    R_new = [str(int(L[i]) ^ int(f_output[i])) for i in range(4)]
    L_new = R
    print(f"After 1st round - L: {L_new}, R: {R_new}")
    
    # Second round
    f_output2 = f_func(R_new, key2)
    L_final = [str(int(L_new[i]) ^ int(f_output2[i])) for i in range(4)]
    R_final = R_new
    print(f"After 2nd round - L: {L_final}, R: {R_final}")
    
    return ''.join(permute(L_final + R_final, IP_inv))

# 加密按钮事件处理函数
def encrypt():
    plaintext = plaintext_entry.get()
    key = key_entry.get()
    
    if len(plaintext) != 8 or len(key) != 10:
        result_var.set("Ensure plaintext is 8 bits and key is 10 bits!")
        return

    encrypted = sdes_encrypt(plaintext, key)
    result_var.set(encrypted)

def sdes_decrypt(ciphertext, key):
    print("====== DECRYPTING ======")
    key1, key2 = generate_keys(key)
    print(f"Key1: {key1}, Key2: {key2}")
    
    ip_permuted = permute(ciphertext, IP)
    print(f"IP Permuted: {ip_permuted}")
    L, R = ip_permuted[:4], ip_permuted[4:]
    print(f"Initial L: {L}, Initial R: {R}")
    
    # First round
    f_output = f_func(R, key2)
    R_new = [str(int(L[i]) ^ int(f_output[i])) for i in range(4)]
    L_new = R
    print(f"After 1st round - L: {L_new}, R: {R_new}")
    
    # Second round
    f_output2 = f_func(R_new, key1)
    L_final = [str(int(L_new[i]) ^ int(f_output2[i])) for i in range(4)]
    R_final = R_new
    print(f"After 2nd round - L: {L_final}, R: {R_final}")
    
    return ''.join(permute(L_final + R_final, IP_inv))

def decrypt():
    ciphertext = ciphertext_entry.get()
    key = key_entry.get()
    
    if len(ciphertext) != 8 or len(key) != 10:
        result_var.set("Ensure ciphertext is 8 bits and key is 10 bits!")
        return

    decrypted = sdes_decrypt(ciphertext, key)
    result_var.set(decrypted)

# 创建基本窗口
root = tk.Tk()
root.title("S-DES Encryption & Decryption")

# 使用默认字体，并设置字体大小
default_font = font.nametofont("TkDefaultFont")
default_font.configure(size=12)
root.option_add("*Font", default_font)

# 输入明文的标签和输入框
plaintext_label = Label(root, text="Plaintext (8 bits):")
plaintext_label.pack(pady=10)

plaintext_entry = Entry(root, width=20, borderwidth=2)
plaintext_entry.pack(pady=10)

# 输入密文的标签和输入框
ciphertext_label = Label(root, text="Ciphertext (8 bits):")
ciphertext_label.pack(pady=10)

ciphertext_entry = Entry(root, width=20, borderwidth=2)
ciphertext_entry.pack(pady=10)

# 输入密钥的标签和输入框
key_label = Label(root, text="Key (10 bits):")
key_label.pack(pady=10)

key_entry = Entry(root, width=20, borderwidth=2)
key_entry.pack(pady=10)

# 加密按钮
encrypt_button = Button(root, text="Encrypt", command=encrypt, bg='#4CAF50', fg='white', padx=20)
encrypt_button.pack(pady=10)

# 解密按钮
decrypt_button = Button(root, text="Decrypt", command=decrypt, bg='#FF5733', fg='white', padx=20)
decrypt_button.pack(pady=10)

# 显示结果的标签
result_var = StringVar()
result_label = Label(root, textvariable=result_var, bg='#F0F0F0', fg='#333', width=20, height=2)
result_label.pack(pady=10, padx=20)

root.mainloop()