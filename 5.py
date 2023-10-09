import tkinter as tk
from tkinter import StringVar, Entry, Button, Label, font
import threading
import time
from tkinter import filedialog

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
    
    # XOR with subkey
    xor_result = [str(int(expanded[i]) ^ int(subkey[i])) for i in range(8)]
    
    # S-Boxes
    left_xor = xor_result[:4]
    right_xor = xor_result[4:]
    left_sbox = sbox(left_xor, Sbox1)
    right_sbox = sbox(right_xor, Sbox2)
    
    combined = left_sbox + right_sbox
    # P4 permutation
    output = permute(combined, P4)
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

def brute_force(known_plaintext, known_ciphertext):
    for i in range(1024):  # 2^10 = 1024 possible keys for S-DES
        potential_key = format(i, '010b')  # Convert number to 10-bit binary string
        
        # Check both encryption and decryption
        if sdes_encrypt(known_plaintext, potential_key) == known_ciphertext and sdes_decrypt(known_ciphertext, potential_key) == known_plaintext:
            return potential_key  # Key found
            
    return None  # Key not found

def find_equivalent_keys(plaintext):
    results = {}
    
    # Iterate through all possible keys
    for i in range(1024): # 2^10 = 1024 possible keys for S-DES
        key = format(i, '010b')
        ciphertext = sdes_encrypt(plaintext, key)
        
        # Store the key associated with the resulting ciphertext
        if ciphertext in results:
            results[ciphertext].append(key)
        else:
            results[ciphertext] = [key]

    # Return the ciphertexts that have multiple keys
    equivalent_keys = {ciphertext: keys for ciphertext, keys in results.items() if len(keys) > 1}
    
    return equivalent_keys

def check_whole_plaintext_space():
    for i in range(256): # 2^8 = 256 possible plaintexts
        plaintext = format(i, '08b')
        eq_keys = find_equivalent_keys(plaintext)
        
        if eq_keys:
            print(f"For plaintext {plaintext}, found equivalent keys: {eq_keys}")

def gui_check_equivalent_keys():
    result_var.set("Checking...")
    eq_keys = find_equivalent_keys(plaintext_entry.get())
    
    # 询问用户保存文件的位置
    fpath = filedialog.asksaveasfilename(defaultextension=".txt", title="Save results as", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if not fpath:  # 如果用户取消保存操作
        return

    # 将结果保存到选择的文件中
    with open(fpath, 'w') as f:
        if eq_keys:
            f.write(f"Found equivalent keys for {plaintext_entry.get()}: {eq_keys}\n")
            result_var.set(f"Saved results to {fpath}")
        else:
            f.write(f"No equivalent keys found for {plaintext_entry.get()}\n")
            result_var.set(f"Saved results to {fpath}")

def sdes_encrypt(plaintext, key):
    key1, key2 = generate_keys(key)
    
    ip_permuted = permute(plaintext, IP)
    L, R = ip_permuted[:4], ip_permuted[4:]
    
    # First round
    f_output = f_func(R, key1)
    R_new = [str(int(L[i]) ^ int(f_output[i])) for i in range(4)]
    L_new = R
    
    # Second round
    f_output2 = f_func(R_new, key2)
    L_final = [str(int(L_new[i]) ^ int(f_output2[i])) for i in range(4)]
    R_final = R_new
    
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
    key1, key2 = generate_keys(key)
    
    ip_permuted = permute(ciphertext, IP)
    L, R = ip_permuted[:4], ip_permuted[4:]
    
    # First round
    f_output = f_func(R, key2)
    R_new = [str(int(L[i]) ^ int(f_output[i])) for i in range(4)]
    L_new = R
    
    # Second round
    f_output2 = f_func(R_new, key1)
    L_final = [str(int(L_new[i]) ^ int(f_output2[i])) for i in range(4)]
    R_final = R_new
    
    return ''.join(permute(L_final + R_final, IP_inv))

def decrypt():
    ciphertext = ciphertext_entry.get()
    key = key_entry.get()
    
    if len(ciphertext) != 8 or len(key) != 10:
        result_var.set("Ensure ciphertext is 8 bits and key is 10 bits!")
        return

    decrypted = sdes_decrypt(ciphertext, key)
    result_var.set(decrypted)

def multi_threaded_brute_force(known_plaintext, known_ciphertext):
    num_threads = 4  # 根据机器的实际核心数调整线程数
    segment = 1024 // num_threads
    threads = []

    for i in range(num_threads):
        start = i * segment
        end = (i + 1) * segment
        t = threading.Thread(target=segmented_brute_force, args=(known_plaintext, known_ciphertext, start, end))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

def segmented_brute_force(known_plaintext, known_ciphertext, start, end):
    for i in range(start, end):
        potential_key = format(i, '010b') 
        if sdes_encrypt(known_plaintext, potential_key) == known_ciphertext:
            print(f"Found the key: {potential_key}")
            return
def gui_brute_force():
    known_plaintext = plaintext_entry.get()
    known_ciphertext = ciphertext_entry.get()
    if len(known_plaintext) != 8 or len(known_ciphertext) != 8:
        result_var.set("Ensure plaintext and ciphertext are both 8 bits!")
        return

    key = brute_force(known_plaintext, known_ciphertext)
    if key:
        result_var.set(f"Key found: {key}")
    else:
        result_var.set("Key not found!")


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
# 在GUI上添加一个按钮
brute_force_button = Button(root, text="Brute Force", command=gui_brute_force, bg='#FF0000', fg='white', padx=20)
brute_force_button.pack(pady=10)
# 在GUI上添加一个按钮来触发等价密钥检查
check_equiv_keys_button = Button(root, text="Check Equivalent Keys", command=gui_check_equivalent_keys, bg='#3F51B5', fg='white', padx=20)
check_equiv_keys_button.pack(pady=10)
root.mainloop()