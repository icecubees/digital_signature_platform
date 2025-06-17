# ui/interface.py
import tkinter as tk
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from tkinter import filedialog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from tkinter import messagebox, scrolledtext
from algorithms.rsa_signature import RSASignature
from algorithms.dsa_signature import DSASignature
from algorithms.ecdsa_signature import ECDSASignature
from datetime import datetime




class SignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("数字签名实验平台")

        # 默认算法
        self.current_algorithm = 'RSA'
        self.algorithms = {
            'RSA': RSASignature(),
            'DSA': DSASignature(),
            'ECDSA': ECDSASignature()
        }
        self.signer = self.algorithms[self.current_algorithm]
        self.private_key, self.public_key = None, None

        self.build_gui()

    def build_gui(self):
        # 算法选择
        algo_frame = tk.Frame(self.root)
        algo_frame.pack(pady=5)
        tk.Label(algo_frame, text="选择算法:").pack(side=tk.LEFT)
        self.algo_var = tk.StringVar(value='RSA')
        algo_menu = tk.OptionMenu(algo_frame, self.algo_var, *self.algorithms.keys(), command=self.on_algo_change)
        algo_menu.pack(side=tk.LEFT)

        # 消息输入 + 摘要容器
        input_frame = tk.Frame(self.root)
        input_frame.pack(fill=tk.BOTH, padx=10, pady=5)

        # 输入消息
        tk.Label(self.root, text="输入消息:").pack()
        self.message_input = scrolledtext.ScrolledText(self.root, width=60, height=5)
        self.message_input.pack(padx=10, pady=5)

        # 摘要显示区域
        tk.Label(input_frame, text="SHA-256 摘要:").pack(anchor=tk.W)
        self.digest_display = tk.Entry(input_frame, state='readonly')
        self.digest_display.pack(fill=tk.X, pady=2)
        self.message_input.bind("<KeyRelease>", self.update_digest)

        # 按钮区域
        frame = tk.Frame(self.root)
        frame.pack(pady=5)

        tk.Button(frame, text="生成密钥对", command=self.generate_keys).grid(row=0, column=0, padx=5)
        tk.Button(frame, text="签名", command=self.sign_message).grid(row=0, column=1, padx=5)
        tk.Button(frame, text="验证签名", command=self.verify_signature).grid(row=0, column=2, padx=5)

        tk.Button(frame, text="导出密钥", command=self.export_keys).grid(row=0, column=3, padx=5)
        tk.Button(frame, text="导入密钥", command=self.import_keys).grid(row=0, column=4, padx=5)

        tk.Button(frame, text="性能测试 (100 次)", command=self.performance_test).grid(row=0, column=5, padx=5)
        tk.Button(frame, text="算法性能对比图", command=self.plot_performance_comparison).grid(row=0, column=6, padx=5)

        # 输出签名
        tk.Label(self.root, text="签名（base64）:").pack()
        self.signature_display = scrolledtext.ScrolledText(self.root, width=60, height=5)
        self.signature_display.pack(padx=10, pady=5)

        # 验证结果
        self.result_label = tk.Label(self.root, text="验证结果: ", font=("Arial", 12), fg="blue")
        self.result_label.pack(pady=5)

        # 日志区域
        log_frame = tk.Frame(self.root)
        log_frame.pack(pady=5, fill=tk.BOTH, expand=True)

        tk.Label(log_frame, text="操作日志:").pack(anchor=tk.W)
        self.log_display = scrolledtext.ScrolledText(log_frame, height=10)
        self.log_display.pack(fill=tk.BOTH, expand=True)

        tk.Button(log_frame, text="清空日志", command=self.clear_log).pack(anchor=tk.E, pady=2)



    def generate_keys(self):
        self.private_key, self.public_key = self.rsa.generate_keys()
        messagebox.showinfo("密钥生成", "成功生成 RSA 密钥对！")


    def on_algo_change(self, selected):
        self.current_algorithm = selected
        self.signer = self.algorithms[selected]
        self.private_key, self.public_key = None, None
        self.result_label.config(text="验证结果: ")
        self.signature_display.delete("1.0", tk.END)
        messagebox.showinfo("算法切换", f"当前算法已切换为 {selected}")

    def generate_keys(self):
        self.private_key, self.public_key = self.signer.generate_keys()
        messagebox.showinfo("密钥生成", f"{self.current_algorithm} 密钥生成成功")
        self.log("密钥生成", "生成新的密钥对")

    def sign_message(self):
        if not self.private_key:
            messagebox.showwarning("错误", "请先生成密钥对")
            return
        msg = self.message_input.get("1.0", tk.END).strip()
        if not msg:
            messagebox.showwarning("错误", "消息不能为空")
            return
        start = time.perf_counter()
        signature = self.signer.sign(msg, self.private_key)
        end = time.perf_counter()
        elapsed_ms = (end - start) * 1000
        import base64
        self.signature_display.delete("1.0", tk.END)
        self.signature_display.insert(tk.END, base64.b64encode(signature).decode())
        self.log("签名", f"对消息签名成功，签名长度 {len(signature)} 字节")
        self.log("签名", f"成功，签名耗时 {elapsed_ms:.2f} ms")
    def verify_signature(self):
        if not self.public_key:
            messagebox.showwarning("错误", "请先生成密钥对")
            return
        msg = self.message_input.get("1.0", tk.END).strip()
        sig_b64 = self.signature_display.get("1.0", tk.END).strip()
        if not msg or not sig_b64:
            messagebox.showwarning("错误", "消息和签名都不能为空")
            return
        try:
            import base64
            sig_bytes = base64.b64decode(sig_b64)
            start = time.perf_counter()
            is_valid = self.signer.verify(msg, sig_bytes, self.public_key)
            end = time.perf_counter()
            elapsed_ms = (end - start) * 1000
            result = "通过" if is_valid else "失败"
            self.result_label.config(text=f"验证结果: {'✅ 有效' if is_valid else '❌ 无效'}")
            self.log("验证", f"{result}，耗时 {elapsed_ms:.2f} ms，消息长度 {len(msg)}")
        except Exception as e:
            messagebox.showerror("验证错误", str(e))

    def export_keys(self):
        if not self.private_key or not self.public_key:
            messagebox.showwarning("警告", "请先生成密钥对")
            return
        # 导出私钥
        priv_path = filedialog.asksaveasfilename(defaultextension=".pem", title="保存私钥")
        if priv_path:
            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(priv_path, 'wb') as f:
                f.write(pem)
        # 导出公钥
        pub_path = filedialog.asksaveasfilename(defaultextension=".pem", title="保存公钥")
        if pub_path:
            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(pub_path, 'wb') as f:
                f.write(pem)
        messagebox.showinfo("导出成功", "密钥已保存为 .pem 文件")

    def import_keys(self):
        algo = self.current_algorithm
        try:
            priv_path = filedialog.askopenfilename(title="导入私钥 PEM 文件")
            with open(priv_path, 'rb') as f:
                priv_data = f.read()

            pub_path = filedialog.askopenfilename(title="导入公钥 PEM 文件")
            with open(pub_path, 'rb') as f:
                pub_data = f.read()

            if algo == 'RSA':
                from cryptography.hazmat.primitives.asymmetric import rsa
                self.private_key = serialization.load_pem_private_key(priv_data, password=None)
                self.public_key = serialization.load_pem_public_key(pub_data)

            elif algo == 'DSA':
                from cryptography.hazmat.primitives.asymmetric import dsa
                self.private_key = serialization.load_pem_private_key(priv_data, password=None)
                self.public_key = serialization.load_pem_public_key(pub_data)

            elif algo == 'ECDSA':
                from cryptography.hazmat.primitives.asymmetric import ec
                self.private_key = serialization.load_pem_private_key(priv_data, password=None)
                self.public_key = serialization.load_pem_public_key(pub_data)

            messagebox.showinfo("导入成功", f"{algo} 密钥导入成功")

        except Exception as e:
            messagebox.showerror("导入失败", f"导入失败: {e}")

    def log(self, action: str, detail: str):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{now}] [{self.current_algorithm}] {action}: {detail}\n"
        self.log_display.insert(tk.END, entry)
        self.log_display.see(tk.END)  # 滚动到底部

    def clear_log(self):
        self.log_display.delete("1.0", tk.END)

    def update_digest(self, event=None):
        msg = self.message_input.get("1.0", tk.END).strip()
        if not msg:
            self.digest_display.config(state='normal')
            self.digest_display.delete(0, tk.END)
            self.digest_display.config(state='readonly')
            return
        digest = hashes.Hash(hashes.SHA256())
        digest.update(msg.encode('utf-8'))
        hash_bytes = digest.finalize()
        import binascii
        hex_digest = binascii.hexlify(hash_bytes).decode()

        self.digest_display.config(state='normal')
        self.digest_display.delete(0, tk.END)
        self.digest_display.insert(0, hex_digest)
        self.digest_display.config(state='readonly')

    def performance_test(self):
        if not self.private_key or not self.public_key:
            messagebox.showwarning("错误", "请先生成密钥对")
            return

        msg = self.message_input.get("1.0", tk.END).strip()
        if not msg:
            messagebox.showwarning("错误", "请输入待签名消息")
            return

        msg_bytes = msg.encode('utf-8')
        iterations = 100

        import time
        # 签名测试
        sign_times = []
        for _ in range(iterations):
            start = time.perf_counter()
            sig = self.signer.sign(msg_bytes, self.private_key)
            end = time.perf_counter()
            sign_times.append((end - start) * 1000)

        # 验证测试
        verify_times = []
        for _ in range(iterations):
            start = time.perf_counter()
            self.signer.verify(msg_bytes, sig, self.public_key)
            end = time.perf_counter()
            verify_times.append((end - start) * 1000)

        # 汇总结果
        avg_sign = sum(sign_times) / iterations
        avg_verify = sum(verify_times) / iterations

        self.log("性能测试", f"{iterations} 次签名平均耗时: {avg_sign:.2f} ms")
        self.log("性能测试", f"{iterations} 次验证平均耗时: {avg_verify:.2f} ms")

    def plot_performance_comparison(self):
        import time
        import matplotlib.pyplot as plt
        from matplotlib.font_manager import FontProperties
        import tkinter as tk
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

        from algorithms.rsa_signature import RSASignature
        from algorithms.dsa_signature import DSASignature
        from algorithms.ecdsa_signature import ECDSASignature

        # 设置 matplotlib 中文字体（请确认该字体路径在你电脑上存在）
        font_path = "C:/Windows/Fonts/msyh.ttc"  # 微软雅黑字体路径
        chinese_font = FontProperties(fname=font_path)
        plt.rcParams['font.family'] = chinese_font.get_name()
        plt.rcParams['axes.unicode_minus'] = False  # 负号正常显示

        # tkinter 字体（窗口标题用中文一般不必特别设置，如果控件文字中文，推荐加字体）
        # 这里默认不特别设置，如果需要可以在控件里加 font 参数

        algorithms = {
            "RSA": RSASignature(),
            "DSA": DSASignature(),
            "ECDSA": ECDSASignature()
        }

        message = b"Performance test message"
        iterations = 100

        sign_times = []
        verify_times = []
        labels = []

        for name, signer in algorithms.items():
            priv, pub = signer.generate_keys()

            # 签名耗时
            s_times = []
            for _ in range(iterations):
                t0 = time.perf_counter()
                sig = signer.sign(message, priv)
                t1 = time.perf_counter()
                s_times.append((t1 - t0) * 1000)

            # 验证耗时
            v_times = []
            for _ in range(iterations):
                t0 = time.perf_counter()
                signer.verify(message, sig, pub)
                t1 = time.perf_counter()
                v_times.append((t1 - t0) * 1000)

            sign_times.append(sum(s_times) / iterations)
            verify_times.append(sum(v_times) / iterations)
            labels.append(name)

        # 绘图
        fig, ax = plt.subplots(figsize=(6, 4))
        x = range(len(labels))
        width = 0.35

        ax.bar([i - width / 2 for i in x], sign_times, width=width, label="签名")
        ax.bar([i + width / 2 for i in x], verify_times, width=width, label="验证")
        ax.set_ylabel("平均耗时 (ms)")
        ax.set_title("算法性能对比（100 次平均）")
        ax.set_xticks(x)
        ax.set_xticklabels(labels, fontproperties=chinese_font)  # 这里显式用中文字体
        ax.legend(prop=chinese_font)  # 图例也设置中文字体

        # 嵌入 tkinter 窗口
        win = tk.Toplevel(self.root)
        win.title("算法性能对比图")
        canvas = FigureCanvasTkAgg(fig, master=win)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

