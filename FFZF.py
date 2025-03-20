import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import httpx
import asyncio
import threading
import json
import csv
import re
from urllib.parse import urljoin
from playwright.async_api import async_playwright

class FuzzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔥 PyFuzzer Pro - Web Attack Toolkit")
        self.root.geometry("1200x750")

        self.setup_widgets()

    def setup_widgets(self):
        tk.Label(self.root, text="Target URL:").pack(anchor="w", padx=10, pady=5)
        self.url_entry = tk.Entry(self.root, width=100)
        self.url_entry.pack(padx=10)

        tk.Label(self.root, text="Request Type:").pack(anchor="w", padx=10, pady=5)
        self.request_type = tk.StringVar(value="GET")
        ttk.Combobox(self.root, textvariable=self.request_type, values=["GET", "POST", "HEAD"]).pack(padx=10)

        tk.Label(self.root, text="POST Data (optional, use FUZZ):").pack(anchor="w", padx=10, pady=5)
        self.post_data = tk.Text(self.root, height=3)
        self.post_data.pack(padx=10, fill="x")

        tk.Label(self.root, text="Headers (JSON format):").pack(anchor="w", padx=10, pady=5)
        self.headers_entry = tk.Text(self.root, height=3)
        self.headers_entry.pack(padx=10, fill="x")

        tk.Button(self.root, text="Select Wordlist", command=self.select_wordlist).pack(pady=5)
        self.wordlist_path = tk.StringVar()
        tk.Label(self.root, textvariable=self.wordlist_path).pack(pady=2)

        self.delay_label = tk.Label(self.root, text="Delay between requests (ms):")
        self.delay_label.pack(anchor="w", padx=10)
        self.delay_var = tk.IntVar(value=0)
        tk.Spinbox(self.root, from_=0, to=5000, textvariable=self.delay_var).pack(padx=10)

        self.bypass_var = tk.BooleanVar()
        tk.Checkbutton(self.root, text="💥 Try WAF Bypass Headers", variable=self.bypass_var).pack(anchor="w", padx=10, pady=5)

        self.js_mode = tk.BooleanVar()
        tk.Checkbutton(self.root, text="🧐 JavaScript Rendering (Playwright)", variable=self.js_mode).pack(anchor="w", padx=10, pady=5)

        self.regex_var = tk.StringVar()
        tk.Label(self.root, text="🔍 Regex to extract from response (optional):").pack(anchor="w", padx=10)
        tk.Entry(self.root, textvariable=self.regex_var, width=100).pack(padx=10, pady=5)

        self.output_filter_var = tk.StringVar()
        tk.Label(self.root, text="📌 Filter results (regex or keyword):").pack(anchor="w", padx=10)
        tk.Entry(self.root, textvariable=self.output_filter_var, width=100).pack(padx=10, pady=5)

        self.start_button = tk.Button(self.root, text="🚀 Start Fuzzing", command=self.start_fuzzing)
        self.start_button.pack(pady=10)

        self.tree = ttk.Treeview(self.root, columns=("URL", "Status", "Length", "Extracted"), show="headings")
        self.tree.heading("URL", text="URL")
        self.tree.heading("Status", text="Status Code")
        self.tree.heading("Length", text="Length")
        self.tree.heading("Extracted", text="Extracted")
        self.tree.pack(expand=True, fill="both", padx=10, pady=10)

        self.save_button = tk.Button(self.root, text="📂 Save Results", command=self.save_results)
        self.save_button.pack(pady=5)
        self.results = []

    def select_wordlist(self):
        file_path = filedialog.askopenfilename(title="Select Wordlist File")
        if file_path:
            self.wordlist_path.set(file_path)

    def start_fuzzing(self):
        url = self.url_entry.get().strip()
        wordlist = self.wordlist_path.get()

        if not url or not wordlist:
            messagebox.showwarning("Input Error", "Please provide both URL and wordlist file.")
            return

        try:
            headers = json.loads(self.headers_entry.get("1.0", tk.END).strip() or '{}')
        except json.JSONDecodeError:
            messagebox.showerror("Header Error", "Invalid headers format. Use valid JSON.")
            return

        if self.bypass_var.get():
            headers.update({
                "X-Original-URL": "/",
                "X-Rewrite-URL": "/",
                "X-Custom-IP-Authorization": "127.0.0.1",
                "X-Forwarded-For": "127.0.0.1",
                "X-Remote-IP": "127.0.0.1"
            })

        post_data = self.post_data.get("1.0", tk.END).strip()
        req_type = self.request_type.get().upper()
        delay = self.delay_var.get() / 1000
        regex = self.regex_var.get().strip()
        use_js = self.js_mode.get()
        output_filter = self.output_filter_var.get().strip()

        self.start_button.config(state=tk.DISABLED)
        self.tree.delete(*self.tree.get_children())
        self.results.clear()

        threading.Thread(target=self.run_fuzzing_thread, args=(url, wordlist, req_type, post_data, headers, delay, regex, use_js, output_filter)).start()

    def run_fuzzing_thread(self, url, wordlist, req_type, post_data, headers, delay, regex, use_js, output_filter):
        asyncio.run(self.fuzz(url, wordlist, req_type, post_data, headers, delay, regex, use_js, output_filter))
        self.start_button.config(state=tk.NORMAL)

    async def fetch_with_playwright(self, url):
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()
            await page.goto(url)
            content = await page.content()
            await browser.close()
            return content

    async def fuzz(self, target, wordlist_path, req_type, post_data, headers, delay, regex, use_js, output_filter):
        with open(wordlist_path, 'r') as f:
            words = f.read().splitlines()

        async with httpx.AsyncClient(headers=headers) as client:
            for word in words:
                full_url = urljoin(target, word)
                try:
                    if use_js:
                        html = await self.fetch_with_playwright(full_url)
                        extracted = re.search(regex, html).group(0) if regex and re.search(regex, html) else ""
                        status = "JS"
                        length = len(html)
                    else:
                        if req_type == "POST":
                            data = post_data.replace("FUZZ", word)
                            r = await client.post(full_url, data=data, timeout=10)
                        elif req_type == "HEAD":
                            r = await client.head(full_url, timeout=10)
                        else:
                            r = await client.get(full_url, timeout=10)

                        extracted = re.search(regex, r.text).group(0) if regex and re.search(regex, r.text) else ""
                        status = r.status_code
                        length = len(r.text)

                    match_text = f"{full_url} {extracted}"
                    if output_filter and not re.search(output_filter, match_text):
                        continue

                    if status != 404:
                        self.results.append((full_url, status, length, extracted))
                        self.tree.insert("", "end", values=(full_url, status, length, extracted))

                except Exception as e:
                    print(f"Error processing {full_url}: {e}")  # Log the error for debugging
                    continue
                await asyncio.sleep(delay)

    def save_results(self):
        if not self.results:
            messagebox.showinfo("No Results", "No results to save.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[
                ("CSV files", "*.csv"),
                ("Text files", "*.txt")
            ]
        )
        if file_path:
            try:
                if file_path.endswith(".txt"):
                    with open(file_path, "w", encoding="utf-8") as f:
                        for row in self.results:
                            f.write(f"URL: {row[0]}\nStatus: {row[1]}\nLength: {row[2]}\nExtracted: {row[3]}\n{'-'*50}\n")
                else:
                    with open(file_path, "w", newline='', encoding="utf-8") as f:
                        writer = csv.writer(f)
                        writer.writerow(["URL", "Status Code", "Length", "Extracted"])
                        for row in self.results:
                            writer.writerow(row)
                messagebox.showinfo("Saved", f"Results saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save results:\n{e}")

def show_info():
    info_window = tk.Toplevel(root)
    info_window.title("📘 معلومات / Info")
    info_window.geometry("900x700")

    toolbar = tk.Frame(info_window)
    toolbar.pack(fill="x")

    search_var = tk.StringVar()
    search_entry = tk.Entry(toolbar, textvariable=search_var, width=30)
    search_entry.pack(side="left", padx=5, pady=5)

    def search_text():
        text_widget.tag_remove('highlight', '1.0', tk.END)
        query = search_var.get()
        if query:
            start_pos = '1.0'
            while True:
                start_pos = text_widget.search(query, start_pos, stopindex=tk.END)
                if not start_pos:
                    break
                end_pos = f"{start_pos}+{len(query)}c"
                text_widget.tag_add('highlight', start_pos, end_pos)
                start_pos = end_pos
            text_widget.tag_config('highlight', background='yellow', foreground='black')

    def increase_font():
        current_font = text_widget.cget("font")
        font_name, font_size = current_font.split()[0], int(current_font.split()[1])
        text_widget.config(font=(font_name, font_size + 2))

    def decrease_font():
        current_font = text_widget.cget("font")
        font_name, font_size = current_font.split()[0], int(current_font.split()[1])
        if font_size > 6:
            text_widget.config(font=(font_name, font_size - 2))

    tk.Button(toolbar, text="🔍 بحث", command=search_text).pack(side="left")
    tk.Button(toolbar, text="🔎 + تكبير", command=increase_font).pack(side="left")
    tk.Button(toolbar, text="🔍 - تصغير", command=decrease_font).pack(side="left")

    text_widget = tk.Text(info_window, wrap="word", font=("Arial", 10))
    text_widget.pack(expand=True, fill="both")

    help_text = """
🧰 PyFuzzer Pro - Advanced Web Fuzzer

PyFuzzer Pro هي أداة متقدمة لاختبار أمان المواقع باستخدام تقنيات Fuzzing.

🔹 خطوات الاستخدام:

1. URL: أدخل الرابط مع الكلمة FUZZ.
2. Request Type: اختر نوع الطلب.
3. POST Data: اكتب بيانات POST إن وجدت.
4. Headers: أدخل الهيدرز بصيغة JSON.
5. Wordlist: اختر ملف كلمات.
6. Delay: تأخير بين الطلبات.
7. Regex Extract: تعبير لاستخراج من الرد.
8. Filter Output: تصفية النتائج.
9. WAF Bypass: تفعيل تجاوز الجدار الناري.
10. JavaScript Rendering: تشغيل تحليل JS.

📂 حفظ النتائج عبر زر "Save Results"

📄 للاستخدام الأخلاقي فقط.
"""
    text_widget.insert("1.0", help_text)
    text_widget.config(state="disabled")

    def save_to_file():
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            try:
                content = text_widget.get("1.0", tk.END)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("تم الحفظ", f"تم حفظ الملف بنجاح إلى: {file_path}")
            except Exception as e:
                messagebox.showerror("خطأ", f"حدث خطأ أثناء حفظ الملف:\n{e}")

    def export_to_pdf():
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfgen import canvas
            file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")])
            if file_path:
                content = text_widget.get("1.0", tk.END).strip().split("\n")
                c = canvas.Canvas(file_path, pagesize=A4)
                width, height = A4
                y = height - 40
                for line in content:
                    c.drawString(40, y, line[:150])
                    y -= 15
                    if y < 40:
                        c.showPage()
                        y = height - 40
                c.save()
                messagebox.showinfo("تم الحفظ", f"تم حفظ الملف كـ PDF بنجاح: {file_path}")
        except ImportError:
            messagebox.showerror("مكتبة ناقصة", "يرجى تنصيب مكتبة reportlab عبر pip install reportlab")
        except Exception as e:
            messagebox.showerror("خطأ", f"حدث خطأ أثناء حفظ الملف كـ PDF:\n{e}")

    tk.Button(toolbar, text="📂 حفظ الشرح", command=save_to_file).pack(side="right", padx=5)
    tk.Button(toolbar, text="📄 تصدير كـ PDF", command=export_to_pdf).pack(side="right", padx=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = FuzzerGUI(root)

    menu_bar = tk.Menu(root)
    help_menu = tk.Menu(menu_bar, tearoff=0)
    help_menu.add_command(label="📘 معلومات / Info", command=show_info)
    menu_bar.add_cascade(label="مساعدة / Help", menu=help_menu)
    root.config(menu=menu_bar)

    root.mainloop()