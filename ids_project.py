import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from collections import defaultdict
from datetime import datetime
import random

# scapy paketi genellikle ek kurulum gerektirdiği için
# yüklü değilse bile programın çökmemesi için try-except kullanıyoruz.
try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class IDS:
    """IDS (Intrusion Detection System) Core Engine
    Ağ trafiğini analiz eder ve şüpheli durumları tespit eder.
    """
    def __init__(self, gui_callback, alert_callback):
        self.gui_callback = gui_callback  # GUI'ye genel log göndermek için
        self.alert_callback = alert_callback # GUI'ye alarm (şüpheli IP) göndermek için

        self.running = False
        
        # Tespit mekanizması için veri yapıları
        self.ip_request_counts = defaultdict(list)  # {ip: [zaman1, zaman2, ...]}
        self.ip_ports_accessed = defaultdict(set)   # {ip: {port1, port2, ...}}
        
        self.suspicious_ips = set()
        
        # IDS Kuralları / Eşik Değerleri
        self.DOS_THRESHOLD = 20  # Aynı IP'den gelecek maksimum istek
        self.DOS_TIME_WINDOW = 5 # Kaç saniye içinde (örn: 5 sn içinde 20 istek)
        self.PORT_SCAN_THRESHOLD = 5 # Farklı port sayısı (Port tarama tespiti için)

    def start(self):
        """Gerçek ağ paketlerini dinlemeyi başlatır."""
        self.running = True
        self.ip_request_counts.clear()
        self.ip_ports_accessed.clear()
        self.suspicious_ips.clear()
        
        if SCAPY_AVAILABLE:
            # İşletim sistemini dondurmamak için dinleme işlemini arka planda (Thread) yapıyoruz
            self.sniff_thread = threading.Thread(target=self._sniff_packets, daemon=True)
            self.sniff_thread.start()
        else:
            self.gui_callback("Sistem", "Uyarı: scapy yüklü değil! Simülasyon modunu kullanın.")

    def stop(self):
        """Dinlemeyi durdurur."""
        self.running = False

    def _sniff_packets(self):
        """Scapy ile paket yakalama fonksiyonu (Arka planda çalışır)"""
        try:
            # Sadece IP paketlerini yakala, prn ile her paketi _process_packet'a gönder
            sniff(filter="ip", prn=self._process_packet, stop_filter=lambda p: not self.running, store=0)
        except Exception as e:
            self.gui_callback("Hata", f"Dinleme hatası (Yönetici izni gerekebilir): {e}")

    def _process_packet(self, packet):
        """Yakalanan her paketi ayrıştırır ve analiz eder."""
        if not self.running:
            return

        if IP in packet:
            src_ip = packet[IP].src
            dst_port = None
            
            # TCP veya UDP portunu al
            if TCP in packet:
                dst_port = packet[TCP].dport
            elif UDP in packet:
                dst_port = packet[UDP].dport
                
            if dst_port is not None:
                self.analyze_traffic(src_ip, dst_port)

    def analyze_traffic(self, src_ip, dst_port):
        """IP ve port bilgisini alıp şüpheli bir durum var mı diye kontrol eder."""
        current_time = time.time()
        
        # ====== 1. DOS / YOĞUN TRAFİK TESPİTİ ======
        # Sadece son 'DOS_TIME_WINDOW' (5 sn) içindeki istekleri tut
        self.ip_request_counts[src_ip] = [t for t in self.ip_request_counts[src_ip] if current_time - t <= self.DOS_TIME_WINDOW]
        self.ip_request_counts[src_ip].append(current_time) # Yeni isteği ekle
        
        # Eğer eşik değerini aştıysa (5 sn içinde 20'den fazla istek)
        if len(self.ip_request_counts[src_ip]) >= self.DOS_THRESHOLD:
            if src_ip not in self.suspicious_ips:
                self.trigger_alert(src_ip, "Şüpheli Yoğun Trafik (Olası DoS)")
        
        # ====== 2. PORT TARAMA (PORT SCAN) TESPİTİ ======
        self.ip_ports_accessed[src_ip].add(dst_port)
        
        # Aynı IP birçok farklı porta istek atmışsa
        if len(self.ip_ports_accessed[src_ip]) >= self.PORT_SCAN_THRESHOLD:
            if src_ip not in self.suspicious_ips:
                self.trigger_alert(src_ip, "Port Tarama Şüphesi (Port Scan)")

    def trigger_alert(self, ip, reason):
        """Şüpheli durum tespit edildiğinde GUI'yi uyarır."""
        self.suspicious_ips.add(ip)
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] {ip} - {reason}"
        self.alert_callback(log_msg, ip)

    # ==========================================
    # DEMO VE SUNUM İÇİN SİMÜLASYON FONKSİYONLARI
    # ==========================================
    def simulate_traffic(self):
        """Test amaçlı sahte trafik oluşturur."""
        self.running = True
        sim_thread = threading.Thread(target=self._run_simulation, daemon=True)
        sim_thread.start()

    def _run_simulation(self):
        normal_ips = ["192.168.1.10", "10.0.0.5", "172.16.0.42", "192.168.1.100"]
        attacker_dos = "192.168.1.99"    # DoS yapacak IP
        attacker_scan = "10.0.0.66"      # Port tarayacak IP
        
        self.gui_callback("Simülasyon", "Sanal ağ trafiği oluşturuluyor...")
        
        while self.running:
            prob = random.random()
            
            if prob < 0.6:
                # %60 İhtimalle Normal Sistem Trafiği
                src_ip = random.choice(normal_ips)
                dst_port = random.choice([80, 443, 53])
                self.analyze_traffic(src_ip, dst_port)
                self.gui_callback(src_ip, f"Normal Paket -> Port: {dst_port}")
            
            elif prob < 0.8:
                # %20 İhtimalle DoS Saldırısı (Kısa sürede çok paket)
                self.gui_callback(attacker_dos, "Arka arkaya hızlı paket gönderiyor...")
                for _ in range(25): # Eşik değer 20, bilerek 25 atıyoruz ki algılasın
                    self.analyze_traffic(attacker_dos, 80)
                    time.sleep(0.01)
            
            else:
                # %20 İhtimalle Port Tarama (Farklı portlara erişim)
                self.gui_callback(attacker_scan, "Sırayla portları tarıyor...")
                for port in range(20, 30): # 10 farklı porta gidiyor (Eşik 5)
                    self.analyze_traffic(attacker_scan, port)
                    time.sleep(0.1)
                    
            time.sleep(random.uniform(0.5, 2.0)) # Bir sonraki olayı rastgele bekle


class IDS_GUI:
    """Kullanıcı Arayüzü (Tkinter) Yönetimi"""
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Ağ Güvenliği - Basit IDS")
        self.root.geometry("900x650")
        self.root.configure(bg="#1e1e2e") # Catppuccin Base colors
        
        self.ids = IDS(gui_callback=self.log_event, alert_callback=self.handle_alert)
        
        self.setup_ui()
        
    def setup_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        
        # Tema Renk Paleti (Modern Koyu Tema)
        BG_COLOR = "#1e1e2e"
        PANEL_BG = "#181825"
        TEXT_COLOR = "#cdd6f4"
        ACCENT_COLOR = "#89b4fa"
        
        style.configure("TFrame", background=BG_COLOR)
        style.configure("Panel.TFrame", background=PANEL_BG)
        style.configure("TLabel", background=BG_COLOR, foreground=TEXT_COLOR, font=("Segoe UI", 11))
        style.configure("Panel.TLabel", background=PANEL_BG, foreground=TEXT_COLOR, font=("Segoe UI", 11, "bold"))
        
        # Basit Header
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=tk.X, pady=(25, 15))
        
        tk.Label(header_frame, text="INTRUSION DETECTION SYSTEM", 
                 bg=BG_COLOR, fg=ACCENT_COLOR, font=("Segoe UI", 22, "bold")).pack()
        
        tk.Label(header_frame, text="Ağ Trafiği Analizi ve Anomali Tespiti", 
                 bg=BG_COLOR, fg="#a6adc8", font=("Segoe UI", 11)).pack()
                 
        # Buton Fonksiyonu (Daha şık butonlar için)
        def create_btn(parent, text, bg, hover_bg, fg, cmd, side=tk.LEFT):
            btn = tk.Button(parent, text=text, bg=bg, fg=fg, activebackground=hover_bg, activeforeground=fg,
                            font=("Segoe UI", 10, "bold"), command=cmd, relief=tk.FLAT, 
                            padx=20, pady=10, cursor="hand2", borderwidth=0)
            btn.pack(side=side, padx=10)
            
            def on_enter(e):
                if btn['state'] == tk.NORMAL: btn['background'] = hover_bg
            def on_leave(e):
                if btn['state'] == tk.NORMAL: btn['background'] = bg
                
            btn.bind("<Enter>", on_enter)
            btn.bind("<Leave>", on_leave)
            
            # Saklamak için orijinal renkleri kaydedelim
            btn.default_bg = bg
            btn.hover_bg = hover_bg
            btn.default_fg = fg
            return btn

        # Kontrol Butonları
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=30, pady=(5, 20))
        
        self.btn_start = create_btn(control_frame, "▶ Gerçek Trafiği Dinle", "#a6e3a1", "#8bd588", "#11111b", self.start_ids)
        self.btn_stop = create_btn(control_frame, "⏹ Durdur", "#f38ba8", "#e06c8b", "#11111b", self.stop_ids)
        self.btn_sim = create_btn(control_frame, "🧪 Demo Simülasyonunu Başlat", "#f9e2af", "#e8cb8d", "#11111b", self.start_simulation, side=tk.RIGHT)
        
        # İçerik Alanı
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 20))
        
        # Sol Kısım: Log Çıktıları
        log_container = ttk.Frame(main_frame, style="Panel.TFrame")
        log_container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 15))
        
        ttk.Label(log_container, text="📋 CANLI AĞ OLAYLARI", style="Panel.TLabel").pack(anchor=tk.W, padx=20, pady=(15, 10))
        
        log_inner = ttk.Frame(log_container, style="Panel.TFrame")
        log_inner.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        self.log_text = tk.Text(log_inner, bg="#11111b", fg="#a6adc8", font=("Consolas", 10), 
                                state=tk.DISABLED, relief=tk.FLAT, padx=15, pady=15,
                                highlightthickness=0, insertbackground=TEXT_COLOR)
        
        log_scroll = ttk.Scrollbar(log_inner, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Alerts tag format
        self.log_text.tag_config("alert", foreground="#f38ba8", font=("Consolas", 10, "bold"))
        self.log_text.tag_config("info", foreground="#89b4fa")
        
        # Sağ Kısım: Şüpheli Tespitler
        alert_container = ttk.Frame(main_frame, style="Panel.TFrame")
        alert_container.pack(side=tk.RIGHT, fill=tk.Y)
        
        ttk.Label(alert_container, text="🚨 ŞÜPHELİ IP'LER", style="Panel.TLabel").pack(anchor=tk.W, padx=20, pady=(15, 10))
        
        alert_inner = ttk.Frame(alert_container, style="Panel.TFrame")
        alert_inner.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        self.alert_list = tk.Listbox(alert_inner, width=35, bg="#313244", fg="#f38ba8", 
                                     font=("Consolas", 11, "bold"), selectbackground="#45475a", 
                                     relief=tk.FLAT, highlightthickness=0, selectborderwidth=0)
        self.alert_list.pack(side=tk.LEFT, fill=tk.Y, expand=True)
        
        # Başlangıçta buton state'leri
        self._toggle_buttons(start=True, stop=False, sim=True)

    def log_event(self, ip, event):
        self.root.after(0, self._update_log, ip, event)
        
    def _update_log(self, ip, event):
        timestamp = datetime.now().strftime("%H:%M:%S")
        msg = f"[{timestamp}] {ip:<15} - {event}\n"
        
        self.log_text.config(state=tk.NORMAL)
        if ip == "SİSTEM":
            self.log_text.insert(tk.END, msg, "info")
        else:
            self.log_text.insert(tk.END, msg)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def handle_alert(self, log_msg, ip):
        self.root.after(0, self._process_alert, log_msg, ip)
        
    def _process_alert(self, log_msg, ip):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, "\n" + "━"*50 + "\n", "alert")
        self.log_text.insert(tk.END, "⚠️ " + log_msg + "\n", "alert")
        self.log_text.insert(tk.END, "━"*50 + "\n\n", "alert")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        
        if ip not in self.alert_list.get(0, tk.END):
            # IP ortalanmış gibi görünsün diye başa boşluk ekleyerek listeye ekle
            self.alert_list.insert(tk.END, f"  {ip}")
            messagebox.showwarning("ŞÜPHELİ AKTİVİTE!", f"Sistem bir anomali tespit etti.\n\nKaynak: {ip}\n\nDetay:\n{log_msg}")

    def start_ids(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Hata", "scapy kütüphanesi yüklü değil!\nKomut: pip install scapy")
            return
            
        self._toggle_buttons(start=False, stop=True, sim=False)
        self.log_event("SİSTEM", "Gerçek zamanlı arayüz dinleme başlatıldı...")
        self.ids.start()

    def stop_ids(self):
        self._toggle_buttons(start=True, stop=False, sim=True)
        self.log_event("SİSTEM", "Dinleme/Simülasyon durduruldu.")
        self.ids.stop()

    def start_simulation(self):
        self._toggle_buttons(start=False, stop=True, sim=False)
        self.log_event("SİSTEM", "TEST SİMÜLASYONU BAŞLATILDI...")
        self.ids.simulate_traffic()
        
    def _toggle_buttons(self, start, stop, sim):
        disabled_bg = "#313244"
        disabled_fg = "#6c7086"
        
        def update_btn(btn, enable):
            if enable:
                btn.config(state=tk.NORMAL, bg=btn.default_bg, fg=btn.default_fg, cursor="hand2")
            else:
                btn.config(state=tk.DISABLED, bg=disabled_bg, fg=disabled_fg, cursor="arrow")

        update_btn(self.btn_start, start)
        update_btn(self.btn_stop, stop)
        update_btn(self.btn_sim, sim)


if __name__ == "__main__":
    # Konsol penceresini kapatsak bile arka planda GUI çalışacaktır
    root = tk.Tk()
    app = IDS_GUI(root)
    root.mainloop()
