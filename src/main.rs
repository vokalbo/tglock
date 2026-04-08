#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

mod ws_proxy;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use eframe::egui;

const PROXY_PORT: u16 = 1081;

fn main() {
    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(680.0, 560.0)),
        min_window_size: Some(egui::vec2(580.0, 460.0)),
        ..Default::default()
    };

    eframe::run_native(
        "TG Unblock",
        options,
        Box::new(|cc| {
            // Включаем адаптивную тему (по умолчанию следует за системой)
            cc.egui_ctx.set_visuals(egui::Visuals::default());
            Box::new(App::new())
        }),
    )
}

#[derive(Clone)]
struct LogEntry {
    text: String,
    is_error: bool,
    ts: String,
}

struct App {
    log: Arc<Mutex<Vec<LogEntry>>>,
    proxy_stats: Arc<ws_proxy::ProxyStats>,
}

impl App {
    fn new() -> Self {
        let app = Self {
            log: Arc::new(Mutex::new(Vec::new())),
            proxy_stats: ws_proxy::ProxyStats::new(),
        };
        log_msg(&app.log, "Запущено", false);
        app
    }

    fn proxy_running(&self) -> bool {
        self.proxy_stats.running.load(Ordering::SeqCst)
    }

    fn start_proxy(&self) {
        if self.proxy_running() {
            return;
        }
        let stats = self.proxy_stats.clone();
        let log = self.log.clone();

        std::thread::spawn(move || {
            log_msg(&log, &format!("Запускаю WS-прокси на 127.0.0.1:{}...", PROXY_PORT), false);

            let rt = tokio::runtime::Runtime::new().unwrap();
            let result = rt.block_on(ws_proxy::run_proxy(PROXY_PORT, stats));
            if let Err(e) = result {
                log_msg(&log, &format!("Прокси остановлен: {}", e), true);
            }
        });

        std::thread::sleep(std::time::Duration::from_millis(300));
        if self.proxy_running() {
            log_msg(&self.log, "Прокси запущен! Настройте Telegram.", false);
        }
    }

    fn stop_proxy(&self) {
        self.proxy_stats.running.store(false, Ordering::SeqCst);
        log_msg(&self.log, "Прокси остановлен", false);
    }

    fn open_tg_proxy_link(&self) {
        let url = format!("tg://socks?server=127.0.0.1&port={}", PROXY_PORT);
        log_msg(&self.log, "Открываю настройку прокси в Telegram...", false);
        let _ = open::that(&url);
    }
}

fn log_msg(log: &Arc<Mutex<Vec<LogEntry>>>, text: &str, err: bool) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ts = format!("{:02}:{:02}:{:02}", (now % 86400) / 3600, (now % 3600) / 60, now % 60);
    log.lock().unwrap().push(LogEntry {
        text: text.to_string(),
        is_error: err,
        ts,
    });
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(std::time::Duration::from_millis(400));

        let running = self.proxy_running();
        let active = self.proxy_stats.active_conn.load(Ordering::Relaxed);
        let total = self.proxy_stats.total_conn.load(Ordering::Relaxed);
        let ws = self.proxy_stats.ws_active.load(Ordering::Relaxed);

        // --- Top bar ---
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("TG Unblock");
                ui.separator();
                if running {
                    ui.colored_label(
                        ui.visuals().widgets.active.fg_stroke.color,
                        egui::RichText::new("ПРОКСИ РАБОТАЕТ").strong(),
                    );
                    ui.separator();
                    ui.label(format!("Соединений: {} (WS: {}) | Всего: {}", active, ws, total));
                } else {
                    ui.label("Прокси не запущен");
                }
            });
        });

        // --- Log panel ---
        egui::TopBottomPanel::bottom("log")
            .min_height(130.0)
            .show(ctx, |ui| {
                ui.label(egui::RichText::new("Лог").strong());
                ui.separator();
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        let logs = self.log.lock().unwrap();
                        for e in logs.iter() {
                            let color = if e.is_error {
                                ui.visuals().error_fg_color
                            } else {
                                ui.visuals().widgets.noninteractive.fg_stroke.color
                            };
                            ui.colored_label(color, format!("[{}] {}", e.ts, e.text));
                        }
                    });
            });

        // --- Main panel ---
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(10.0);

            // --- VPN ad (top) ---
            ui.vertical_centered(|ui| {
                egui::Frame::none()
                    .fill(ui.visuals().widgets.inactive.bg_fill)
                    .rounding(8.0)
                    .inner_margin(egui::style::Margin::symmetric(14.0, 8.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.colored_label(
                                ui.visuals().hyperlink_color,
                                egui::RichText::new("by sonic VPN").size(13.0).strong(),
                            );
                            ui.label(
                                egui::RichText::new("Полный обход для всех приложений")
                                    .size(12.0)
                                    .color(ui.visuals().widgets.noninteractive.fg_stroke.color),
                            );
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.add(
                                    egui::Button::new(
                                        egui::RichText::new("@bysonicvpn_bot")
                                            .size(12.0)
                                            .strong()
                                            .color(ui.visuals().hyperlink_color),
                                    )
                                    .frame(false),
                                ).clicked() {
                                    let _ = open::that("https://t.me/bysonicvpn_bot");
                                }
                            });
                        });
                    });
            });

            ui.add_space(12.0);

            ui.vertical_centered(|ui| {
                if !running {
                    ui.label(egui::RichText::new("Обход блокировки Telegram через WebSocket-прокси").size(15.0));
                    ui.add_space(5.0);
                    ui.label("Трафик идёт через web.telegram.org — провайдер видит обычный HTTPS");
                    ui.add_space(15.0);

                    let btn = ui.add_sized(
                        [340.0, 55.0],
                        egui::Button::new(egui::RichText::new("Запустить обход").size(20.0).strong()),
                    );
                    if btn.clicked() {
                        self.start_proxy();
                    }
                } else {
                    ui.colored_label(
                        ui.visuals().widgets.active.fg_stroke.color,
                        egui::RichText::new("Обход работает").size(22.0).strong(),
                    );
                    ui.add_space(5.0);
                    ui.label(format!("SOCKS5 прокси на 127.0.0.1:{}", PROXY_PORT));
                    ui.label(format!("WebSocket-туннелей: {} | Соединений: {}", ws, active));
                    ui.add_space(12.0);

                    let stop = ui.add_sized(
                        [340.0, 42.0],
                        egui::Button::new(egui::RichText::new("Остановить").size(17.0)),
                    );
                    if stop.clicked() {
                        self.stop_proxy();
                    }
                }
            });

            ui.add_space(20.0);
            ui.separator();
            ui.add_space(8.0);

            ui.heading("Настройка Telegram Desktop");
            ui.add_space(6.0);

            if running {
                ui.horizontal(|ui| {
                    if ui.button("   Настроить автоматически   ").clicked() {
                        self.open_tg_proxy_link();
                    }
                    ui.label("(откроет Telegram, нажмите \"Подключить\")");
                });
                ui.add_space(8.0);
            }

            ui.label("Или вручную: Настройки → Продвинутые → Тип соединения → SOCKS5");
            ui.add_space(4.0);
            egui::Grid::new("manual_setup")
                .num_columns(2)
                .spacing([15.0, 4.0])
                .show(ui, |ui| {
                    ui.label("Сервер:");
                    ui.monospace("127.0.0.1");
                    ui.end_row();
                    ui.label("Порт:");
                    ui.monospace(format!("{}", PROXY_PORT));
                    ui.end_row();
                    ui.label("Логин/Пароль:");
                    ui.label("оставить пустыми");
                    ui.end_row();
                });

            ui.add_space(15.0);
            ui.separator();
            ui.add_space(5.0);

            ui.heading("Как это работает");
            ui.add_space(4.0);
            ui.label("1. Локальный SOCKS5-прокси принимает соединения от Telegram");
            ui.label("2. Трафик к серверам Telegram заворачивается в WebSocket (WSS)");
            ui.label("3. Подключение идёт через web.telegram.org — обычный HTTPS");
            ui.label("4. Провайдер/DPI не видит MTProto, не может замедлить");
            ui.add_space(4.0);
            ui.colored_label(
                ui.visuals().widgets.noninteractive.fg_stroke.color,
                "Не-Telegram трафик проходит напрямую без изменений",
            );
        });
    }
}
