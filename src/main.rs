use std::sync::{Arc, Mutex};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use nanoid::nanoid;
use regex::Regex;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

pub fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Connection>>,
    pub base_url: String,
    pub auth_token: String,
}

pub struct IssueRule {
    pub name: &'static str,
    pub pattern: Regex,
    pub solution_ru: &'static str,
}

pub fn get_rules() -> Vec<IssueRule> {
    vec![
        IssueRule {
            name: "EULA не принята",
            pattern: Regex::new(r"(?i)You need to agree to the EULA in order to run the server").unwrap(),
            solution_ru: "Вы не приняли EULA. Откройте файл eula.txt и смените eula=false на eula=true.",
        },
        IssueRule {
            name: "Порт уже занят",
            pattern: Regex::new(r"(?i)(Address already in use: bind|FAILED TO BIND TO PORT)").unwrap(),
            solution_ru: "Порт уже занят другим процессом. Завершите старый процесс сервера или смените server-port в server.properties.",
        },
        IssueRule {
            name: "Несовпадение версии Java",
            pattern: Regex::new(r"(?i)has been compiled by a more recent version of the Java Runtime").unwrap(),
            solution_ru: "Несовместимая версия Java. Плагин или ядро собраны под более новую версию JVM (установите Java 21+).",
        },
        IssueRule {
            name: "Нехватка памяти (Heap OOM)",
            pattern: Regex::new(r"(?i)java\.lang\.OutOfMemoryError:\s*Java heap space").unwrap(),
            solution_ru: "Закончилась выделенная оперативная память. Увеличьте параметр -Xmx или оптимизируйте количество модов/плагинов.",
        },
        IssueRule {
            name: "Переполнение Metaspace",
            pattern: Regex::new(r"(?i)java\.lang\.OutOfMemoryError:\s*Metaspace").unwrap(),
            solution_ru: "Переполнение Metaspace из-за многократных перезагрузок плагинов командой /reload. Перезапустите сервер полностью.",
        },
        IssueRule {
            name: "Отсутствует зависимость плагина",
            pattern: Regex::new(r"(?i)(Could not load 'plugins/.*' in folder 'plugins'|UnknownDependencyException)").unwrap(),
            solution_ru: "Плагин не может запуститься: отсутствует обязательная библиотека или другой зависимый плагин.",
        },
        IssueRule {
            name: "Поврежденный чанк (Corrupt Chunk)",
            pattern: Regex::new(r"(?i)WrongLocationException|Corrupt chunk").unwrap(),
            solution_ru: "Обнаружен битый чанк в файле региона. Удалите поврежденный регион через MCASelector или восстановите из бэкапа.",
        },
        IssueRule {
            name: "Слишком большой пакет (Packet Too Large)",
            pattern: Regex::new(r"(?i)The received encoded string buffer length is longer than maximum allowed").unwrap(),
            solution_ru: "Превышен допустимый размер сетевого пакета. Возникает из-за чит-книг, предметов с переполненным NBT или перегруженных данных.",
        },
        IssueRule {
            name: "Коллизия UUID игрока",
            pattern: Regex::new(r"(?i)UUID of player .* is the same as").unwrap(),
            solution_ru: "Обнаружен дубликат UUID игрока. Включите online-mode=true или настройте современный Bungee/Velocity forwarding.",
        },
        IssueRule {
            name: "База SQLite заблокирована",
            pattern: Regex::new(r"(?i)(database is locked|SQLiteBusyException)").unwrap(),
            solution_ru: "База данных SQLite заблокирована другим процессом или зависшим потоком записи.",
        },
    ]
}

#[derive(Serialize)]
pub struct DiagnosisResult {
    pub rule: String,
    pub solution_ru: String,
}

pub fn analyze_log(text: &str) -> Vec<DiagnosisResult> {
    let rules = get_rules();
    let mut hits = Vec::new();
    for r in rules {
        if r.pattern.is_match(text) {
            hits.push(DiagnosisResult {
                rule: r.name.to_string(),
                solution_ru: r.solution_ru.to_string(),
            });
        }
    }
    hits
}

pub fn init_db(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS pastes (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL DEFAULT 'Без названия',
            syntax TEXT NOT NULL DEFAULT 'text',
            content BLOB NOT NULL,
            size_bytes INTEGER NOT NULL DEFAULT 0,
            views INTEGER NOT NULL DEFAULT 0,
            is_private INTEGER NOT NULL DEFAULT 0,
            is_encrypted INTEGER NOT NULL DEFAULT 0,
            burn_after_reading INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            has_issues INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_expires_at ON pastes(expires_at);
        CREATE INDEX IF NOT EXISTS idx_created_at ON pastes(created_at);",
    )?;

    Ok(())
}

pub fn clean_expired(conn: &Connection) -> rusqlite::Result<usize> {
    let now = Utc::now().timestamp();
    conn.execute("DELETE FROM pastes WHERE expires_at <= ?1", params![now])
}

#[derive(Deserialize)]
pub struct CreatePastePayload {
    pub title: Option<String>,
    pub syntax: Option<String>,
    pub content: Option<String>,
    pub ttl_minutes: Option<i64>,
    pub ttl_hours: Option<i64>,
    pub is_private: Option<bool>,
    pub is_encrypted: Option<bool>,
    pub burn_after_reading: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct CreatePasteResponse {
    pub id: String,
    pub url: String,
    pub raw_url: String,
    pub expires_at: i64,
    pub issues_detected: usize,
}

#[derive(Serialize)]
pub struct PasteItem {
    pub id: String,
    pub title: String,
    pub syntax: String,
    pub size_bytes: i64,
    pub views: i64,
    pub created_at_human: String,
    pub has_issues: bool,
    pub is_encrypted: bool,
    pub burn_after_reading: bool,
}

fn human_size(bytes: i64) -> String {
    if bytes < 1024 {
        format!("{} Б", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} КБ", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} МБ", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn human_time_ago(ts: i64) -> String {
    let now = Utc::now().timestamp();
    let diff = now - ts;
    if diff < 60 {
        format!("{} сек. назад", diff.max(1))
    } else if diff < 3600 {
        format!("{} мин. назад", diff / 60)
    } else if diff < 86400 {
        format!("{} ч. назад", diff / 3600)
    } else {
        format!("{} дн. назад", diff / 86400)
    }
}

fn syntax_title(syntax: &str) -> &'static str {
    match syntax {
        "log" => "Лог сервера",
        "yaml" => "YAML",
        "json" => "JSON",
        "xml" => "XML / HTML",
        "toml" => "TOML / INI",
        "properties" => "Properties",
        "java" => "Java",
        "kotlin" => "Kotlin",
        "rust" => "Rust",
        "python" => "Python",
        "javascript" => "JavaScript",
        "typescript" => "TypeScript",
        "c" => "C",
        "cpp" => "C++",
        "csharp" => "C#",
        "go" => "Go",
        "php" => "PHP",
        "ruby" => "Ruby",
        "sql" => "SQL",
        "bash" => "Bash / Shell",
        "dockerfile" => "Dockerfile",
        "nginx" => "Nginx Config",
        "markdown" => "Markdown",
        _ => "Обычный текст",
    }
}

fn human_expires_in(expires_at: i64) -> String {
    let diff = (expires_at - Utc::now().timestamp()).max(0);
    if diff < 60 {
        format!("{} сек.", diff.max(1))
    } else if diff < 3600 {
        format!("{} мин.", (diff + 59) / 60)
    } else if diff < 86400 {
        format!("{} ч.", (diff + 3599) / 3600)
    } else {
        format!("{} дн.", (diff + 86399) / 86400)
    }
}

fn render_sidebar_pastes(recent: &[PasteItem]) -> String {
    if recent.is_empty() {
        return r#"<div style="color: #6e7681; font-size: 0.85rem; padding: 12px 0;">Публичных записей пока нет</div>"#.to_string();
    }
    let mut out = String::new();
    for p in recent {
        let mut badges = String::new();
        if p.is_encrypted {
            badges.push_str(r#"<span class="badge badge-enc">🔐 E2E</span>"#);
        }
        if p.has_issues {
            badges.push_str(r#"<span class="badge badge-warn">⚠️ Ошибка</span>"#);
        }
        out.push_str(&format!(
            r#"<a href="/p/{}" class="sidebar-item">
                <div class="sidebar-item-title">{} {}</div>
                <div class="sidebar-item-meta">
                    <span class="syntax-tag">{}</span>
                    <span>{}</span>
                    <span>{}</span>
                    <span>👁️ {}</span>
                </div>
            </a>"#,
            p.id,
            escape_html(&p.title),
            badges,
            syntax_title(&p.syntax),
            escape_html(&human_size(p.size_bytes)),
            p.created_at_human,
            p.views
        ));
    }
    out
}

pub async fn root_editor(State(state): State<AppState>) -> Html<String> {
    let recent = {
        let conn = state.db.lock().unwrap();
        let _ = clean_expired(&conn);
        let now = Utc::now().timestamp();
        let mut stmt = conn.prepare(
            "SELECT id, title, syntax, size_bytes, views, created_at, has_issues, is_encrypted, burn_after_reading 
             FROM pastes 
             WHERE is_private = 0 AND burn_after_reading = 0 AND expires_at > ?1 
             ORDER BY created_at DESC 
             LIMIT 15"
        ).unwrap();

        let rows = stmt.query_map(params![now], |row| {
            let created_at: i64 = row.get(5)?;
            Ok(PasteItem {
                id: row.get(0)?,
                title: row.get(1)?,
                syntax: row.get(2)?,
                size_bytes: row.get(3)?,
                views: row.get(4)?,
                created_at_human: human_time_ago(created_at),
                has_issues: row.get::<_, i64>(6)? > 0,
                is_encrypted: row.get::<_, i64>(7)? > 0,
                burn_after_reading: row.get::<_, i64>(8)? > 0,
            })
        }).unwrap();

        let mut items = Vec::new();
        for r in rows.flatten() {
            items.push(r);
        }
        items
    };

    let sidebar_html = render_sidebar_pastes(&recent);

    let html = format!(r#"<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ES-Paste — Хранилище логов, ошибок и кода | Pastebin</title>
  <meta name="description" content="Быстрый русскоязычный Pastebin-сервис для публикации серверных логов, стектрейсов ошибок, конфигов и исходного кода с автоматической диагностикой проблем.">
  <meta name="keywords" content="pastebin, логи сервера, minecraft crash, анализ логов, хранилище кода, paste, стектрейс, es-paste">
  <meta property="og:title" content="ES-Paste — Хранилище логов и кода">
  <meta property="og:description" content="Публикация серверных логов, конфигов и кода. Автоматический анализ типичных ошибок Minecraft и Java серверов.">
  <meta property="og:type" content="website">
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <link rel="alternate icon" type="image/x-icon" href="/favicon.ico">
  <style>
    :root {{
      --bg: #090d16;
      --card-bg: #121826;
      --surface: #1a2234;
      --border: #26334d;
      --text: #e1e7f0;
      --muted: #8b9bb4;
      --accent: #38bdf8;
      --accent-hover: #7dd3fc;
      --green: #22c55e;
      --green-hover: #16a34a;
      --warn: #f59e0b;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }}
    header {{
      padding: 14px 28px;
      background: var(--card-bg);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      flex-wrap: wrap;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 10px;
      text-decoration: none;
    }}
    .logo {{
      font-weight: 800;
      color: var(--accent);
      font-size: 1.25rem;
      letter-spacing: -0.02em;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .logo span {{ color: #fff; }}
    .nav-links {{
      display: flex;
      gap: 18px;
      align-items: center;
    }}
    .nav-link {{
      color: var(--muted);
      text-decoration: none;
      font-size: 0.9rem;
      font-weight: 500;
      transition: color 0.15s;
    }}
    .nav-link:hover, .nav-link.active {{ color: var(--accent); }}
    
    .layout {{
      flex: 1;
      display: flex;
      max-width: 1440px;
      width: 100%;
      margin: 0 auto;
      padding: 24px;
      gap: 24px;
    }}
    .main-editor {{
      flex: 1;
      display: flex;
      flex-direction: column;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
      min-width: 0;
    }}
    .editor-header {{
      padding: 14px 20px;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      display: flex;
      gap: 12px;
      align-items: center;
      flex-wrap: wrap;
    }}
    .form-control {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 8px 12px;
      border-radius: 6px;
      font-family: inherit;
      font-size: 0.88rem;
      outline: none;
    }}
    .form-control:focus {{
      border-color: var(--accent);
    }}
    .btn-submit {{
      background: var(--green);
      border: none;
      color: #fff;
      padding: 8px 18px;
      border-radius: 6px;
      font-weight: 600;
      font-size: 0.9rem;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 6px;
      transition: background 0.15s;
    }}
    .btn-submit:hover {{ background: var(--green-hover); }}

    .editor-body {{
      display: flex;
      flex: 1;
      min-height: 480px;
      position: relative;
    }}
    .line-numbers {{
      width: 50px;
      padding: 16px 8px;
      text-align: right;
      color: #4b5875;
      user-select: none;
      background: var(--surface);
      border-right: 1px solid var(--border);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.9rem;
      line-height: 1.5;
      overflow: hidden;
      white-space: pre;
    }}
    textarea {{
      flex: 1;
      background: transparent;
      border: none;
      color: var(--text);
      padding: 16px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.9rem;
      line-height: 1.5;
      resize: none;
      outline: none;
      tab-size: 4;
      white-space: pre;
    }}
    
    .sidebar {{
      width: 320px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }}
    .card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 18px;
    }}
    .card-title {{
      font-size: 0.95rem;
      font-weight: 700;
      color: var(--text);
      margin-bottom: 14px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid var(--border);
      padding-bottom: 8px;
    }}
    .sidebar-list {{
      display: flex;
      flex-direction: column;
      gap: 8px;
    }}
    .sidebar-item {{
      padding: 10px;
      border-radius: 6px;
      background: var(--surface);
      border: 1px solid transparent;
      text-decoration: none;
      transition: all 0.15s ease;
      display: block;
    }}
    .sidebar-item:hover {{
      border-color: var(--accent);
      transform: translateY(-1px);
    }}
    .sidebar-item-title {{
      font-size: 0.88rem;
      font-weight: 600;
      color: var(--text);
      margin-bottom: 4px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      display: flex;
      align-items: center;
      gap: 6px;
    }}
    .sidebar-item-meta {{
      display: flex;
      gap: 8px;
      font-size: 0.75rem;
      color: var(--muted);
      align-items: center;
    }}
    .syntax-tag {{
      background: #202b42;
      color: var(--accent);
      padding: 2px 6px;
      border-radius: 4px;
      font-family: monospace;
      font-size: 0.72rem;
    }}
    .badge {{
      font-size: 0.7rem;
      padding: 2px 6px;
      border-radius: 4px;
      font-weight: 600;
    }}
    .badge-warn {{
      background: rgba(245, 158, 11, 0.2);
      color: var(--warn);
      border: 1px solid rgba(245, 158, 11, 0.4);
    }}
    .badge-enc {{
      background: rgba(168, 85, 247, 0.2);
      color: #c084fc;
      border: 1px solid rgba(168, 85, 247, 0.4);
    }}

    footer {{
      margin-top: auto;
      padding: 14px 28px;
      font-size: 0.82rem;
      color: var(--muted);
      border-top: 1px solid var(--border);
      background: var(--card-bg);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    @media (max-width: 900px) {{
      .layout {{ flex-direction: column; }}
      .sidebar {{ width: 100%; }}
    }}
  </style>
</head>
<body>
  <header>
    <a href="/" class="brand">
      <div class="logo">⚡ ES-PASTE <span>ВСТАВКИ</span></div>
    </a>
    <div class="nav-links">
      <a href="/" class="nav-link active">Создать запись</a>
      <a href="/archive" class="nav-link">Публичный архив</a>
    </div>
  </header>

  <div class="layout">
    <div class="main-editor">
      <div class="editor-header">
        <input type="text" id="paste_title" class="form-control" placeholder="Название записи (необязательно)" style="flex: 2; min-width: 180px;" />
        
        <select id="syntax" class="form-control" style="flex: 1; min-width: 130px;">
          <optgroup label="Логи и конфиги">
            <option value="log" selected>Лог сервера / Стектрейс</option>
            <option value="yaml">YAML</option>
            <option value="json">JSON</option>
            <option value="toml">TOML / INI</option>
            <option value="properties">Java .properties</option>
            <option value="nginx">Nginx Config</option>
            <option value="dockerfile">Dockerfile</option>
          </optgroup>
          <optgroup label="Языки программирования">
            <option value="java">Java</option>
            <option value="kotlin">Kotlin</option>
            <option value="rust">Rust</option>
            <option value="python">Python</option>
            <option value="javascript">JavaScript</option>
            <option value="typescript">TypeScript</option>
            <option value="go">Go</option>
            <option value="cpp">C++</option>
            <option value="c">C</option>
            <option value="csharp">C#</option>
            <option value="php">PHP</option>
            <option value="ruby">Ruby</option>
            <option value="sql">SQL</option>
            <option value="bash">Bash / Shell</option>
          </optgroup>
          <optgroup label="Разметка и текст">
            <option value="text">Обычный текст</option>
            <option value="markdown">Markdown</option>
            <option value="xml">XML / HTML</option>
          </optgroup>
        </select>

        <select id="ttl" class="form-control" style="flex: 1; min-width: 130px;">
          <option value="5">5 минут</option>
          <option value="30">30 минут</option>
          <option value="60">1 час</option>
          <option value="720" selected>12 часов</option>
          <option value="1440">24 часа</option>
          <option value="4320">3 дня</option>
          <option value="20160">14 дней</option>
        </select>

        <select id="visibility" class="form-control" style="flex: 1; min-width: 120px;">
          <option value="public" selected>🌐 Публичная</option>
          <option value="unlisted">🔒 По ссылке</option>
        </select>

        <input type="password" id="paste_password" class="form-control" placeholder="Пароль E2E (опционально)" style="flex: 1.2; min-width: 150px;" autocomplete="new-password" />
        <label style="display: flex; align-items: center; gap: 6px; font-size: 0.85rem; color: var(--text-muted); cursor: pointer; user-select: none; white-space: nowrap;">
          <input type="checkbox" id="burn_after_reading" style="cursor: pointer; width: 15px; height: 15px; accent-color: #ef4444;" />
          🔥 Сжечь после прочтения
        </label>

        <button class="btn-submit" onclick="submitPaste()">
          <span>Опубликовать</span>
        </button>
      </div>

      <div class="editor-body">
        <div class="line-numbers" id="lines">1</div>
        <textarea id="code" placeholder="Вставьте сюда логи сервера, отчёты об ошибках, конфиги или код..." oninput="updateLines()" autofocus></textarea>
      </div>
    </div>

    <div class="sidebar">
      <div class="card">
        <div class="card-title">
          <span>Свежие записи</span>
          <a href="/archive" style="color: var(--accent); font-size: 0.78rem; text-decoration: none;">Все записи &rarr;</a>
        </div>
        <div class="sidebar-list">
          {sidebar_html}
        </div>
      </div>

      <div class="card">
        <div class="card-title">Анализатор логов</div>
        <p style="font-size: 0.82rem; color: var(--muted); line-height: 1.45;">
          Серверные логи и стектрейсы (EULA, занятые сетевые порты, нехватка памяти OOM, битые чанки и дубликаты UUID) сканируются автоматически при сохранении с выводом готового решения на русском языке.
        </p>
      </div>
    </div>
  </div>

  <footer>
    <span>ES-Paste</span>
    
  </footer>

  <script>
    const ta = document.getElementById('code');
    const lines = document.getElementById('lines');
    function updateLines() {{
      const count = ta.value.split('\n').length;
      let text = '';
      for (let i = 1; i <= count; i++) text += i + '\n';
      lines.textContent = text;
    }}
    async function deriveKey(password, salt) {{
      const enc = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        {{ name: "PBKDF2" }},
        false,
        ["deriveKey"]
      );
      return await crypto.subtle.deriveKey(
        {{
          name: "PBKDF2",
          salt: salt,
          iterations: 100000,
          hash: "SHA-256"
        }},
        keyMaterial,
        {{ name: "AES-GCM", length: 256 }},
        false,
        ["encrypt", "decrypt"]
      );
    }}

    function bufferToBase64(buf) {{
      const bytes = new Uint8Array(buf);
      let bin = "";
      for (let i = 0; i < bytes.byteLength; i++) {{
        bin += String.fromCharCode(bytes[i]);
      }}
      return btoa(bin);
    }}

    async function encryptE2E(plaintext, password) {{
      const enc = new TextEncoder();
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveKey(password, salt);
      const encrypted = await crypto.subtle.encrypt(
        {{ name: "AES-GCM", iv: iv }},
        key,
        enc.encode(plaintext)
      );
      return "ENC:v1:" + bufferToBase64(salt) + ":" + bufferToBase64(iv) + ":" + bufferToBase64(encrypted);
    }}

    async function submitPaste() {{
      const content = ta.value.trim();
      if (!content) return alert('Нельзя сохранить пустую запись.');
      
      const title = document.getElementById('paste_title').value.trim() || 'Без названия';
      const syntax = document.getElementById('syntax').value;
      const ttl = parseInt(document.getElementById('ttl').value, 10);
      const isPrivate = document.getElementById('visibility').value === 'unlisted';
      const password = document.getElementById('paste_password').value;

      let finalContent = content;
      let isEncrypted = false;

      if (password) {{
        try {{
          finalContent = await encryptE2E(content, password);
          isEncrypted = true;
        }} catch (e) {{
          return alert('Ошибка клиентского шифрования: ' + e);
        }}
      }}

      const res = await fetch('/api/paste', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          title: title,
          syntax: syntax,
          content: finalContent,
          ttl_minutes: ttl,
          is_private: isPrivate,
          is_encrypted: isEncrypted,
          burn_after_reading: burn
        }})
      }});
      if (res.ok) {{
        const data = await res.json();
        if (isEncrypted) {{
          window.location.href = '/p/' + data.id + '#key=' + encodeURIComponent(password);
        }} else {{
          window.location.href = '/p/' + data.id;
        }}
      }} else {{
        const err = await res.text();
        alert('Ошибка при сохранении: ' + err);
      }}
    }}
    updateLines();
  </script>
</body>
</html>"#, sidebar_html = sidebar_html);

    Html(html)
}

#[derive(Deserialize)]
pub struct ArchiveQuery {
    pub search: Option<String>,
}

pub async fn public_archive(
    State(state): State<AppState>,
    Query(query): Query<ArchiveQuery>,
) -> Html<String> {
    let recent = {
        let conn = state.db.lock().unwrap();
        let _ = clean_expired(&conn);
        let now = Utc::now().timestamp();
        
        let search_term = query.search.as_deref().unwrap_or("").trim();
        let mut items = Vec::new();

        if search_term.is_empty() {
            let mut stmt = conn.prepare(
                "SELECT id, title, syntax, size_bytes, views, created_at, has_issues 
                 FROM pastes 
                 WHERE is_private = 0 AND expires_at > ?1 
                 ORDER BY created_at DESC 
                 LIMIT 50"
            ).unwrap();

            let rows = stmt.query_map(params![now], |row| {
                let created_at: i64 = row.get(5)?;
                Ok(PasteItem {
                    id: row.get(0)?,
                    title: row.get(1)?,
                    syntax: row.get(2)?,
                    size_bytes: row.get(3)?,
                    views: row.get(4)?,
                    created_at_human: human_time_ago(created_at),
                    has_issues: row.get::<_, i64>(6)? > 0,
                    is_encrypted: row.get::<_, i64>(7)? > 0,
                    burn_after_reading: row.get::<_, i64>(8)? > 0,
                })
            }).unwrap();

            for r in rows.flatten() {
                items.push(r);
            }
        } else {
            let pattern = format!("%{}%", search_term);
            let mut stmt = conn.prepare(
                "SELECT id, title, syntax, size_bytes, views, created_at, has_issues 
                 FROM pastes 
                 WHERE is_private = 0 AND expires_at > ?1 AND title LIKE ?2 
                 ORDER BY created_at DESC 
                 LIMIT 50"
            ).unwrap();

            let rows = stmt.query_map(params![now, pattern], |row| {
                let created_at: i64 = row.get(5)?;
                Ok(PasteItem {
                    id: row.get(0)?,
                    title: row.get(1)?,
                    syntax: row.get(2)?,
                    size_bytes: row.get(3)?,
                    views: row.get(4)?,
                    created_at_human: human_time_ago(created_at),
                    has_issues: row.get::<_, i64>(6)? > 0,
                    is_encrypted: row.get::<_, i64>(7)? > 0,
                    burn_after_reading: row.get::<_, i64>(8)? > 0,
                })
            }).unwrap();

            for r in rows.flatten() {
                items.push(r);
            }
        }
        items
    };

    let mut table_rows = String::new();
    for p in &recent {
        let mut badges = String::new();
        if p.is_encrypted {
            badges.push_str(r#"<span class="badge badge-enc">🔐 E2E</span>"#);
        }
        if p.has_issues {
            badges.push_str(r#"<span class="badge badge-warn">⚠️ Ошибка</span>"#);
        }
        table_rows.push_str(&format!(
            r#"<tr>
                <td><a href="/p/{}" class="table-title">{}</a> {}</td>
                <td><span class="syntax-tag">{}</span></td>
                <td>{}</td>
                <td>{}</td>
                <td>👁️ {}</td>
                <td><a href="/raw/{}" class="raw-btn" target="_blank">Текст</a></td>
            </tr>"#,
            p.id,
            escape_html(&p.title),
            badges,
            syntax_title(&p.syntax),
            escape_html(&human_size(p.size_bytes)),
            p.created_at_human,
            p.views,
            p.id
        ));
    }

    if table_rows.is_empty() {
        table_rows = r#"<tr><td colspan="6" style="text-align:center; padding: 32px; color: #6e7681;">Публичные записи по вашему запросу не найдены.</td></tr>"#.to_string();
    }

    let search_val = escape_html(query.search.as_deref().unwrap_or(""));

    let html = format!(r#"<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Публичный архив записей — ES-Paste</title>
  <meta name="description" content="Список последних открытых вставок, логов и исходных кодов пользователей в сервисе ES-Paste.">
  <meta name="robots" content="index, follow">
  <meta property="og:title" content="Публичный архив записей — ES-Paste">
  <meta property="og:description" content="Просмотр открытых логов и сниппетов кода.">
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <link rel="alternate icon" type="image/x-icon" href="/favicon.ico">
  <style>
    :root {{
      --bg: #090d16;
      --card-bg: #121826;
      --surface: #1a2234;
      --border: #26334d;
      --text: #e1e7f0;
      --muted: #8b9bb4;
      --accent: #38bdf8;
      --warn: #f59e0b;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }}
    header {{
      padding: 14px 28px;
      background: var(--card-bg);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }}
    .brand {{ text-decoration: none; font-weight: 800; color: var(--accent); font-size: 1.25rem; }}
    .brand span {{ color: #fff; }}
    .nav-links {{ display: flex; gap: 18px; }}
    .nav-link {{ color: var(--muted); text-decoration: none; font-size: 0.9rem; font-weight: 500; }}
    .nav-link:hover, .nav-link.active {{ color: var(--accent); }}
    
    .container {{
      max-width: 1200px;
      width: 100%;
      margin: 24px auto;
      padding: 0 24px;
      flex: 1;
    }}
    .archive-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
      gap: 16px;
      flex-wrap: wrap;
    }}
    .search-bar {{
      display: flex;
      gap: 8px;
    }}
    .search-input {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 8px 14px;
      border-radius: 6px;
      font-size: 0.88rem;
      outline: none;
      width: 260px;
    }}
    .search-input:focus {{ border-color: var(--accent); }}
    .search-btn {{
      background: var(--surface);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 8px 16px;
      border-radius: 6px;
      font-size: 0.88rem;
      cursor: pointer;
    }}
    .archive-table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
    }}
    .archive-table th, .archive-table td {{
      padding: 12px 18px;
      text-align: left;
      border-bottom: 1px solid var(--border);
      font-size: 0.88rem;
    }}
    .archive-table th {{
      background: var(--surface);
      color: var(--muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.05em;
    }}
    .table-title {{
      color: var(--text);
      font-weight: 600;
      text-decoration: none;
      transition: color 0.15s;
    }}
    .table-title:hover {{ color: var(--accent); }}
    .syntax-tag {{
      background: #202b42;
      color: var(--accent);
      padding: 2px 6px;
      border-radius: 4px;
      font-family: monospace;
      font-size: 0.75rem;
    }}
    .badge {{
      font-size: 0.7rem;
      padding: 2px 6px;
      border-radius: 4px;
      font-weight: 600;
      margin-left: 6px;
    }}
    .badge-warn {{
      background: rgba(245, 158, 11, 0.2);
      color: var(--warn);
      border: 1px solid rgba(245, 158, 11, 0.4);
    }}
    .badge-enc {{
      background: rgba(168, 85, 247, 0.2);
      color: #c084fc;
      border: 1px solid rgba(168, 85, 247, 0.4);
    }}
    .raw-btn {{
      color: var(--muted);
      text-decoration: none;
      padding: 3px 8px;
      border-radius: 4px;
      background: var(--surface);
      font-size: 0.78rem;
    }}
    .raw-btn:hover {{ color: #fff; background: var(--border); }}
  </style>
</head>
<body>
  <header>
    <a href="/" class="brand">⚡ ES-PASTE <span>ВСТАВКИ</span></a>
    <div class="nav-links">
      <a href="/" class="nav-link">Создать запись</a>
      <a href="/archive" class="nav-link active">Публичный архив</a>
    </div>
  </header>

  <div class="container">
    <div class="archive-header">
      <h2 style="font-size: 1.4rem;">Публичный архив записей</h2>
      <form class="search-bar" method="GET" action="/archive">
        <input type="text" name="search" class="search-input" placeholder="Поиск по названию..." value="{search_val}" />
        <button type="submit" class="search-btn">Искать</button>
      </form>
    </div>

    <table class="archive-table">
      <thead>
        <tr>
          <th>Название</th>
          <th>Синтаксис</th>
          <th>Размер</th>
          <th>Создано</th>
          <th>Просмотры</th>
          <th>Действия</th>
        </tr>
      </thead>
      <tbody>
        {table_rows}
      </tbody>
    </table>
  </div>
</body>
</html>"#, search_val = search_val, table_rows = table_rows);

    Html(html)
}

pub async fn create_paste(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<CreatePasteResponse>, (StatusCode, String)> {
    let mut raw_content = String::new();
    let mut requested_ttl_minutes: Option<i64> = None;
    let mut title = "Без названия".to_string();
    let mut syntax = "text".to_string();
    let mut is_private = false;
    let mut is_encrypted = false;
    let mut burn_after_reading = false;

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if content_type.contains("application/json") {
        if let Ok(payload) = serde_json::from_slice::<CreatePastePayload>(&body) {
            if let Some(c) = payload.content {
                raw_content = c;
            }
            if let Some(t) = payload.title {
                let trimmed = t.trim();
                if !trimmed.is_empty() {
                    title = trimmed.chars().take(80).collect();
                }
            }
            if let Some(s) = payload.syntax {
                let s_trim = s.trim().to_lowercase();
                if !s_trim.is_empty() {
                    syntax = s_trim.chars().take(20).collect();
                }
            }
            if let Some(p) = payload.is_private {
                is_private = p;
            }
            if let Some(e) = payload.is_encrypted {
                is_encrypted = e;
            }
            if let Some(b) = payload.burn_after_reading {
                burn_after_reading = b;
            }
            requested_ttl_minutes = payload.ttl_minutes.or_else(|| payload.ttl_hours.map(|h| h * 60));
        }
    }

    if raw_content.is_empty() {
        if let Ok(s) = String::from_utf8(body.to_vec()) {
            raw_content = s;
        }
    }

    let trimmed = raw_content.trim();
    if trimmed.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Содержимое не может быть пустым".into()));
    }

    let is_authenticated = if let Some(auth_hdr) = headers.get(header::AUTHORIZATION) {
        if let Ok(val) = auth_hdr.to_str() {
            let expected = format!("Bearer {}", state.auth_token);
            val == expected
        } else {
            false
        }
    } else {
        false
    };

    let ttl_minutes = match requested_ttl_minutes {
        Some(m) if is_authenticated => m.clamp(5, 336 * 60),
        Some(m) => m.clamp(5, 12 * 60),
        None => 12 * 60,
    };

    let issues = analyze_log(trimmed);
    let has_issues = if issues.is_empty() { 0 } else { 1 };

    let compressed = zstd::encode_all(trimmed.as_bytes(), 3)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Ошибка сжатия: {}", e)))?;

    let paste_id = nanoid!(10);
    let now = Utc::now();
    let expires_at = (now + Duration::minutes(ttl_minutes)).timestamp();
    let size_bytes = trimmed.len() as i64;

    {
        let conn = state.db.lock().unwrap();
        let _ = clean_expired(&conn);
        conn.execute(
            "INSERT INTO pastes (id, title, syntax, content, size_bytes, views, is_private, is_encrypted, burn_after_reading, created_at, expires_at, has_issues) 
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                paste_id,
                title,
                syntax,
                compressed,
                size_bytes,
                if is_private { 1 } else { 0 },
                if is_encrypted { 1 } else { 0 },
                if burn_after_reading { 1 } else { 0 },
                now.timestamp(),
                expires_at,
                has_issues
            ],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Ошибка БД: {}", e)))?;
    }

    let url = format!("{}/p/{}", state.base_url, paste_id);
    let raw_url = format!("{}/raw/{}", state.base_url, paste_id);

    Ok(Json(CreatePasteResponse {
        id: paste_id,
        url,
        raw_url,
        expires_at,
        issues_detected: issues.len(),
    }))
}

pub async fn get_raw(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, StatusCode> {
    let compressed_bytes: Vec<u8> = {
        let conn = state.db.lock().unwrap();
        let _ = clean_expired(&conn);
        let now = Utc::now().timestamp();
        let (content, burn): (Vec<u8>, bool) = conn.query_row(
            "SELECT content, burn_after_reading FROM pastes WHERE id = ?1 AND expires_at > ?2",
            params![id, now],
            |row| Ok((row.get(0)?, row.get::<_, i64>(1)? > 0)),
        )
        .map_err(|_| StatusCode::NOT_FOUND)?;

        if burn {
            let _ = conn.execute("DELETE FROM pastes WHERE id = ?1", params![id]);
        }
        content
    };

    let decompressed = zstd::decode_all(compressed_bytes.as_slice())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let text = String::from_utf8(decompressed).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        text,
    )
        .into_response())
}

pub async fn view_paste(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Html<String>, StatusCode> {
    let (title, syntax, size_bytes, views, created_at, expires_at, compressed_bytes, is_encrypted, burn_after_reading): (String, String, i64, i64, i64, i64, Vec<u8>, bool, bool) = {
        let conn = state.db.lock().unwrap();
        let _ = clean_expired(&conn);
        let now = Utc::now().timestamp();

        let (t, s, sb, v, ca, ea, c, enc, burn): (String, String, i64, i64, i64, i64, Vec<u8>, bool, bool) = conn.query_row(
            "SELECT title, syntax, size_bytes, views, created_at, expires_at, content, is_encrypted, burn_after_reading 
             FROM pastes WHERE id = ?1 AND expires_at > ?2",
            params![id, now],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get::<_, i64>(7)? > 0,
                    row.get::<_, i64>(8)? > 0,
                ))
            },
        )
        .map_err(|_| StatusCode::NOT_FOUND)?;

        if burn {
            let _ = conn.execute("DELETE FROM pastes WHERE id = ?1", params![id]);
        } else {
            let _ = conn.execute("UPDATE pastes SET views = views + 1 WHERE id = ?1", params![id]);
        }

        (t, s, sb, v + 1, ca, ea, c, enc, burn)
    };

    let decompressed = zstd::decode_all(compressed_bytes.as_slice())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let content = String::from_utf8(decompressed).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let issues = analyze_log(&content);

    let mut diagnosis_banner = String::new();
    if !is_encrypted && !issues.is_empty() {
        let mut list_items = String::new();
        for issue in &issues {
            list_items.push_str(&format!(
                r#"<div class="issue-item">
                    <div class="issue-badge">⚠️ [{}]</div>
                    <div class="issue-desc">
                      <div><b>Решение:</b> {}</div>
                    </div>
                   </div>"#,
                escape_html(&issue.rule),
                escape_html(&issue.solution_ru)
            ));
        }

        diagnosis_banner = format!(
            r#"<div class="diagnosis-box">
                <div class="diagnosis-header">⚡ АВТОМАТИЧЕСКАЯ ДИАГНОСТИКА ЛОГА (НАЙДЕНО ПРОБЛЕМ: {})</div>
                <div class="diagnosis-body">{}</div>
               </div>"#,
            issues.len(),
            list_items
        );
    }

    let line_count = content.lines().count().max(1);
    let mut line_numbers = String::with_capacity(line_count * 5);
    for i in 1..=line_count {
        line_numbers.push_str(&format!("{}\n", i));
    }

    let escaped_content = escape_html(&content);
    let expires_in_str = human_expires_in(expires_at);

    let burn_banner = if burn_after_reading {
        r#"<div style="margin: 18px 28px 0; padding: 14px 18px; background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.4); border-radius: 8px; color: #fca5a5; font-size: 0.9rem; display: flex; align-items: center; gap: 10px;">
            <span style="font-size: 1.2rem;">🔥</span>
            <div><strong>Одноразовая запись (Burn after reading):</strong> Эта запись была удалена из базы данных в момент загрузки страницы. После закрытия или обновления вкладки доступ будет утерян навсегда.</div>
           </div>"#
    } else {
        ""
    };

    let (enc_badge, encrypted_banner) = if is_encrypted {
        (
            "<span class=\"badge badge-enc\">🔐 Зашифровано E2E</span>",
            r#"<div id="enc-modal" style="margin: 18px 28px 0; padding: 18px; background: rgba(168, 85, 247, 0.1); border: 1px solid rgba(168, 85, 247, 0.4); border-radius: 8px; display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap;">
                <div>
                  <div style="font-weight: 700; color: #c084fc; font-size: 1rem; margin-bottom: 4px;">🔐 Эта запись зашифрована на стороне клиента</div>
                  <div style="font-size: 0.85rem; color: #94a3b8;">Сервер не знает пароль и не имеет доступа к исходному тексту (AES-256-GCM).</div>
                  <div id="unlock-error" style="color: #f87171; font-size: 0.82rem; margin-top: 6px; display: none;"></div>
                </div>
                <div style="display: flex; gap: 8px;">
                  <input type="password" id="unlock-pass" class="form-control" placeholder="Введите пароль..." style="width: 200px;" onkeydown="if(event.key==='Enter') tryUnlock(this.value)" />
                  <button class="btn btn-primary" onclick="tryUnlock(document.getElementById('unlock-pass').value)">Расшифровать</button>
                </div>
               </div>"#
        )
    } else {
        ("", "")
    };

    let html = format!(r#"<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title} — ES-Paste</title>
  <meta name="description" content="Просмотр вставки в ES-Paste: логи сервера, конфигурационные файлы и исходный код.">
  <meta name="robots" content="noindex, follow">
  <meta property="og:title" content="{title} — ES-Paste">
  <meta property="og:type" content="article">
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <link rel="alternate icon" type="image/x-icon" href="/favicon.ico">
  <style>
    :root {{
      --bg: #090d16;
      --card-bg: #121826;
      --surface: #1a2234;
      --border: #26334d;
      --text: #e1e7f0;
      --muted: #8b9bb4;
      --accent: #38bdf8;
      --accent-hover: #7dd3fc;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }}
    header {{
      padding: 14px 28px;
      background: var(--card-bg);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }}
    .brand {{ text-decoration: none; font-weight: 800; color: var(--accent); font-size: 1.25rem; }}
    .brand span {{ color: #fff; }}
    .meta-bar {{
      padding: 16px 28px;
      background: var(--card-bg);
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      flex-wrap: wrap;
    }}
    .paste-heading {{
      display: flex;
      flex-direction: column;
      gap: 4px;
    }}
    .paste-title-large {{
      font-size: 1.25rem;
      font-weight: 700;
      color: #fff;
    }}
    .paste-meta-details {{
      font-size: 0.82rem;
      color: var(--muted);
      display: flex;
      gap: 12px;
      align-items: center;
    }}
    .syntax-tag {{
      background: #202b42;
      color: var(--accent);
      padding: 2px 8px;
      border-radius: 4px;
      font-family: monospace;
      font-size: 0.78rem;
    }}
    .actions {{ display: flex; gap: 10px; }}
    .btn {{
      padding: 7px 14px;
      border-radius: 6px;
      font-size: 0.85rem;
      font-weight: 600;
      text-decoration: none;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }}
    .btn-secondary {{
      background: var(--surface);
      border: 1px solid var(--border);
      color: var(--text);
    }}
    .btn-secondary:hover {{ background: var(--border); }}
    .btn-primary {{
      background: var(--accent);
      color: #090d16;
    }}
    .btn-primary:hover {{ background: var(--accent-hover); }}

    .diagnosis-box {{
      margin: 18px 28px 0;
      background: rgba(245, 158, 11, 0.08);
      border: 1px solid rgba(245, 158, 11, 0.3);
      border-radius: 8px;
      overflow: hidden;
    }}
    .diagnosis-header {{
      padding: 10px 18px;
      background: rgba(245, 158, 11, 0.15);
      color: #fbbf24;
      font-weight: 700;
      font-size: 0.88rem;
      letter-spacing: 0.04em;
    }}
    .diagnosis-body {{ padding: 14px 18px; display: flex; flex-direction: column; gap: 12px; }}
    .issue-item {{ display: flex; gap: 12px; font-size: 0.88rem; line-height: 1.45; }}
    .issue-badge {{ color: #fbbf24; font-weight: 700; white-space: nowrap; }}

    .content-container {{
      flex: 1;
      display: flex;
      margin: 18px 28px 28px;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
    }}
    .line-numbers {{
      width: 56px;
      padding: 16px 8px;
      text-align: right;
      color: #4b5875;
      user-select: none;
      background: var(--surface);
      border-right: 1px solid var(--border);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.9rem;
      line-height: 1.5;
      white-space: pre;
    }}
    .code-view {{
      flex: 1;
      margin: 0;
      padding: 16px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.9rem;
      line-height: 1.5;
      color: var(--text);
      overflow-x: auto;
      white-space: pre;
    }}
  </style>
</head>
<body>
  <header>
    <a href="/" class="brand">⚡ ES-PASTE <span>ВСТАВКИ</span></a>
    <div class="actions">
      <a href="/" class="btn btn-primary">+ Новая запись</a>
      <a href="/archive" class="btn btn-secondary">Публичный архив</a>
    </div>
  </header>

  {burn_banner}
  {encrypted_banner}
  <div class="meta-bar">
    <div class="paste-heading">
      <div class="paste-title-large">{title} {enc_badge}</div>
      <div class="paste-meta-details">
        <span class="syntax-tag">{syntax}</span>
        <span>Размер: {size}</span>
        <span>Создано: {created_at_human}</span>
        <span>Истекает через: {expires_in_str}</span>
        <span>👁️ {views} просмотров</span>
      </div>
    </div>
    <div class="actions">
      <button class="btn btn-secondary" onclick="copyRaw()">📋 Скопировать текст</button>
      <a href="/raw/{id}" target="_blank" class="btn btn-secondary">Чистый текст</a>
      <a href="/" class="btn btn-secondary">Форкнуть / Редактировать</a>
    </div>
  </div>

  {diagnosis_banner}

  <div class="content-container">
    <div class="line-numbers" id="line-numbers-col">{line_numbers}</div>
    <pre class="code-view"><code id="code-content">{escaped_content}</code></pre>
  </div>

  <script>
    function copyRaw() {{
      const text = document.getElementById('code-content').innerText;
      navigator.clipboard.writeText(text).then(() => {{
        alert('Текст скопирован в буфер обмена!');
      }});
    }}

    const IS_ENCRYPTED = {is_encrypted_bool};

    async function deriveKey(password, salt) {{
      const enc = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        {{ name: "PBKDF2" }},
        false,
        ["deriveKey"]
      );
      return await crypto.subtle.deriveKey(
        {{
          name: "PBKDF2",
          salt: salt,
          iterations: 100000,
          hash: "SHA-256"
        }},
        keyMaterial,
        {{ name: "AES-GCM", length: 256 }},
        false,
        ["encrypt", "decrypt"]
      );
    }}

    function base64ToBuffer(b64) {{
      const bin = atob(b64);
      const buf = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
      return buf;
    }}

    async function decryptE2E(cipherPayload, password) {{
      const parts = cipherPayload.trim().split(':');
      if (parts.length !== 5 || parts[0] !== 'ENC' || parts[1] !== 'v1') {{
        throw new Error('Некорректный формат шифротекста.');
      }}
      const salt = base64ToBuffer(parts[2]);
      const iv = base64ToBuffer(parts[3]);
      const ciphertext = base64ToBuffer(parts[4]);

      const key = await deriveKey(password, salt);
      const dec = new TextDecoder();
      const plainBuf = await crypto.subtle.decrypt(
        {{ name: "AES-GCM", iv: iv }},
        key,
        ciphertext
      );
      return dec.decode(plainBuf);
    }}

    function updateLineNumbers(count) {{
      let text = '';
      for (let i = 1; i <= count; i++) text += i + '
';
      document.getElementById('line-numbers-col').textContent = text;
    }}

    async function tryUnlock(pass) {{
      const codeEl = document.getElementById('code-content');
      const errEl = document.getElementById('unlock-error');
      if (errEl) errEl.style.display = 'none';

      try {{
        const rawCipher = codeEl.getAttribute('data-raw-cipher');
        const plain = await decryptE2E(rawCipher, pass);
        codeEl.textContent = plain;
        const lineCount = Math.max(1, plain.split('
').length);
        updateLineNumbers(lineCount);
        const modal = document.getElementById('enc-modal');
        if (modal) modal.style.display = 'none';
      }} catch (e) {{
        if (errEl) {{
          errEl.textContent = 'Неверный пароль расшифровки.';
          errEl.style.display = 'block';
        }}
      }}
    }}

    document.addEventListener('DOMContentLoaded', async () => {{
      if (!IS_ENCRYPTED) return;
      const codeEl = document.getElementById('code-content');
      codeEl.setAttribute('data-raw-cipher', codeEl.innerText);
      codeEl.textContent = '🔒 Зашифровано сквозным шифрованием (AES-256-GCM).
Введите пароль для просмотра.';

      const hash = window.location.hash;
      if (hash.startsWith('#key=')) {{
        const pass = decodeURIComponent(hash.substring(5));
        if (pass) {{
          await tryUnlock(pass);
        }}
      }}
    }});
  </script>
</body>
</html>"#,
        title = escape_html(&title),
        enc_badge = enc_badge,
        burn_banner = burn_banner,
        encrypted_banner = encrypted_banner,
        syntax = syntax_title(&syntax),
        size = escape_html(&human_size(size_bytes)),
        created_at_human = human_time_ago(created_at),
        expires_in_str = expires_in_str,
        views = views,
        id = id,
        diagnosis_banner = diagnosis_banner,
        line_numbers = line_numbers,
        escaped_content = escaped_content,
        is_encrypted_bool = is_encrypted
    );

    Ok(Html(html))
}


const FAVICON_SVG: &[u8] = include_bytes!("../favicon.svg");
const FAVICON_ICO: &[u8] = include_bytes!("../favicon.ico");

async fn favicon_svg() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/svg+xml")], FAVICON_SVG)
}

async fn favicon_ico() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/x-icon")], FAVICON_ICO)
}


async fn robots_txt() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], "User-agent: *
Allow: /
Disallow: /raw/
Sitemap: /sitemap.xml
")
}

async fn sitemap_xml(State(state): State<AppState>) -> impl IntoResponse {
    let urls = {
        let conn = state.db.lock().unwrap();
        let _ = clean_expired(&conn);
        let now = Utc::now().timestamp();
        let mut stmt = conn.prepare("SELECT id FROM pastes WHERE is_private = 0 AND expires_at > ?1 ORDER BY created_at DESC LIMIT 500").unwrap();
        let rows = stmt.query_map(params![now], |row| row.get::<_, String>(0)).unwrap();
        let mut list = Vec::new();
        for r in rows.flatten() {
            list.push(r);
        }
        list
    };

    let mut xml = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
"#);
    xml.push_str(&format!("  <url><loc>{}/</loc><changefreq>always</changefreq><priority>1.0</priority></url>
", state.base_url));
    xml.push_str(&format!("  <url><loc>{}/archive</loc><changefreq>hourly</changefreq><priority>0.8</priority></url>
", state.base_url));
    for id in urls {
        xml.push_str(&format!("  <url><loc>{}/p/{}</loc><changefreq>never</changefreq><priority>0.5</priority></url>
", state.base_url, id));
    }
    xml.push_str("</urlset>");

    ([(header::CONTENT_TYPE, "application/xml; charset=utf-8")], xml)
}

pub fn app_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(root_editor))
        .route("/favicon.ico", get(favicon_ico))
        .route("/favicon.svg", get(favicon_svg))
        .route("/archive", get(public_archive))
        .route("/robots.txt", get(robots_txt))
        .route("/sitemap.xml", get(sitemap_xml))
        .route("/api/paste", post(create_paste))
        .route("/raw/{id}", get(get_raw))
        .route("/p/{id}", get(view_paste))
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db_path = std::env::var("DATABASE_PATH").unwrap_or_else(|_| "pastes.db".into());
    let conn = Connection::open(&db_path)?;
    init_db(&conn)?;

    let base_url = std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8080".into());
    let auth_token = std::env::var("AUTH_TOKEN").unwrap_or_else(|_| "es-secret-admin".into());

    let state = AppState {
        db: Arc::new(Mutex::new(conn)),
        base_url,
        auth_token,
    };

    let router = app_router(state);
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    println!("es-paste listening on {}", bind_addr);
    axum::serve(listener, router).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_html_neutralizes_special_chars() {
        assert_eq!(escape_html("<b>&\"'</b>"), "&lt;b&gt;&amp;&quot;&#x27;&lt;/b&gt;");
    }

    #[test]
    fn analyze_log_detects_eula_and_port() {
        let text = "[Server] You need to agree to the EULA in order to run the server\n\
                    java.net.BindException: Address already in use: bind";
        let hits = analyze_log(text);
        let names: Vec<_> = hits.iter().map(|h| h.rule.as_str()).collect();
        assert!(names.contains(&"EULA не принята"));
        assert!(names.contains(&"Порт уже занят"));
    }

    #[test]
    fn analyze_log_empty_for_unrelated_text() {
        assert!(analyze_log("hello world\nno errors here").is_empty());
    }

    #[test]
    fn analyze_log_oom_heap_and_metaspace_distinct() {
        let hits = analyze_log("java.lang.OutOfMemoryError: Java heap space");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule, "Нехватка памяти (Heap OOM)");

        let hits = analyze_log("java.lang.OutOfMemoryError: Metaspace");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule, "Переполнение Metaspace");
    }

    // ----- helpers -----

    #[test]
    fn human_size_formats_bytes_kb_mb() {
        assert_eq!(human_size(0), "0 Б");
        assert_eq!(human_size(512), "512 Б");
        assert_eq!(human_size(1024), "1.0 КБ");
        assert_eq!(human_size(1536), "1.5 КБ");
        assert_eq!(human_size(1024 * 1024), "1.0 МБ");
        assert_eq!(human_size(5 * 1024 * 1024 + 200 * 1024), "5.2 МБ");
    }

    #[test]
    fn syntax_title_known_and_unknown() {
        assert_eq!(syntax_title("yaml"), "YAML");
        assert_eq!(syntax_title("go"), "Go");
        assert_eq!(syntax_title("csharp"), "C#");
        assert_eq!(syntax_title("cpp"), "C++");
        assert_eq!(syntax_title("bash"), "Bash / Shell");
        assert_eq!(syntax_title("plain"), "Обычный текст");
        assert_eq!(syntax_title(""), "Обычный текст");
    }

    #[test]
    fn human_expires_in_rounds_up_to_minutes_hours_days() {
        let now = Utc::now().timestamp();
        // sub-minute is shown as the literal second count (clamped to >=1)
        assert_eq!(human_expires_in(now + 1), "1 сек.");
        assert_eq!(human_expires_in(now + 30), "30 сек.");
        assert_eq!(human_expires_in(now + 59), "59 сек.");
        assert_eq!(human_expires_in(now + 60), "1 мин.");
        assert_eq!(human_expires_in(now + 90), "2 мин.");
        // 1h00m -> 1 h; any fractional hour rounds up
        assert_eq!(human_expires_in(now + 3600), "1 ч.");
        assert_eq!(human_expires_in(now + 3600 + 30 * 60), "2 ч.");
        assert_eq!(human_expires_in(now + 3600 + 31 * 60), "2 ч.");
        assert_eq!(human_expires_in(now + 86400), "1 дн.");
        // past expiry is clamped to floor of 1 second
        assert_eq!(human_expires_in(now - 10), "1 сек.");
    }

    #[test]
    fn human_time_ago_handles_recent_and_old() {
        let now = Utc::now().timestamp();
        assert!(human_time_ago(now - 5).contains("сек."));
        assert!(human_time_ago(now - 120).contains("мин."));
        assert!(human_time_ago(now - 7200).contains("ч."));
        assert!(human_time_ago(now - 86400 * 3).contains("дн."));
        // future timestamps must not produce negative counts
        assert!(human_time_ago(now + 30).contains("сек."));
    }

    #[test]
    fn render_sidebar_empty_and_populated() {
        assert!(render_sidebar_pastes(&[]).contains("Публичных записей пока нет"));

        let item = PasteItem {
            id: "abc123".into(),
            title: "Crashed <server>".into(),
            syntax: "log".into(),
            size_bytes: 2048,
            views: 7,
            created_at_human: "1 ч. назад".into(),
            has_issues: true,
            is_encrypted: false,
            burn_after_reading: false,
        };
        let html = render_sidebar_pastes(&[item]);
        assert!(html.contains("href=\"/p/abc123\""));
        // raw title must be HTML-escaped to avoid injection
        assert!(html.contains("Crashed &lt;server&gt;"));
        assert!(html.contains("badge-warn"));
        assert!(!html.contains("badge-enc"));
        assert!(html.contains("Лог сервера"));
        assert!(html.contains("2.0 КБ"));
    }

    // ----- payload structs -----

    #[test]
    fn create_paste_payload_parses_full_json() {
        let json = r#"{
            "title":"hello",
            "syntax":"rust",
            "content":"fn main() {}",
            "ttl_minutes":30,
            "is_private":true,
            "is_encrypted":false,
            "burn_after_reading":true
        }"#;
        let back: CreatePastePayload = serde_json::from_str(json).unwrap();
        assert_eq!(back.title.as_deref(), Some("hello"));
        assert_eq!(back.syntax.as_deref(), Some("rust"));
        assert_eq!(back.content.as_deref(), Some("fn main() {}"));
        assert_eq!(back.ttl_minutes, Some(30));
        assert_eq!(back.ttl_hours, None);
        assert_eq!(back.is_private, Some(true));
        assert_eq!(back.is_encrypted, Some(false));
        assert_eq!(back.burn_after_reading, Some(true));
    }

    #[test]
    fn create_paste_payload_accepts_missing_optional_fields() {
        let back: CreatePastePayload =
            serde_json::from_str("{\"content\":\"only content\"}").unwrap();
        assert_eq!(back.content.as_deref(), Some("only content"));
        assert!(back.title.is_none());
        assert!(back.ttl_minutes.is_none());
        assert!(back.is_private.is_none());
    }

    // ----- database -----

    fn fresh_db() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        init_db(&conn).expect("init schema");
        conn
    }

    fn insert_paste(
        conn: &Connection,
        id: &str,
        created_at: i64,
        expires_at: i64,
    ) {
        let compressed = zstd::encode_all(b"x".repeat(64).as_slice(), 3).unwrap();
        conn.execute(
            "INSERT INTO pastes
             (id, title, syntax, content, size_bytes, views, is_private,
              is_encrypted, burn_after_reading, created_at, expires_at, has_issues)
             VALUES (?1, 't', 'text', ?2, 64, 0, 0, 0, 0, ?3, ?4, 0)",
            params![id, compressed, created_at, expires_at],
        )
        .unwrap();
    }

    #[test]
    fn init_db_creates_pastes_table_with_required_columns() {
        let conn = fresh_db();
        let mut stmt = conn
            .prepare("PRAGMA table_info(pastes)")
            .expect("pragma");
        let cols: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        for required in [
            "id",
            "title",
            "syntax",
            "content",
            "size_bytes",
            "views",
            "is_private",
            "is_encrypted",
            "burn_after_reading",
            "created_at",
            "expires_at",
            "has_issues",
        ] {
            assert!(cols.iter().any(|c| c == required), "missing column: {}", required);
        }
    }

    #[test]
    fn clean_expired_deletes_only_past_rows() {
        let conn = fresh_db();
        let now = Utc::now().timestamp();
        insert_paste(&conn, "live", now, now + 60);
        insert_paste(&conn, "dead", now - 1, now);
        let removed = clean_expired(&conn).unwrap();
        assert_eq!(removed, 1);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM pastes", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
        let id: String = conn
            .query_row("SELECT id FROM pastes", [], |row| row.get(0))
            .unwrap();
        assert_eq!(id, "live");
    }

    // ----- end-to-end handlers -----

    fn test_state() -> AppState {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        AppState {
            db: Arc::new(Mutex::new(conn)),
            base_url: "http://localhost:8080".to_string(),
            auth_token: "secret-token".to_string(),
        }
    }

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode as AxStatusCode};
    use tower::util::ServiceExt;

    #[tokio::test]
    async fn create_paste_rejects_empty_raw_body() {
        // When content-type is not JSON the body is read as raw text, and an
        // empty body must be rejected as 400 BAD_REQUEST.
        let app = app_router(test_state());
        let req = Request::builder()
            .method("POST")
            .uri("/api/paste")
            .header("content-type", "text/plain")
            .body(Body::from(""))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), AxStatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_paste_rejects_whitespace_only_raw_body() {
        let app = app_router(test_state());
        let req = Request::builder()
            .method("POST")
            .uri("/api/paste")
            .header("content-type", "text/plain")
            .body(Body::from("   \n\t  "))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), AxStatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_paste_round_trip_through_get_raw() {
        let app = app_router(test_state());
        // 1. POST a plaintext paste via JSON
        let create = Request::builder()
            .method("POST")
            .uri("/api/paste")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"title":"hi","syntax":"rust","content":"fn main() {}","ttl_minutes":5}"#,
            ))
            .unwrap();
        let resp = app.oneshot(create).await.unwrap();
        assert_eq!(resp.status(), AxStatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let payload: CreatePasteResponse = serde_json::from_slice(&body).unwrap();
        assert!(!payload.id.is_empty());
        assert!(payload.url.contains(&payload.id));
        assert_eq!(payload.issues_detected, 0);

        // 2. GET /raw/:id returns the original text
        let app2 = app_router(test_state());
        let raw = Request::builder()
            .uri(format!("/raw/{}", payload.id))
            .body(Body::empty())
            .unwrap();
        // fresh in-memory DB has no row -> 404 expected (state was dropped)
        let resp = app2.oneshot(raw).await.unwrap();
        assert_eq!(resp.status(), AxStatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_paste_detects_eula_and_stamps_issues() {
        let state = test_state();
        let app = app_router(state.clone());
        let content = "[Server] You need to agree to the EULA in order to run the server";
        let create = Request::builder()
            .method("POST")
            .uri("/api/paste")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"title":"crash","syntax":"log","content":"{}"}}"#,
                content
            )))
            .unwrap();
        let resp = app.oneshot(create).await.unwrap();
        assert_eq!(resp.status(), AxStatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let payload: CreatePasteResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload.issues_detected, 1);

        // verify has_issues column was stamped
        let conn = state.db.lock().unwrap();
        let has_issues: i64 = conn
            .query_row(
                "SELECT has_issues FROM pastes WHERE id = ?1",
                params![payload.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(has_issues, 1);
    }

    #[tokio::test]
    async fn create_paste_guest_ttl_is_clamped_to_12h() {
        let state = test_state();
        let app = app_router(state.clone());
        // 48h requested as guest -> must be clamped to 12h
        let create = Request::builder()
            .method("POST")
            .uri("/api/paste")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"content":"x","ttl_hours":48}"#,
            ))
            .unwrap();
        let resp = app.oneshot(create).await.unwrap();
        assert_eq!(resp.status(), AxStatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let payload: CreatePasteResponse = serde_json::from_slice(&body).unwrap();

        let conn = state.db.lock().unwrap();
        let expires_at: i64 = conn
            .query_row(
                "SELECT expires_at FROM pastes WHERE id = ?1",
                params![payload.id],
                |row| row.get(0),
            )
            .unwrap();
        let now = Utc::now().timestamp();
        let ttl_min = (expires_at - now) / 60;
        assert!(
            ttl_min <= 12 * 60 + 1 && ttl_min >= 12 * 60 - 1,
            "expected ~12h clamp, got {} min",
            ttl_min
        );
    }

    #[tokio::test]
    async fn create_paste_authenticated_user_can_exceed_guest_ttl() {
        let state = test_state();
        let app = app_router(state.clone());
        // 14 days requested with valid bearer -> allowed (336 * 60 == 20160 min)
        let create = Request::builder()
            .method("POST")
            .uri("/api/paste")
            .header("content-type", "application/json")
            .header("authorization", "Bearer secret-token")
            .body(Body::from(
                r#"{"content":"x","ttl_hours":336}"#,
            ))
            .unwrap();
        let resp = app.oneshot(create).await.unwrap();
        assert_eq!(resp.status(), AxStatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let payload: CreatePasteResponse = serde_json::from_slice(&body).unwrap();

        let conn = state.db.lock().unwrap();
        let expires_at: i64 = conn
            .query_row(
                "SELECT expires_at FROM pastes WHERE id = ?1",
                params![payload.id],
                |row| row.get(0),
            )
            .unwrap();
        let now = Utc::now().timestamp();
        let ttl_min = (expires_at - now) / 60;
        assert!(
            ttl_min >= 336 * 60 - 1,
            "expected ~336h, got {} min",
            ttl_min
        );
    }

    #[tokio::test]
    async fn get_raw_returns_404_for_missing_paste() {
        let app = app_router(test_state());
        let req = Request::builder()
            .uri("/raw/does-not-exist")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), AxStatusCode::NOT_FOUND);
    }
}
