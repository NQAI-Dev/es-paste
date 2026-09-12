use std::sync::{Arc, Mutex};
use axum::{
    body::Bytes,
    extract::{Path, State},
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Issue {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub cause: String,
    pub solution: String,
}

pub struct Rule {
    pub id: &'static str,
    pub pattern: Regex,
    pub title: &'static str,
    pub severity: &'static str,
    pub cause: &'static str,
    pub solution: &'static str,
}

pub fn get_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "eula_not_accepted",
            pattern: Regex::new(r"(?i)You need to agree to the EULA in order to run the server").unwrap(),
            title: "Не принято соглашение EULA",
            severity: "CRITICAL",
            cause: "В файле eula.txt параметр eula установлен в false.",
            solution: "Откройте файловый менеджер в панели Mars Host, найдите eula.txt и смените на eula=true.",
        },
        Rule {
            id: "port_bind_failure",
            pattern: Regex::new(r"(?i)(FAILED TO BIND TO PORT|Address already in use: bind|BindException: Address already in use)").unwrap(),
            title: "Порт уже занят (Port Bind Failure)",
            severity: "CRITICAL",
            cause: "Выделенный порт сервера занят зависшим процессом или контейнером.",
            solution: "1. Перезапустите сервер через панель управления.\n2. Проверьте параметр server-port в server.properties.",
        },
        Rule {
            id: "java_version_mismatch",
            pattern: Regex::new(r"(?i)has been compiled by a more recent version of the Java Runtime \(class file version (\d+\.\d+)\), this version of the Java Runtime only recognizes class file versions up to (\d+\.\d+)").unwrap(),
            title: "Несовместимость версии Java",
            severity: "CRITICAL",
            cause: "Ядро или плагин требуют более свежую версию Java Runtime.",
            solution: "В настройках сервера в панели Mars Host выберите Java 21 (или требуемую версию).",
        },
        Rule {
            id: "oom_heap",
            pattern: Regex::new(r"(?i)(java\.lang\.OutOfMemoryError:\s*Java heap space|Out of memory: Kill process)").unwrap(),
            title: "Нехватка оперативной памяти (Heap OOM)",
            severity: "CRITICAL",
            cause: "Сервер потребил всю выделенную оперативную память (Heap Space).",
            solution: "1. Увеличьте объем RAM кнопкой 'Улучшить' в панели Mars Host.\n2. Уменьшите view-distance до 4-6 чанков или удалите ресурсоемкие плагины.",
        },
        Rule {
            id: "oom_metaspace",
            pattern: Regex::new(r"(?i)java\.lang\.OutOfMemoryError:\s*Metaspace").unwrap(),
            title: "Переполнение памяти классов (Metaspace)",
            severity: "CRITICAL",
            cause: "Загружено слишком много классов плагинов, исчерпан лимит Metaspace JVM.",
            solution: "Удалите избыточные плагины или увеличьте лимит RAM сервера.",
        },
        Rule {
            id: "missing_plugin_dependency",
            pattern: Regex::new(r"(?i)(?:Could not load '[^']*' in folder 'plugins'|UnknownDependencyException|Plugin '[^']+' requires|depends on: )").unwrap(),
            title: "Отсутствует зависимость плагина",
            severity: "ERROR",
            cause: "Плагин требует наличие базовой библиотеки (Vault, ProtocolLib, PlaceholderAPI и др.).",
            solution: "Установите недостающие зависимые плагины через вкладку 'Плагины' в панели управления.",
        },
        Rule {
            id: "corrupted_chunk",
            pattern: Regex::new(r"(?i)(Chunk file at .*? is in the wrong location|Corrupt chunk detected|RegionFileException|Corrupted chunk data)").unwrap(),
            title: "Повреждение файлов мира (Corrupted Region)",
            severity: "CRITICAL",
            cause: "Аварийная остановка повредила .mca файл региона карты.",
            solution: "1. Восстановите мир из бэкапа в панели Mars Host.\n2. Либо удалите поврежденный файл региона из папки world/region/.",
        },
        Rule {
            id: "sqlite_db_locked",
            pattern: Regex::new(r"(?i)(database is locked|sqlite3\.OperationalError:\s*database is locked)").unwrap(),
            title: "База данных заблокирована (SQLite Lock)",
            severity: "ERROR",
            cause: "Параллельные потоки плагинов заблокировали файл SQLite.",
            solution: "Перезапустите сервер или переключите плагины на внешний MySQL/PostgreSQL.",
        },
    ]
}

pub fn analyze_log(text: &str) -> Vec<Issue> {
    let rules = get_rules();
    let mut issues = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for rule in &rules {
        if seen.contains(rule.id) {
            continue;
        }
        if rule.pattern.is_match(text) {
            seen.insert(rule.id);
            issues.push(Issue {
                id: rule.id.to_string(),
                title: rule.title.to_string(),
                severity: rule.severity.to_string(),
                cause: rule.cause.to_string(),
                solution: rule.solution.to_string(),
            });
        }
    }
    issues
}

pub fn init_db(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS pastes (
            id TEXT PRIMARY KEY,
            content BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            has_issues INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_expires_at ON pastes(expires_at);",
    )
}

pub fn clean_expired(conn: &Connection) -> rusqlite::Result<usize> {
    let now = Utc::now().timestamp();
    conn.execute("DELETE FROM pastes WHERE expires_at <= ?1", params![now])
}

#[derive(Deserialize)]
pub struct CreatePastePayload {
    pub content: Option<String>,
    pub ttl_hours: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct CreatePasteResponse {
    pub id: String,
    pub url: String,
    pub raw_url: String,
    pub expires_at: i64,
    pub issues_detected: usize,
}

pub async fn root_editor() -> Html<&'static str> {
    Html(r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ES-Paste - Minimal Log Vault</title>
  <style>
    :root {
      --bg: #0d1117;
      --surface: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --accent: #58a6ff;
      --accent-hover: #79c0ff;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      padding: 12px 24px;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .logo {
      font-weight: 700;
      color: var(--accent);
      font-size: 1.15rem;
      letter-spacing: 0.05em;
    }
    .actions { display: flex; gap: 12px; align-items: center; }
    select, button, input {
      background: var(--bg);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 6px 14px;
      border-radius: 6px;
      font-family: inherit;
      font-size: 0.88rem;
    }
    button {
      background: #238636;
      border-color: #2ea043;
      color: #fff;
      cursor: pointer;
      font-weight: 600;
    }
    button:hover { background: #2ea043; }
    .editor-container {
      flex: 1;
      display: flex;
      position: relative;
    }
    .line-numbers {
      width: 48px;
      padding: 16px 8px;
      text-align: right;
      color: #484f58;
      user-select: none;
      background: var(--surface);
      border-right: 1px solid var(--border);
      font-size: 0.9rem;
      line-height: 1.5;
      overflow: hidden;
      white-space: pre;
    }
    textarea {
      flex: 1;
      background: transparent;
      border: none;
      color: var(--text);
      padding: 16px;
      font-family: inherit;
      font-size: 0.9rem;
      line-height: 1.5;
      resize: none;
      outline: none;
      tab-size: 4;
      white-space: pre;
    }
    footer {
      padding: 8px 24px;
      font-size: 0.8rem;
      color: #8b949e;
      border-top: 1px solid var(--border);
      background: var(--surface);
      display: flex;
      justify-content: space-between;
    }
  </style>
</head>
<body>
  <header>
    <div class="logo">⚡ ES-PASTE // LOG VAULT</div>
    <div class="actions">
      <select id="ttl">
        <option value="1">1 Hour</option>
        <option value="12" selected>12 Hours (Guest default)</option>
        <option value="24">24 Hours</option>
        <option value="72">3 Days</option>
        <option value="336">14 Days (Auth max)</option>
      </select>
      <input type="password" id="token" placeholder="Optional token" style="width: 130px;" />
      <button onclick="submitPaste()">Save Paste</button>
    </div>
  </header>
  <div class="editor-container">
    <div class="line-numbers" id="lines">1</div>
    <textarea id="code" placeholder="Paste server logs, stack traces, configs..." oninput="updateLines()" autofocus></textarea>
  </div>
  <footer>
    <span>ESCloud Minimal Monospace Vault</span>
    <span>Axum + SQLite + Zstandard</span>
  </footer>
  <script>
    const ta = document.getElementById('code');
    const lines = document.getElementById('lines');
    function updateLines() {
      const count = ta.value.split('\n').length;
      let text = '';
      for (let i = 1; i <= count; i++) text += i + '\n';
      lines.textContent = text;
    }
    async function submitPaste() {
      const content = ta.value.trim();
      if (!content) return alert('Cannot save empty paste.');
      const ttl = parseInt(document.getElementById('ttl').value, 10);
      const token = document.getElementById('token').value;
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = 'Bearer ' + token;
      
      const res = await fetch('/api/paste', {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({ content: content, ttl_hours: ttl })
      });
      if (res.ok) {
        const data = await res.json();
        window.location.href = '/p/' + data.id;
      } else {
        const err = await res.text();
        alert('Error: ' + err);
      }
    }
    updateLines();
  </script>
</body>
</html>"#)
}

pub async fn create_paste(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<CreatePasteResponse>, (StatusCode, String)> {
    let mut raw_content = String::new();
    let mut requested_ttl_hours: Option<i64> = None;

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if content_type.contains("application/json") {
        if let Ok(payload) = serde_json::from_slice::<CreatePastePayload>(&body) {
            if let Some(c) = payload.content {
                raw_content = c;
            }
            requested_ttl_hours = payload.ttl_hours;
        }
    }

    if raw_content.is_empty() {
        raw_content = String::from_utf8(body.to_vec())
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid UTF-8 content".into()))?;
    }

    if raw_content.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Content cannot be empty".into()));
    }

    let is_authed = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|auth| {
            let token = auth.strip_prefix("Bearer ").unwrap_or(auth);
            token == state.auth_token
        })
        .unwrap_or(false);

    let max_ttl_hours = if is_authed { 14 * 24 } else { 12 };
    let final_ttl_hours = match requested_ttl_hours {
        Some(h) if h > 0 => h.min(max_ttl_hours),
        _ => if is_authed { 14 * 24 } else { 12 },
    };

    let issues = analyze_log(&raw_content);
    let has_issues = if !issues.is_empty() { 1 } else { 0 };

    let compressed = zstd::encode_all(raw_content.as_bytes(), 3)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Compression error: {}", e)))?;

    let id = nanoid!(8);
    let now = Utc::now();
    let created_at = now.timestamp();
    let expires_at = (now + Duration::hours(final_ttl_hours)).timestamp();

    {
        let conn = state.db.lock().unwrap();
        conn.execute(
            "INSERT INTO pastes (id, content, created_at, expires_at, has_issues) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, compressed, created_at, expires_at, has_issues],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB insert error: {}", e)))?;
    }

    let url = format!("{}/p/{}", state.base_url, id);
    let raw_url = format!("{}/raw/{}", state.base_url, id);

    Ok(Json(CreatePasteResponse {
        id,
        url,
        raw_url,
        expires_at,
        issues_detected: issues.len(),
    }))
}

pub async fn get_raw(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    let (compressed, expires_at): (Vec<u8>, i64) = {
        let conn = state.db.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT content, expires_at FROM pastes WHERE id = ?1")
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        stmt.query_row(params![id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|_| (StatusCode::NOT_FOUND, "Paste not found".into()))?
    };

    if Utc::now().timestamp() > expires_at {
        return Err((StatusCode::NOT_FOUND, "Paste has expired".into()));
    }

    let decompressed = zstd::decode_all(compressed.as_slice())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Decompress error: {}", e)))?;

    Ok((
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        decompressed,
    ).into_response())
}

pub async fn view_paste(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Html<String>, (StatusCode, String)> {
    let (compressed, expires_at): (Vec<u8>, i64) = {
        let conn = state.db.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT content, expires_at FROM pastes WHERE id = ?1")
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        stmt.query_row(params![id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|_| (StatusCode::NOT_FOUND, "Paste not found".into()))?
    };

    if Utc::now().timestamp() > expires_at {
        return Err((StatusCode::NOT_FOUND, "Paste has expired".into()));
    }

    let decompressed = zstd::decode_all(compressed.as_slice())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Decompress error: {}", e)))?;
    let content = String::from_utf8_lossy(&decompressed);

    let issues = analyze_log(&content);

    let mut diagnosis_banner = String::new();
    if !issues.is_empty() {
        diagnosis_banner.push_str(r#"<div class="diagnosis-banner">"#);
        diagnosis_banner.push_str(r#"<div class="banner-header">⚠️ AUTOMATED LOG DIAGNOSIS DETECTED ISSUES</div>"#);
        for issue in issues {
            let badge_class = match issue.severity.as_str() {
                "CRITICAL" => "badge-critical",
                "ERROR" => "badge-error",
                _ => "badge-warn",
            };
            diagnosis_banner.push_str(&format!(
                r#"<div class="issue-card">
                    <div class="issue-title"><span class="badge {}">{}</span> {}</div>
                    <div class="issue-meta"><strong>Причина:</strong> {}</div>
                    <div class="issue-meta"><strong>Решение:</strong> <pre class="sol">{}</pre></div>
                </div>"#,
                badge_class,
                escape_html(&issue.severity),
                escape_html(&issue.title),
                escape_html(&issue.cause),
                escape_html(&issue.solution)
            ));
        }
        diagnosis_banner.push_str("</div>");
    }

    let line_count = content.lines().count().max(1);
    let mut line_numbers = String::new();
    for i in 1..=line_count {
        line_numbers.push_str(&format!("{}\n", i));
    }

    let escaped_content = escape_html(&content);

    let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Paste {} - ES-Paste</title>
  <style>
    :root {{
      --bg: #0d1117;
      --surface: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --accent: #58a6ff;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }}
    header {{
      padding: 12px 24px;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }}
    .logo a {{
      font-weight: 700;
      color: var(--accent);
      font-size: 1.15rem;
      text-decoration: none;
    }}
    .actions a, .actions button {{
      background: var(--bg);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 6px 14px;
      border-radius: 6px;
      text-decoration: none;
      font-size: 0.88rem;
    }}
    .diagnosis-banner {{
      background: #1f1418;
      border-bottom: 2px solid #f85149;
      padding: 16px 24px;
    }}
    .banner-header {{
      font-weight: bold;
      color: #f85149;
      margin-bottom: 12px;
      letter-spacing: 0.05em;
    }}
    .issue-card {{
      background: #27161c;
      border-left: 4px solid #f85149;
      padding: 12px;
      border-radius: 4px;
      margin-bottom: 10px;
    }}
    .issue-title {{ font-size: 1rem; font-weight: bold; margin-bottom: 6px; }}
    .badge {{
      font-size: 0.75rem;
      padding: 2px 6px;
      border-radius: 4px;
      margin-right: 8px;
    }}
    .badge-critical {{ background: #b62324; color: #fff; }}
    .badge-error {{ background: #da3633; color: #fff; }}
    .badge-warn {{ background: #d29922; color: #000; }}
    .issue-meta {{ font-size: 0.88rem; margin-top: 4px; color: #e6edf3; }}
    .sol {{ margin-top: 4px; white-space: pre-wrap; color: #7ee787; background: #161b22; padding: 6px 10px; border-radius: 4px; }}
    .content-container {{
      flex: 1;
      display: flex;
      overflow-x: auto;
    }}
    .line-numbers {{
      width: 56px;
      padding: 16px 8px;
      text-align: right;
      color: #484f58;
      user-select: none;
      background: var(--surface);
      border-right: 1px solid var(--border);
      font-size: 0.9rem;
      line-height: 1.5;
      white-space: pre;
    }}
    pre.code-view {{
      flex: 1;
      padding: 16px;
      font-family: inherit;
      font-size: 0.9rem;
      line-height: 1.5;
      overflow-x: auto;
      white-space: pre;
    }}
  </style>
</head>
<body>
  <header>
    <div class="logo"><a href="/">⚡ ES-PASTE // LOG VAULT</a></div>
    <div class="actions">
      <a href="/raw/{}" target="_blank">Raw Output</a>
      <a href="/">New Paste</a>
    </div>
  </header>
  {}
  <div class="content-container">
    <div class="line-numbers">{}</div>
    <pre class="code-view"><code>{}</code></pre>
  </div>
</body>
</html>"#,
        id, id, diagnosis_banner, line_numbers, escaped_content
    );

    Ok(Html(html))
}

pub fn app_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(root_editor))
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
    use axum::body::to_bytes;
    use axum::http::Request;
    use tower::ServiceExt;

    fn setup_test_state() -> AppState {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        AppState {
            db: Arc::new(Mutex::new(conn)),
            base_url: "http://localhost:8080".into(),
            auth_token: "secret-test-token".into(),
        }
    }

    #[tokio::test]
    async fn test_create_and_read_paste() {
        let state = setup_test_state();
        let app = app_router(state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/paste")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"content": "Address already in use: bind\nServer crashed"}"#))
            .unwrap();

        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let created: CreatePasteResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(created.issues_detected, 1);

        let req_raw = Request::builder()
            .method("GET")
            .uri(format!("/raw/{}", created.id))
            .body(axum::body::Body::empty())
            .unwrap();

        let res_raw = app.clone().oneshot(req_raw).await.unwrap();
        assert_eq!(res_raw.status(), StatusCode::OK);
        let raw_body = to_bytes(res_raw.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            String::from_utf8(raw_body.to_vec()).unwrap(),
            "Address already in use: bind\nServer crashed"
        );

        let req_view = Request::builder()
            .method("GET")
            .uri(format!("/p/{}", created.id))
            .body(axum::body::Body::empty())
            .unwrap();
        let res_view = app.oneshot(req_view).await.unwrap();
        assert_eq!(res_view.status(), StatusCode::OK);
        let view_body = to_bytes(res_view.into_body(), usize::MAX).await.unwrap();
        let view_html = String::from_utf8(view_body.to_vec()).unwrap();
        assert!(view_html.contains("AUTOMATED LOG DIAGNOSIS DETECTED ISSUES"));
        assert!(view_html.contains("Порт уже занят"));
    }

    #[tokio::test]
    async fn test_auth_ttl_limits() {
        let state = setup_test_state();
        let app = app_router(state);

        // Guest requesting 100 hours -> clamped to 12
        let req_guest = Request::builder()
            .method("POST")
            .uri("/api/paste")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"content": "guest log", "ttl_hours": 100}"#))
            .unwrap();
        let res_guest = app.clone().oneshot(req_guest).await.unwrap();
        let body = to_bytes(res_guest.into_body(), usize::MAX).await.unwrap();
        let guest_resp: CreatePasteResponse = serde_json::from_slice(&body).unwrap();
        let now = Utc::now().timestamp();
        assert!(guest_resp.expires_at <= now + 12 * 3600 + 5);

        // Authed requesting 100 hours -> allowed
        let req_auth = Request::builder()
            .method("POST")
            .uri("/api/paste")
            .header("content-type", "application/json")
            .header("authorization", "Bearer secret-test-token")
            .body(axum::body::Body::from(r#"{"content": "admin log", "ttl_hours": 100}"#))
            .unwrap();
        let res_auth = app.oneshot(req_auth).await.unwrap();
        let body = to_bytes(res_auth.into_body(), usize::MAX).await.unwrap();
        let auth_resp: CreatePasteResponse = serde_json::from_slice(&body).unwrap();
        assert!(auth_resp.expires_at > now + 90 * 3600);
    }
}
