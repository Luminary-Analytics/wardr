//! Branded inline HTML splash and diagnostic screens for the Wardr native shell.

fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

pub fn loading_html(headline: &str, detail: &str) -> String {
    let headline = escape_html(headline);
    let detail = escape_html(detail);
    format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wardr</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  html, body {{
    margin: 0;
    height: 100%;
    background: radial-gradient(circle at 50% 35%, #163d2d 0%, #0d241b 65%, #091913 100%);
    color: #eef6f1;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
    display: flex;
    align-items: center;
    justify-content: center;
    user-select: none;
  }}
  .card {{
    text-align: center;
    max-width: 420px;
    padding: 40px 36px;
    border-radius: 20px;
    background: rgba(15, 42, 31, 0.72);
    border: 1px solid rgba(116, 214, 152, 0.18);
    box-shadow: 0 24px 64px rgba(0, 0, 0, 0.38);
  }}
  .mark {{
    width: 64px;
    height: 64px;
    margin: 0 auto 20px;
    border-radius: 16px;
    background: linear-gradient(145deg, #34d399, #15803d);
    display: grid;
    place-items: center;
    box-shadow: 0 12px 28px rgba(21, 128, 61, 0.42);
  }}
  .mark svg {{ width: 34px; height: 34px; }}
  h1 {{
    margin: 0 0 8px;
    font-size: 20px;
    font-weight: 600;
    letter-spacing: -0.01em;
  }}
  p {{
    margin: 0 0 24px;
    font-size: 14px;
    line-height: 1.5;
    color: #a9c7b6;
  }}
  .spinner {{
    width: 28px;
    height: 28px;
    margin: 0 auto;
    border-radius: 50%;
    border: 3px solid rgba(169, 199, 182, 0.22);
    border-top-color: #4ade80;
    animation: spin 0.85s linear infinite;
  }}
  @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
</style>
</head>
<body>
  <main class="card">
    <div class="mark" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="#082014" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <path d="m9 12 2 2 4-4"/>
      </svg>
    </div>
    <h1>{headline}</h1>
    <p>{detail}</p>
    <div class="spinner" role="status" aria-label="Loading"></div>
  </main>
</body>
</html>"##
    )
}

pub fn error_html(headline: &str, detail: &str) -> String {
    let headline = escape_html(headline);
    let detail = escape_html(detail);
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wardr</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  html, body {{
    margin: 0;
    height: 100%;
    background: #0d1f18;
    color: #eef6f1;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
    display: flex;
    align-items: center;
    justify-content: center;
  }}
  .card {{
    max-width: 520px;
    width: calc(100% - 48px);
    padding: 36px;
    border-radius: 18px;
    background: #132c22;
    border: 1px solid rgba(248, 113, 113, 0.35);
    box-shadow: 0 24px 64px rgba(0, 0, 0, 0.4);
  }}
  h1 {{ margin: 0 0 12px; font-size: 20px; color: #fecaca; }}
  pre {{
    margin: 0;
    padding: 14px;
    border-radius: 10px;
    background: rgba(0, 0, 0, 0.32);
    color: #dbe9e1;
    font-size: 13px;
    line-height: 1.45;
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 240px;
    overflow: auto;
  }}
  p {{ margin: 16px 0 0; font-size: 13px; color: #9eb9aa; }}
</style>
</head>
<body>
  <main class="card">
    <h1>{headline}</h1>
    <pre>{detail}</pre>
    <p>You can quit Wardr from the system tray or menu bar and relaunch after resolving the issue.</p>
  </main>
</body>
</html>"#
    )
}
