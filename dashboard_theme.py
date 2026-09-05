"""Clawpilot tokens scoped to the self-contained assessment dashboard."""

DETECT = """
(() => {
  const param = new URLSearchParams(window.location.search).get("scoutTheme");
  const theme = (param === "light" || param === "dark") ? param :
    (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  document.documentElement.setAttribute("data-theme", theme);
})();
"""

CSS = """
:root {
  color-scheme: light;
  --cp-bg: #f7f4ef;
  --cp-bg-elevated: #fcfbf8;
  --cp-surface: #ffffff;
  --cp-surface-soft: #f5f5f5;
  --cp-border: #dedede;
  --cp-border-strong: #919191;
  --cp-text: #242424;
  --cp-text-muted: #5c5c5c;
  --cp-text-soft: #6f6f6f;
  --cp-accent: #b11f4b;
  --cp-accent-hover: #9a1a41;
  --cp-accent-soft: rgba(177, 31, 75, 0.08);
  --cp-accent-fg: #ffffff;
  --cp-success: #16a34a;
  --cp-danger: #dc2626;
  --cp-warning: #f59e0b;
  --cp-link: #0078d4;
  --cp-shadow: 0 18px 48px rgba(0, 0, 0, 0.12);
  --cp-overlay: rgba(255, 255, 255, 0.8);
  --cp-panel: rgba(255, 255, 255, 0.86);
  --cp-panel-strong: rgba(255, 255, 255, 0.96);
  --cp-sheen: rgba(255, 255, 255, 0.55);
  --cp-highlight: rgba(177, 31, 75, 0.12);
}
html[data-theme="dark"] {
  color-scheme: dark;
  --cp-bg: #3d3b3a;
  --cp-bg-elevated: #343231;
  --cp-surface: #292929;
  --cp-surface-soft: #2e2e2e;
  --cp-border: #474747;
  --cp-border-strong: #5f5f5f;
  --cp-text: #dedede;
  --cp-text-muted: #919191;
  --cp-text-soft: #b0b0b0;
  --cp-accent: #fd8ea1;
  --cp-accent-hover: #fb7b91;
  --cp-accent-soft: rgba(253, 142, 161, 0.14);
  --cp-accent-fg: #1a1a1a;
  --cp-success: #4ade80;
  --cp-danger: #f87171;
  --cp-warning: #fbbf24;
  --cp-link: #4da6ff;
  --cp-shadow: 0 18px 48px rgba(0, 0, 0, 0.32);
  --cp-overlay: rgba(41, 41, 41, 0.88);
  --cp-panel: rgba(41, 41, 41, 0.72);
  --cp-panel-strong: rgba(41, 41, 41, 0.96);
  --cp-sheen: rgba(255, 255, 255, 0.04);
  --cp-highlight: rgba(253, 142, 161, 0.12);
}
:root,:root[data-theme]{
 --cp-success-readable:color-mix(in srgb,var(--cp-success) 35%,var(--cp-text));
 --cp-warning-readable:color-mix(in srgb,var(--cp-warning) 35%,var(--cp-text));
 --cp-card-shadow:0 0 2px rgba(0,0,0,0.12),0 1px 2px rgba(0,0,0,0.14);
 --bg:var(--cp-bg);--card:var(--cp-surface);--ink:var(--cp-text);
 --muted:var(--cp-text-muted);--line:var(--cp-border);--track:var(--cp-surface-soft);
 --link:var(--cp-link);--panel:var(--cp-surface);
 --viz-grid:var(--cp-border);--viz-axis:var(--cp-border-strong);--viz-label:var(--cp-text-muted);
}
body,button,input,textarea,select{
 font-family:"Segoe UI",Aptos,Calibri,-apple-system,BlinkMacSystemFont,sans-serif;
}
.mono,.lic{font-family:Consolas,"Courier New",Courier,monospace}
.card,.decision,.narrative,.tile{border-radius:16px;box-shadow:var(--cp-card-shadow)}
.chip,.search,nav a,.iconbtn,.campaign,.acceptance,.dstatus,.badge{border-radius:10px}
.narrative,.decision{border-color:var(--cp-border);border-top-color:var(--cp-accent)}
.narrative{border-left-color:var(--cp-accent)}
.confbar.telemetry i,.logo i:nth-child(n){background:var(--cp-accent)}
.lic,:root[data-theme=dark] .lic{background:var(--cp-accent-soft);color:var(--cp-accent)}
.badge:not(.hollow){color:var(--cp-accent-fg)}
.dstatus.overdue,.dstatus.expired{background:var(--cp-accent-soft);color:var(--cp-danger)}
.trend.up,.conflist .bad{color:var(--cp-danger)}
.trend.down,.conflist .ok{color:var(--cp-success-readable)}
.conflist .warn{color:var(--cp-warning-readable)}
.scrim{background:var(--cp-overlay)}
.executive-strip{display:flex;flex-wrap:wrap;gap:12px 24px;align-items:center;
 padding:16px 20px;border:1px solid var(--cp-border);border-radius:16px;
 background:var(--cp-surface);color:var(--cp-text)}
.executive-strip strong{color:var(--cp-accent)}
.executive-strip p{margin:0;flex-basis:100%;font-size:13px;color:var(--cp-text-muted)}
.attention{padding:12px 16px;border-radius:10px;background:var(--cp-accent-soft);
 color:var(--cp-text);font-size:14px}
.details-block{margin:16px 0}
summary{cursor:pointer;padding:12px 4px;font-weight:600;color:var(--cp-text)}
.workflow-actions{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.workflow-btn{border:1px solid var(--cp-border-strong);background:var(--cp-surface);
 color:var(--cp-text);border-radius:10px;padding:8px 12px;font-size:14px;cursor:pointer}
.workflow-btn.primary{background:var(--cp-accent);color:var(--cp-accent-fg);border-color:var(--cp-accent)}
.workflow-btn:hover{border-color:var(--cp-accent)}
.workflow-btn:disabled{opacity:.6;cursor:not-allowed}
:focus-visible{outline:2px solid var(--cp-accent);outline-offset:3px}
.workflow-review{margin:16px 0}
.workflow-review-row{display:grid;grid-template-columns:1fr 1fr auto;align-items:center;
 gap:12px;padding:12px 0;border-top:1px solid var(--cp-border)}
.workflow-review-row p{margin:0;font-size:13px;color:var(--cp-text-muted)}
.workflow-snapshot{font-size:13px;color:var(--cp-text-muted);margin:8px 0}
.workflow-snapshot strong{color:var(--cp-danger)}
.workflow-message{white-space:pre-wrap;overflow-wrap:anywhere}
.workflow-message.error{color:var(--cp-danger)}
.workflow-dialog{width:min(720px,calc(100% - 24px));max-height:90vh;overflow:auto;
 border:1px solid var(--cp-border);border-radius:16px;padding:24px;
 background:var(--cp-surface);color:var(--cp-text);box-shadow:var(--cp-shadow)}
.workflow-dialog::backdrop{background:var(--cp-overlay)}
.workflow-dialog h2{margin:0 0 12px;font-size:22px}
.workflow-fields{border:0;padding:0;margin:12px 0;min-width:0}
.workflow-fields label,.workflow-auth label{display:block;font-size:14px;font-weight:600;margin:12px 0 4px}
.workflow-fields input,.workflow-fields select,.workflow-fields textarea,.workflow-auth input{
 width:100%;padding:10px;border-radius:10px;border:1px solid var(--cp-border-strong);
 background:var(--cp-bg-elevated);color:var(--cp-text);font-size:15px}
.workflow-fields textarea{resize:vertical;min-height:72px}
.workflow-fields small{display:block;color:var(--cp-text-muted)}
.workflow-history{padding-left:20px;overflow-wrap:anywhere;font-size:13px}
[hidden]{display:none!important}
@media(max-width:700px){
 .topbar{height:auto;min-height:56px;flex-wrap:wrap;gap:8px;padding:8px 12px}
 .topbar nav{order:3;flex-basis:100%}.topright{margin-left:auto}.topright>span{display:none}
 .wrap{padding:16px 12px 36px}.card{padding:16px}.workflow-review-row{grid-template-columns:1fr}
 h1{font-size:24px}.postrow{flex-wrap:wrap}.workflow-dialog{padding:16px}
}
@media print{
 :root,html[data-theme]{--cp-bg:#fff;--cp-surface:#fff;--cp-text:#242424;
 --cp-text-muted:#5c5c5c;--cp-border:#dedede;--cp-accent:#b11f4b;--cp-danger:#dc2626}
 .workflow-actions,.workflow-auth,.workflow-dialog,.workflow-btn,.topbar{display:none!important}
 .view:not(#v-overview){display:none!important}
 #v-overview{display:block!important}
 .details-block{display:none!important}
 .decisiongrid{grid-template-columns:1fr}
 .decision,.workflow-review-row,.executive-strip{break-inside:avoid}
 .card{break-inside:auto}.workflow-snapshot{color:var(--cp-text-muted)}
 body{background:var(--cp-bg);color:var(--cp-text)}
}
"""
