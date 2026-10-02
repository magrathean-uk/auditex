"""Self-contained interactive HTML explorer for a finalized Auditex run.

The page embeds the run's summary, findings, proof rows, attack paths, the
evidence records findings point at, and the run's data-handling assertions.
It makes no network requests. It contains tenant evidence, so share it the
same way as the run folder itself.
"""
from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from azure_tenant_audit.resources import load_json_resource

_EVIDENCE_LIMIT = 400


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _evidence_records(run_dir: Path, findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    wanted: dict[str, set[str]] = {}
    for finding in findings:
        for ref in finding.get("evidence_refs") or []:
            artifact, key = ref.get("artifact_path"), ref.get("record_key")
            if isinstance(artifact, str) and isinstance(key, str):
                wanted.setdefault(artifact, set()).add(key)
    records: dict[str, dict[str, Any]] = {}
    for artifact, keys in wanted.items():
        payload = _read_json(run_dir / artifact, {})
        rows = payload.get("records") if isinstance(payload, dict) else payload
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and row.get("key") in keys and len(records) < _EVIDENCE_LIMIT:
                records[f"{artifact}#{row['key']}"] = row
    return records


def _collector_permissions(collectors: list[str]) -> list[dict[str, Any]]:
    definitions = (load_json_resource("configs/collector-definitions.json", default={}) or {}).get("collectors", {})
    rows = []
    for name in collectors:
        definition = definitions.get(name) or {}
        rows.append(
            {
                "collector": name,
                "description": definition.get("description", ""),
                "permissions": definition.get("required_permissions") or [],
            }
        )
    return rows


def build_explorer_data(run_dir: Path) -> dict[str, Any]:
    run_dir = Path(run_dir)
    manifest = _read_json(run_dir / "run-manifest.json", {})
    report_pack = _read_json(run_dir / "reports" / "report-pack.json", {})
    findings = _read_json(run_dir / "findings" / "findings.json", [])
    data_handling = _read_json(run_dir / "data-handling.json", {})
    validation = _read_json(run_dir / "validation.json", {})
    collectors = [str(name) for name in manifest.get("selected_collectors") or data_handling.get("collectors") or []]
    keep = (
        "id", "rule_id", "severity", "category", "title", "status", "collector", "affected_objects",
        "description", "impact", "remediation", "references", "framework_mappings", "evidence_refs",
    )
    return {
        "tenant": manifest.get("tenant_name") or report_pack.get("summary", {}).get("tenant_name"),
        "run_id": manifest.get("run_id"),
        "created_utc": manifest.get("created_utc"),
        "mode": manifest.get("mode"),
        "platform": manifest.get("platform"),
        "contract_valid": bool(validation.get("valid")),
        "provenance": manifest.get("fixture_provenance") or report_pack.get("fixture_provenance"),
        "summary": report_pack.get("summary") or {},
        "findings": [{key: finding.get(key) for key in keep if key in finding} for finding in findings if isinstance(finding, dict)],
        "proof": [
            {key: row.get(key) for key in ("finding_id", "proof_status", "confidence", "evidence_count", "artifacts", "blast_radius")}
            for row in report_pack.get("proof_table") or []
            if isinstance(row, dict)
        ],
        "attack_paths": report_pack.get("attack_paths") or [],
        "evidence": _evidence_records(run_dir, findings if isinstance(findings, list) else []),
        "data_handling": {
            key: data_handling.get(key)
            for key in ("read_only", "content_reads", "write_actions", "scope_risk", "write_capable_scopes", "provider_assertions")
        },
        "collectors": _collector_permissions(collectors),
        "detection": report_pack.get("detection_coverage") or {},
        "baselines": _baseline_view(report_pack.get("baseline_alignment") or {}),
        "public_footprint": report_pack.get("public_footprint"),
    }


def _baseline_view(alignment: dict[str, Any]) -> dict[str, Any]:
    frameworks = alignment.get("frameworks") if isinstance(alignment.get("frameworks"), dict) else {}
    return {
        "frameworks": [
            {
                "key": key,
                "title": framework.get("title"),
                "version": framework.get("version"),
                "status_counts": framework.get("status_counts") or {},
                "controls": [
                    {name: control.get(name) for name in ("control_id", "title", "status", "finding_ids")}
                    for control in framework.get("controls") or []
                    if isinstance(control, dict)
                ],
            }
            for key, framework in frameworks.items()
            if isinstance(framework, dict)
        ],
        "secure_score": alignment.get("secure_score") or {},
    }


def render_explorer_html(data: dict[str, Any]) -> str:
    payload = json.dumps(data, ensure_ascii=False, default=str).replace("</", "<\\/")
    title = html.escape(f"Auditex explorer · {data.get('tenant') or 'run'}")
    return _TEMPLATE.replace("__TITLE__", title).replace("__DATA__", payload)


def write_explorer(run_dir: Path | str, output_path: Path | str) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_explorer_html(build_explorer_data(Path(run_dir))), encoding="utf-8")
    return output


_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#f6f7f9;--panel:#fff;--ink:#16191d;--muted:#5d6670;--line:#dfe3e8;--accent:#1f5fbf;
--crit:#b3261e;--high:#d9480f;--med:#b7791f;--low:#2b7a78;--info:#6b7280;--ok:#2f7d32;--chip:#eef1f5}
@media (prefers-color-scheme:dark){:root{--bg:#101317;--panel:#171b21;--ink:#e8ebef;--muted:#9aa4af;--line:#2a3038;
--accent:#7fb0ff;--crit:#ff6b60;--high:#ff8f4d;--med:#e3b341;--low:#4fc3b8;--info:#9ca3af;--ok:#6cc070;--chip:#222831}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
header{padding:20px 24px 0;max-width:1180px;margin:0 auto}h1{font-size:22px;margin:0 0 4px}.sub{color:var(--muted);font-size:13px}
.banner{margin:12px 0 0;padding:8px 12px;border-radius:8px;background:color-mix(in srgb,var(--med) 16%,transparent);border:1px solid color-mix(in srgb,var(--med) 45%,transparent);font-size:13px}
nav{display:flex;gap:4px;max-width:1180px;margin:16px auto 0;padding:0 24px;overflow-x:auto;border-bottom:1px solid var(--line)}
nav button{background:none;border:0;border-bottom:2px solid transparent;color:var(--muted);padding:10px 12px;font:inherit;cursor:pointer;white-space:nowrap}
nav button[aria-selected=true]{color:var(--ink);border-color:var(--accent);font-weight:600}
main{max-width:1180px;margin:0 auto;padding:20px 24px 48px}section[hidden]{display:none}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
.tile b{display:block;font-size:26px;line-height:1.2}.tile>span{color:var(--muted);font-size:13px}.tile b .sev{font-size:15px;padding:3px 12px;margin-top:4px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;margin-top:16px}
.card{overflow-x:auto}.card h2{font-size:15px;margin:0 0 12px}.bar{display:flex;height:14px;border-radius:7px;overflow:hidden;background:var(--chip)}
.legend{display:flex;flex-wrap:wrap;gap:14px;margin-top:8px;font-size:13px;color:var(--muted)}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px;vertical-align:baseline}
.rows div{display:grid;grid-template-columns:minmax(120px,220px) 1fr 36px;gap:10px;align-items:center;font-size:13px;margin:5px 0}
.rows i{display:block;height:10px;border-radius:5px;background:var(--accent)}
.sev{display:inline-block;min-width:72px;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;text-align:center;color:#fff}
.sev.critical{background:var(--crit)}.sev.high{background:var(--high)}.sev.medium{background:var(--med)}.sev.low{background:var(--low)}.sev.info{background:var(--info)}
.tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.tools input,.tools select{font:inherit;padding:7px 10px;border-radius:8px;border:1px solid var(--line);background:var(--panel);color:var(--ink)}
.tools input{flex:1;min-width:200px}.chip{border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:999px;padding:4px 10px;font:inherit;font-size:13px;cursor:pointer}
.chip[aria-pressed=true]{background:var(--ink);color:var(--panel)}
.finding{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-top:10px}
.finding summary{list-style:none;cursor:pointer;padding:12px 14px;display:grid;grid-template-columns:auto 1fr auto;gap:12px;align-items:center}
.finding summary::-webkit-details-marker{display:none}.finding .meta{color:var(--muted);font-size:12px}
.detail{border-top:1px solid var(--line);padding:12px 14px;display:grid;gap:10px}.detail h3{font-size:13px;margin:0;color:var(--muted);font-weight:600}
.tags{display:flex;flex-wrap:wrap;gap:6px}.tag{background:var(--chip);border-radius:6px;padding:2px 8px;font-size:12px}
pre{margin:0;background:var(--chip);border-radius:8px;padding:10px;overflow:auto;font-size:12px;max-height:280px}
.path{display:flex;flex-wrap:wrap;align-items:stretch;gap:8px}.stage{flex:1 1 180px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px;position:relative}
.stage small{color:var(--muted);text-transform:uppercase;letter-spacing:.04em;font-size:11px}.arrow{align-self:center;color:var(--muted);font-size:20px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}
.ok{color:var(--ok);font-weight:600}.st{display:inline-block;min-width:64px;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;text-align:center;background:var(--chip)}.st.on,.st.pass{background:color-mix(in srgb,var(--ok) 22%,transparent);color:var(--ok)}.st.off,.st.fail{background:color-mix(in srgb,var(--crit) 18%,transparent);color:var(--crit)}.st.accepted_risk{background:color-mix(in srgb,var(--med) 22%,transparent);color:var(--med)}.st.unknown,.st.not_assessed{color:var(--muted)}.stack{display:flex;height:10px;border-radius:5px;overflow:hidden;background:var(--chip);min-width:72px}.bad{color:var(--crit);font-weight:600}a{color:var(--accent)}
.finding summary .sev{justify-self:start}@media (max-width:640px){header,main,nav{padding-left:16px;padding-right:16px}.finding summary{grid-template-columns:auto 1fr}.finding summary>.meta:last-child{grid-column:2}.path{flex-direction:column}.stage{flex:none}.arrow{transform:rotate(90deg);align-self:center}}
</style>
</head>
<body>
<header><h1 id="title"></h1><div class="sub" id="sub"></div><div id="banner"></div></header>
<nav role="tablist">
<button role="tab" data-tab="overview" aria-selected="true">Overview</button>
<button role="tab" data-tab="findings">Findings</button>
<button role="tab" data-tab="paths">Attack paths</button>
<button role="tab" data-tab="detection">Detection</button>
<button role="tab" data-tab="baselines">Baselines</button>
<button role="tab" data-tab="access">Access &amp; data handling</button>
</nav>
<main>
<section id="overview"></section>
<section id="findings" hidden>
<div class="tools"><input id="q" type="search" placeholder="Search findings, objects, rule ids" aria-label="Search findings">
<select id="fw" aria-label="Framework"><option value="">All frameworks</option></select></div>
<div class="tools" id="sevs" style="margin-top:8px"></div><div id="list"></div>
</section>
<section id="paths" hidden></section>
<section id="detection" hidden></section>
<section id="baselines" hidden></section>
<section id="access" hidden></section>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
const D=JSON.parse(document.getElementById('data').textContent);
const SEV=['critical','high','medium','low','info'];
const FW={cis_m365_v7:'CIS M365 v7',cis_m365_v3:'CIS M365 v3 (legacy)',cisa_scuba:'CISA SCuBA',ms_secure_score:'Secure Score',ms_zero_trust:'Zero Trust',mcsb:'MCSB',google_workspace_baseline:'Google Workspace',nist_800_53:'NIST 800-53',iso_27001:'ISO 27001',soc2:'SOC 2',nis2:'NIS2',dora:'DORA',mitre_attack:'MITRE ATT&CK'};
const el=(t,a={},...k)=>{const e=document.createElement(t);for(const[n,v]of Object.entries(a)){if(n==='class')e.className=v;else if(n==='text')e.textContent=v;else e.setAttribute(n,v)}for(const c of k)if(c!=null)e.append(c);return e};
const sev=s=>el('span',{class:'sev '+(s||'info'),text:s||'info'});
const proofBy=Object.fromEntries((D.proof||[]).map(p=>[p.finding_id,p]));
const findings=[...(D.findings||[])].sort((a,b)=>SEV.indexOf(a.severity)-SEV.indexOf(b.severity));
document.getElementById('title').textContent='Auditex · '+(D.tenant||'run');
document.getElementById('sub').textContent=[D.platform,D.mode,D.run_id,D.created_utc].filter(Boolean).join(' · ');
const P=D.provenance||{};
if(P.synthetic||P.seed_kind==='demo'||D.mode==='offline'){document.getElementById('banner').append(el('div',{class:'banner',text:(P.synthetic||P.seed_kind==='demo'?'Synthetic demo data. ':'Offline replay. ')+(P.description||'No live tenant was contacted for this run.')}))}
function overview(){const s=D.summary||{},r=s.risk||{},c=s.severity_counts||{};const sec=document.getElementById('overview');
const ids=new Set(findings.map(f=>f.id));const supported=new Set((D.proof||[]).filter(p=>ids.has(p.finding_id)&&(p.proof_status||'supported')==='supported').map(p=>p.finding_id)).size;
sec.append(el('div',{class:'tiles'},
el('div',{class:'tile'},el('span',{text:'Risk grade'}),el('b',{},sev(r.grade))),
el('div',{class:'tile'},el('span',{text:'Risk score'}),el('b',{text:(r.score??'–')+' / 100'})),
el('div',{class:'tile'},el('span',{text:'Open findings'}),el('b',{text:String(s.open_count??findings.length)})),
el('div',{class:'tile'},el('span',{text:'Findings with proof'}),el('b',{text:supported+' / '+findings.length})),
el('div',{class:'tile'},el('span',{text:'Bundle contract'}),el('b',{class:D.contract_valid?'ok':'bad',text:D.contract_valid?'valid':'invalid'}))));
const total=SEV.reduce((n,k)=>n+(c[k]||0),0)||1;const bar=el('div',{class:'bar',role:'img','aria-label':'Findings by severity'});const leg=el('div',{class:'legend'});
for(const k of SEV){if(!c[k])continue;bar.append(el('div',{style:`width:${100*c[k]/total}%;background:var(--${k==='critical'?'crit':k==='medium'?'med':k})`}));leg.append(el('span',{},el('span',{class:'dot',style:`background:var(--${k==='critical'?'crit':k==='medium'?'med':k})`}),`${k} ${c[k]}`))}
sec.append(el('div',{class:'card'},el('h2',{text:'Findings by severity'}),bar,leg));
const cats={};for(const f of findings)cats[f.category||'other']=(cats[f.category||'other']||0)+1;const max=Math.max(1,...Object.values(cats));
const rows=el('div',{class:'rows'});for(const[k,v]of Object.entries(cats).sort((a,b)=>b[1]-a[1]))rows.append(el('div',{},el('span',{text:k.replace(/_/g,' ')}),el('i',{style:`width:${100*v/max}%`}),el('span',{text:String(v)})));
sec.append(el('div',{class:'card'},el('h2',{text:'Findings by area'}),rows));
const top=el('div',{});for(const f of findings.slice(0,5))top.append(el('div',{style:'display:flex;gap:10px;align-items:center;margin:6px 0'},sev(f.severity),el('span',{text:f.title})));
sec.append(el('div',{class:'card'},el('h2',{text:'Fix first'}),top))}
let sevFilter=new Set();
function findingCard(f){const p=proofBy[f.id]||{};const d=el('details',{class:'finding'});
d.append(el('summary',{},sev(f.severity),el('div',{},el('div',{text:f.title}),el('div',{class:'meta',text:[f.rule_id,(f.affected_objects||[]).slice(0,3).join(', ')].filter(Boolean).join(' · ')})),el('span',{class:'meta',text:(p.proof_status||'supported')+' proof'})));
const det=el('div',{class:'detail'});
for(const[k,l]of[['description','What we found'],['impact','Why it matters'],['remediation','How to fix']])if(f[k])det.append(el('div',{},el('h3',{text:l}),el('div',{text:f[k]})));
const tags=el('div',{class:'tags'});for(const[k,v]of Object.entries(f.framework_mappings||{}))for(const id of v||[])tags.append(el('span',{class:'tag',text:(FW[k]||k)+' '+id}));
if(tags.childNodes.length)det.append(el('div',{},el('h3',{text:'Frameworks'}),tags));
for(const ref of f.evidence_refs||[]){const rec=D.evidence[ref.artifact_path+'#'+ref.record_key];det.append(el('div',{},el('h3',{text:'Evidence · '+ref.artifact_path+' → '+ref.record_key}),el('pre',{text:rec?JSON.stringify(rec,null,2):'Record not embedded; open the run folder.'})))}
d.append(det);return d}
function renderList(){const q=document.getElementById('q').value.toLowerCase(),fw=document.getElementById('fw').value;const list=document.getElementById('list');list.replaceChildren();
const shown=findings.filter(f=>(!sevFilter.size||sevFilter.has(f.severity))&&(!fw||(f.framework_mappings||{})[fw]?.length)&&(!q||JSON.stringify([f.title,f.rule_id,f.affected_objects,f.category]).toLowerCase().includes(q)));
list.append(el('div',{class:'meta',style:'margin-top:10px',text:shown.length+' of '+findings.length+' findings'}));for(const f of shown)list.append(findingCard(f))}
function findingsTab(){const fws=new Set();for(const f of findings)for(const k of Object.keys(f.framework_mappings||{}))fws.add(k);const sel=document.getElementById('fw');for(const k of fws)sel.append(el('option',{value:k,text:FW[k]||k}));
const sevs=document.getElementById('sevs');for(const s of SEV){if(!findings.some(f=>f.severity===s))continue;const b=el('button',{class:'chip','aria-pressed':'false',text:s});b.onclick=()=>{sevFilter.has(s)?sevFilter.delete(s):sevFilter.add(s);b.setAttribute('aria-pressed',String(sevFilter.has(s)));renderList()};sevs.append(b)}
document.getElementById('q').oninput=renderList;sel.onchange=renderList;renderList()}
function pathsTab(){const sec=document.getElementById('paths');const paths=D.attack_paths||[];if(!paths.length){sec.append(el('p',{text:'No multi-stage attack path was found in this run.'}));return}
for(const p of paths){const row=el('div',{class:'path'});const hops=Array.isArray(p.hops)&&p.hops.length?p.hops:null;
const stages=hops?hops.map(h=>({stage:h.edge,severity:p.severity,title:(h.from||'')+' → '+(h.to||''),technique:h.technique,eligible:h.eligible})):(p.findings||[]);
stages.forEach((s,i)=>{if(i)row.append(el('span',{class:'arrow',text:'→'}));const st=el('div',{class:'stage'},el('small',{text:(s.stage||'').replace(/_/g,' ')+(s.eligible?' (PIM-eligible)':'')}),el('div',{style:'margin:6px 0'},sev(s.severity)),el('div',{text:s.title}));if(s.technique)st.append(el('div',{class:'tags'},el('span',{class:'tag',text:'ATT&CK '+s.technique})));row.append(st)});
const head=hops?(p.source||'')+' → '+(p.target||''):(p.chain||[]).join(' → ').replace(/_/g,' ');
const card=el('div',{class:'card'},el('h2',{},sev(p.severity),' ',head),row);
if(hops){if(p.summary)card.append(el('p',{text:p.summary}));const bp=(p.breakpoints||[]).map(b=>(b.from||'')+' → '+(b.to||'')+' ('+(b.edge||'').replace(/_/g,' ')+')');
card.append(el('p',{class:'meta',text:bp.length?'Remove any one of these to break the path: '+bp.join('; '):'No single edge removal breaks this route; other routes reach the same tier-0 target.'}))}
else card.append(el('p',{class:'meta',text:'Each stage links one finding an intruder could chain with the next. Fixing any stage breaks the path.'}));
sec.append(card)}}
function accessTab(){const sec=document.getElementById('access');const h=D.data_handling||{};const yes=v=>el('span',{class:v?'bad':'ok',text:v?'yes':'no'});
const a=h.provider_assertions||{};sec.append(el('div',{class:'card'},el('h2',{text:'What this run could and could not do'}),el('table',{},
el('tr',{},el('th',{text:'Wrote to the tenant'}),el('td',{},yes(h.write_actions))),
el('tr',{},el('th',{text:'Read mail bodies or file contents'}),el('td',{},yes(h.content_reads||a.body_or_file_content_reads))),
el('tr',{},el('th',{text:'Captured raw secrets'}),el('td',{},yes(a.raw_secret_capture))),
el('tr',{},el('th',{text:'Write-capable scopes held'}),el('td',{text:(h.write_capable_scopes||[]).join(', ')||'none'})))));
const t=el('table',{},el('tr',{},el('th',{text:'Collector'}),el('th',{text:'Read permissions'}),el('th',{text:'What it reads'})));
for(const c of D.collectors||[])t.append(el('tr',{},el('td',{text:c.collector}),el('td',{text:(c.permissions||[]).join(', ')||'–'}),el('td',{text:c.description||''})));
sec.append(el('div',{class:'card'},el('h2',{text:'Collectors and their read permissions'}),t))}
for(const b of document.querySelectorAll('nav button'))b.onclick=()=>{for(const o of document.querySelectorAll('nav button'))o.setAttribute('aria-selected',String(o===b));for(const s of document.querySelectorAll('main>section'))s.hidden=s.id!==b.dataset.tab};
function detectionTab(){const sec=document.getElementById('detection');const dc=D.detection||{};const sig=dc.signals||[];
if(!sig.length){sec.append(el('p',{text:'This run has no detection coverage data.'}));return}
const c=dc.counts||{};sec.append(el('div',{class:'tiles'},el('div',{class:'tile'},el('span',{text:'Detection score'}),el('b',{text:(dc.score??'–')+' / 100'})),
el('div',{class:'tile'},el('span',{text:'Signals on'}),el('b',{class:'ok',text:String(c.on??sig.filter(s=>s.status==='on').length)})),
el('div',{class:'tile'},el('span',{text:'Signals off'}),el('b',{class:'bad',text:String(c.off??sig.filter(s=>s.status==='off').length)})),
el('div',{class:'tile'},el('span',{text:'Not verified'}),el('b',{text:String(c.unknown??sig.filter(s=>s.status==='unknown').length)}))));
const t=el('table',{},el('tr',{},el('th',{text:'Signal'}),el('th',{text:'Status'}),el('th',{text:'Why it matters'})));
for(const s of sig)t.append(el('tr',{},el('td',{text:s.title||s.name}),el('td',{},el('span',{class:'st '+s.status,text:s.status})),el('td',{text:s.why_it_matters||''})));
sec.append(el('div',{class:'card'},el('h2',{text:'Could this tenant see an attack?'}),t,el('p',{class:'meta',text:'"unknown" means Auditex could not collect the evidence; it is never counted as off.'})))}
function baselinesTab(){const sec=document.getElementById('baselines');const b=D.baselines||{};const fws=b.frameworks||[];
if(!fws.length){sec.append(el('p',{text:'This run has no baseline alignment data.'}));return}
const order=['fail','accepted_risk','pass','not_assessed'],col={fail:'var(--crit)',accepted_risk:'var(--med)',pass:'var(--ok)',not_assessed:'var(--line)'};
const t=el('table',{},el('tr',{},el('th',{text:'Framework'}),el('th',{text:'Controls'}),el('th',{text:'Fail'}),el('th',{text:'Pass'})));
for(const f of fws){const sc=f.status_counts||{};const tot=order.reduce((n,k)=>n+(sc[k]||0),0)||1;const st=el('div',{class:'stack',role:'img','aria-label':order.map(k=>k+' '+(sc[k]||0)).join(', ')});
for(const k of order)if(sc[k])st.append(el('div',{style:`width:${100*sc[k]/tot}%;background:${col[k]}`}));
t.append(el('tr',{},el('td',{text:(f.title||f.key)+(f.version?' '+f.version:'')}),el('td',{},st),el('td',{class:'bad',text:String(sc.fail||0)}),el('td',{class:'ok',text:String(sc.pass||0)})))}
sec.append(el('div',{class:'card'},el('h2',{text:'Alignment by framework'}),t));
for(const f of fws){const d=el('details',{class:'finding'});d.append(el('summary',{},el('span',{class:'st '+((f.status_counts||{}).fail?'fail':'pass'),text:(f.status_counts||{}).fail?'gaps':'aligned'}),el('div',{text:(f.title||f.key)+' controls'}),el('span',{class:'meta',text:(f.controls||[]).length+' controls'})));
const ct=el('table',{},el('tr',{},el('th',{text:'Control'}),el('th',{text:'Status'}),el('th',{text:'Title'})));for(const c of f.controls||[])ct.append(el('tr',{},el('td',{text:c.control_id}),el('td',{},el('span',{class:'st '+c.status,text:String(c.status).replace('_',' ')})),el('td',{text:c.title||''})));
d.append(el('div',{class:'detail'},ct));sec.append(d)}
const ss=b.secure_score||{};if(ss.available){const o=ss.overall||{};const t2=el('table',{},el('tr',{},el('th',{text:'Secure Score control'}),el('th',{text:'Microsoft'}),el('th',{text:'Auditex'})));
for(const c of ss.controls||[])t2.append(el('tr',{},el('td',{text:c.title||c.control_profile_id}),el('td',{text:(c.microsoft_score??'–')+' / '+(c.microsoft_max_score??'–')}),el('td',{},el('span',{class:'st '+(c.auditex_state||'not_assessed'),text:String(c.auditex_state||'not assessed').replace('_',' ')}))));
sec.append(el('div',{class:'card'},el('h2',{text:`Microsoft Secure Score ${o.current_score??'–'} / ${o.max_score??'–'} (${o.percentage??'–'}%)`}),t2,el('p',{class:'meta',text:'Auditex column: whether Auditex findings agree with Microsoft for the same control.'})))}}
overview();findingsTab();pathsTab();detectionTab();baselinesTab();accessTab();
</script>
</body>
</html>
"""
