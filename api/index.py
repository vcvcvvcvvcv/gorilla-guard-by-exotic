import os, zipfile, textwrap

root="/mnt/data/gtag_anticheat_hub"
os.makedirs(root+"/templates", exist_ok=True)
os.makedirs(root+"/static", exist_ok=True)

files = {
"app.py": r'''
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

MODULES = [
    {"id":"movement","icon":"🦍","name":"Movement Integrity","category":"Movement","risk":"High","description":"Server-side movement validation for impossible speed, position deltas, and velocity.","tags":["movement","velocity","server"]},
    {"id":"teleport","icon":"⚡","name":"Teleport Detection","category":"Movement","risk":"High","description":"Flags position changes that exceed your configured movement model.","tags":["teleport","position"]},
    {"id":"auth","icon":"🔐","name":"Secure Auto Authentication","category":"Authentication","risk":"Critical","description":"Automatically establishes and validates a trusted player session when the game connects.","tags":["auth","session","identity"]},
    {"id":"session","icon":"🪪","name":"Session Integrity","category":"Authentication","risk":"High","description":"Short-lived server sessions with expiration and replay protection.","tags":["session","replay"]},
    {"id":"anti_lib","icon":"🧩","name":"Anti-Lib / Modding Signals","category":"Anti-Modding","risk":"Critical","description":"Collects integrity signals for unexpected or modified game libraries. Treats them as evidence rather than absolute proof.","tags":["library","integrity","modding"]},
    {"id":"rpc","icon":"📡","name":"RPC Spam Guard","category":"Network","risk":"High","description":"Rate-limits gameplay requests and flags abnormal event bursts.","tags":["rpc","spam","network"]},
    {"id":"packet","icon":"📦","name":"Packet Validation","category":"Network","risk":"High","description":"Validates expected packet/event structure and server state transitions.","tags":["packet","network","state"]},
    {"id":"inventory","icon":"🎒","name":"Inventory Authority","category":"Economy","risk":"Critical","description":"Keeps purchases and inventory changes authoritative on the backend.","tags":["inventory","shop","server"]},
    {"id":"currency","icon":"💎","name":"Currency Authority","category":"Economy","risk":"Critical","description":"Prevents client-only currency changes by validating economy operations server-side.","tags":["currency","economy"]},
    {"id":"reports","icon":"🚨","name":"Report Abuse Guard","category":"Moderation","risk":"Medium","description":"Flags suspicious report bursts for moderator review.","tags":["reports","moderation"]},
    {"id":"discord","icon":"🔔","name":"Discord Detection Alerts","category":"Alerts","risk":"High","description":"Sends private or public detection notifications through server-side Discord webhooks.","tags":["discord","webhook","alerts"]},
    {"id":"logging","icon":"📋","name":"Detection Logging","category":"Monitoring","risk":"Medium","description":"Stores detection evidence, timestamps, and player/session references.","tags":["logs","evidence"]},
]

REVISIONS = [
    {"version":"v1.0","name":"Foundation","status":"Archived","changes":["Movement checks","Basic rate limiting"]},
    {"version":"v2.0","name":"Secure Core","status":"Archived","changes":["Authentication","Session validation","Inventory authority"]},
    {"version":"v3.0","name":"Secure Core+","status":"Current","changes":["Anti-modding signals","Discord alerts","Packet validation"]},
]

@app.get("/")
def home():
    return render_template("index.html", modules=MODULES, revisions=REVISIONS)

@app.get("/api/modules")
def modules():
    return jsonify(MODULES)

@app.get("/api/modules/<module_id>")
def module(module_id):
    item = next((x for x in MODULES if x["id"] == module_id), None)
    if not item:
        return jsonify({"error":"Module not found"}), 404
    return jsonify(item)

@app.get("/api/revisions")
def revisions():
    return jsonify(REVISIONS)

@app.post("/api/revisions")
def create_revision():
    data = request.get_json(silent=True) or {}
    version = str(data.get("version","")).strip()
    name = str(data.get("name","")).strip()
    changes = data.get("changes", [])
    if not version or not name or not isinstance(changes, list):
        return jsonify({"error":"version, name and changes are required"}), 400
    revision = {"version":version,"name":name,"status":"Draft","changes":changes}
    REVISIONS.insert(0, revision)
    return jsonify(revision), 201

@app.get("/hello-world")
def hello_world():
    return "GTAG Anti-Cheat Hub Flask backend online."

if __name__ == "__main__":
    app.run(debug=True)
''',

"templates/index.html": r'''
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GorillaGuard — Anti-Cheat Hub</title>
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
<div class="bg-orb one"></div><div class="bg-orb two"></div>
<header>
  <div class="brand"><div class="logo">🦍</div><div><b>GorillaGuard</b><small>ANTI-CHEAT HUB</small></div></div>
  <nav><a href="#browse">Browse</a><a href="#revisions">Revisions</a><a href="#backend">Backend</a></nav>
  <div class="online"><i></i> SYSTEM ONLINE</div>
</header>

<main>
<section class="hero">
  <div class="hero-copy">
    <div class="eyebrow">FOR YOUR OWN GTAG-STYLE GAME</div>
    <h1>Build a safer<br><span>gorilla world.</span></h1>
    <p>Browse defensive anti-cheat modules, organize revisions, and choose what belongs in your Flask backend.</p>
    <div class="actions"><a class="button green" href="#browse">Browse Anti-Cheat</a><a class="button" href="#revisions">Revision Center</a></div>
  </div>
  <div class="hero-art">
    <div class="circle"></div><div class="gorilla">🦍</div>
    <div class="float f1">SERVER AUTHORITATIVE</div><div class="float f2">SECURE AUTH</div><div class="float f3">DISCORD ALERTS</div>
  </div>
</section>

<section class="quick">
  <div><b>{{ modules|length }}</b><span>MODULES</span></div>
  <div><b>3</b><span>REVISION TRACK</span></div>
  <div><b>FLASK</b><span>BACKEND</span></div>
  <div><b>V2</b><span>ARCHITECTURE</span></div>
</section>

<section id="browse" class="section">
  <div class="heading"><div><label>01 / BROWSE</label><h2>Anti-Cheat Modules</h2></div><div class="search"><span>⌕</span><input id="search" placeholder="Search modules..."></div></div>
  <div class="filters" id="filters"></div>
  <div class="grid" id="grid">
  {% for m in modules %}
    <article class="card" data-search="{{ (m.name ~ ' ' ~ m.category ~ ' ' ~ m.description ~ ' ' ~ m.tags|join(' '))|lower }}" data-category="{{m.category}}">
      <div class="top"><span class="module-icon">{{m.icon}}</span><span class="risk {{m.risk|lower}}">{{m.risk}}</span></div>
      <div class="category">{{m.category}}</div>
      <h3>{{m.name}}</h3><p>{{m.description}}</p>
      <div class="tags">{% for t in m.tags %}<span>#{{t}}</span>{% endfor %}</div>
      <button onclick="viewModule('{{m.id}}')">View module <b>→</b></button>
    </article>
  {% endfor %}
  </div>
</section>

<section id="backend" class="backend">
  <div><label>02 / INSTALLATION MODEL</label><h2>Keep the active backend separate.</h2><p>Modules selected for your game belong in the server-side Flask backend. The revision system is a separate lane for drafts and history.</p></div>
  <div class="flow"><div>🧑‍💻<b>Game Developer</b><small>Chooses modules</small></div><em>→</em><div>🛡️<b>Backend</b><small>Active protection</small></div><em>→</em><div>📊<b>Detection</b><small>Log + alert</small></div></div>
</section>

<section id="revisions" class="section">
  <div class="heading"><div><label>03 / REVISION CENTER</label><h2>Separate revision anti-cheat</h2></div><button class="new" onclick="openRevision()">+ New Revision</button></div>
  <div class="timeline">
  {% for r in revisions %}
    <div class="revision"><div class="dot"></div><div class="ver">{{r.version}}</div><div><h3>{{r.name}} <small>{{r.status}}</small></h3><ul>{% for c in r.changes %}<li>{{c}}</li>{% endfor %}</ul></div></div>
  {% endfor %}
  </div>
</section>
</main>

<div id="modal" class="modal" onclick="if(event.target===this)closeModal()"><div class="modalbox"><button class="close" onclick="closeModal()">×</button><div id="modalContent"></div></div></div>

<footer>GORILLAGUARD • FLASK / VERCEL • <a href="/hello-world">BACKEND STATUS</a></footer>
<script>
const modules = {{ modules|tojson }};
const cats = ["All", ...new Set(modules.map(x=>x.category))];
const filters = document.getElementById("filters");
cats.forEach((c,i)=>{let b=document.createElement("button");b.textContent=c;b.className=i===0?"active":"";b.onclick=()=>filter(c,b);filters.appendChild(b)});
let selected="All";
function filter(c,btn){selected=c;document.querySelectorAll(".filters button").forEach(x=>x.classList.remove("active"));btn.classList.add("active");apply();}
document.getElementById("search").addEventListener("input",apply);
function apply(){let q=document.getElementById("search").value.toLowerCase();document.querySelectorAll(".card").forEach(x=>x.style.display=((selected==="All"||x.dataset.category===selected)&&x.dataset.search.includes(q))?"block":"none")}
function viewModule(id){let m=modules.find(x=>x.id===id);document.getElementById("modalContent").innerHTML=`<div class="bigicon">${m.icon}</div><label>${m.category}</label><h2>${m.name}</h2><p>${m.description}</p><div class="modalrisk">${m.risk} SECURITY</div><h4>Module tags</h4><div class="tags">${m.tags.map(x=>`<span>#${x}</span>`).join("")}</div><div class="install"><b>Add to Backend</b><span>Connect this module to your Flask anti-cheat implementation.</span></div>`;document.getElementById("modal").classList.add("show")}
function openRevision(){document.getElementById("modalContent").innerHTML=`<label>REVISION CENTER</label><h2>Create a revision</h2><p>Use revisions to prepare and track changes separately from the active backend.</p><input id="rv" class="field" placeholder="Version e.g. v4.0"><input id="rn" class="field" placeholder="Name"><textarea id="rc" class="field" placeholder="One change per line"></textarea><button class="button green" onclick="createRevision()">Create Draft</button>`;document.getElementById("modal").classList.add("show")}
async function createRevision(){let version=document.getElementById("rv").value,name=document.getElementById("rn").value,changes=document.getElementById("rc").value.split("\n").map(x=>x.trim()).filter(Boolean);let r=await fetch("/api/revisions",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({version,name,changes})});if(r.ok){location.reload()}else{alert("Could not create revision")}}
function closeModal(){document.getElementById("modal").classList.remove("show")}
</script>
</body>
</html>
''',

"static/style.css": r'''
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=Space+Grotesk:wght@500;600;700&display=swap');
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:#070a08;color:#edf3ee;font-family:Inter,Arial,sans-serif}body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.18;background-image:linear-gradient(#fff1 1px,transparent 1px),linear-gradient(90deg,#fff1 1px,transparent 1px);background-size:44px 44px}.bg-orb{position:fixed;width:450px;height:450px;border-radius:50%;filter:blur(130px);opacity:.12;pointer-events:none}.one{background:#52f084;left:-200px;top:-200px}.two{background:#9b5cff;right:-250px;top:500px}
header{height:74px;border-bottom:1px solid #1c241f;background:#080c0ae8;backdrop-filter:blur(15px);display:flex;align-items:center;padding:0 5vw;gap:38px;position:sticky;top:0;z-index:10}.brand{display:flex;align-items:center;gap:10px;margin-right:auto}.logo{font-size:32px}.brand b{font-family:"Space Grotesk";font-size:18px;display:block}.brand small{font-size:8px;color:#6e7c72;letter-spacing:2px}.online{font-size:9px;letter-spacing:1.2px;color:#7e8a83}.online i{display:inline-block;width:7px;height:7px;background:#69ef91;border-radius:50%;box-shadow:0 0 12px #69ef91;margin-right:7px}nav{display:flex;gap:25px}nav a{color:#8a958e;text-decoration:none;font-size:11px}nav a:hover{color:#77ee9a}
main{max-width:1180px;margin:auto;padding:0 24px}.hero{min-height:560px;display:grid;grid-template-columns:1.1fr .9fr;align-items:center}.eyebrow,label{color:#72ed98;font-size:9px;font-weight:800;letter-spacing:2px}.hero h1{font:700 clamp(54px,7vw,90px)/.9 "Space Grotesk";letter-spacing:-5px;margin:15px 0}.hero h1 span{color:#79f29b}.hero p{color:#849089;line-height:1.7;max-width:550px;font-size:14px}.actions{display:flex;gap:10px;margin-top:28px}.button,.new{display:inline-block;border:1px solid #29342e;background:#0d120f;color:#eaf0ec;padding:12px 16px;border-radius:9px;text-decoration:none;font-weight:700;font-size:11px;cursor:pointer}.button.green{background:#77ee9b;color:#061009;border-color:#77ee9b}.hero-art{height:420px;position:relative;display:grid;place-items:center}.circle{position:absolute;width:330px;height:330px;border:1px solid #31513b;border-radius:50%;box-shadow:0 0 90px #58ed7b14,inset 0 0 70px #58ed7b0b}.gorilla{font-size:170px;filter:drop-shadow(0 30px 25px #000);z-index:2}.float{position:absolute;background:#0e1511;border:1px solid #2c3d32;border-radius:7px;padding:8px 10px;font-size:8px;letter-spacing:1px;color:#aab5ad;z-index:3}.f1{right:5px;top:70px}.f2{left:20px;top:165px}.f3{right:25px;bottom:75px}
.quick{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:90px}.quick div{border:1px solid #1e2822;background:#0b100d;border-radius:11px;padding:19px}.quick b{font:700 21px "Space Grotesk";display:block}.quick span{font-size:8px;color:#657068;letter-spacing:1.5px;display:block;margin-top:6px}
.section{padding:55px 0 90px}.heading{display:flex;justify-content:space-between;align-items:end;margin-bottom:22px}.heading h2,.backend h2{font:700 35px "Space Grotesk";letter-spacing:-1.5px;margin:7px 0 0}.search{border:1px solid #253029;background:#0b100d;border-radius:9px;padding:0 12px;display:flex;align-items:center}.search span{color:#77857b}.search input{border:0;outline:0;background:none;color:#fff;padding:11px;width:220px;font-size:11px}.filters{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:14px}.filters button{border:1px solid #202a24;background:#0b100d;color:#7f8a83;padding:7px 10px;border-radius:999px;font-size:9px;cursor:pointer}.filters button.active{background:#17321f;border-color:#3b714c;color:#83efa0}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.card{border:1px solid #202923;background:linear-gradient(145deg,#0d130f,#090d0b);border-radius:13px;padding:18px;transition:.2s}.card:hover{transform:translateY(-3px);border-color:#3d5946}.top{display:flex;justify-content:space-between}.module-icon{font-size:23px}.risk{font-size:8px;border-radius:5px;padding:5px 7px}.risk.medium{background:#211b0d;color:#e9c96d}.risk.high{background:#21120e;color:#ff9578}.risk.critical{background:#280d12;color:#ff778c}.category{color:#62d786;text-transform:uppercase;letter-spacing:1.2px;font-size:8px;margin-top:18px}.card h3{font-size:14px;margin:8px 0}.card p{font-size:11px;color:#7f8a83;line-height:1.6;min-height:53px}.tags{display:flex;gap:5px;flex-wrap:wrap;margin:13px 0}.tags span{font-size:8px;color:#65716a;background:#111914;padding:5px 6px;border-radius:5px}.card button{width:100%;border:1px solid #29342e;background:#111713;color:#dce5df;padding:9px;border-radius:7px;font-size:9px;cursor:pointer}.card button b{float:right;color:#7aed99}
.backend{margin:0 0 70px;padding:40px;border:1px solid #253229;border-radius:16px;background:linear-gradient(120deg,#0c140f,#0a0d0b);display:grid;grid-template-columns:1fr 1fr;gap:40px;align-items:center}.backend p{font-size:11px;color:#7e8982;line-height:1.7;max-width:500px}.flow{display:flex;align-items:center;justify-content:center;gap:10px}.flow div{min-width:115px;text-align:center;background:#111713;border:1px solid #26342b;padding:18px 8px;border-radius:10px;font-size:20px}.flow b,.flow small{display:block}.flow b{font-size:9px;margin-top:8px}.flow small{font-size:7px;color:#68746c;margin-top:4px}.flow em{color:#70eb95;font-style:normal}
.timeline{border-left:1px solid #2a342e;margin:25px 0 0 10px}.revision{position:relative;display:grid;grid-template-columns:80px 1fr;gap:18px;padding:0 0 32px 28px}.dot{position:absolute;left:-5px;top:4px;width:9px;height:9px;border-radius:50%;background:#77ed99;box-shadow:0 0 13px #77ed99}.ver{font:700 19px "Space Grotesk";color:#77ed99}.revision h3{margin:0;font-size:14px}.revision small{font-size:7px;border:1px solid #303832;padding:4px 6px;border-radius:4px;color:#79837d;margin-left:6px}.revision ul{padding-left:16px;color:#7e8981;font-size:10px;line-height:1.9}
.modal{position:fixed;inset:0;background:#000b;backdrop-filter:blur(8px);display:none;align-items:center;justify-content:center;z-index:30;padding:20px}.modal.show{display:flex}.modalbox{position:relative;width:min(520px,100%);background:#0b100d;border:1px solid #314036;border-radius:16px;padding:28px;box-shadow:0 30px 80px #000}.close{position:absolute;right:15px;top:12px;background:none;border:0;color:#7f8a83;font-size:25px;cursor:pointer}.modalbox h2{font:700 30px "Space Grotesk";margin:8px 0}.modalbox p{color:#849087;font-size:11px;line-height:1.7}.bigicon{font-size:42px}.modalrisk{display:inline-block;color:#7aef99;background:#13251a;border:1px solid #315b3d;border-radius:6px;padding:6px 8px;font-size:8px;margin:8px 0}.install{margin-top:20px;border:1px solid #294334;background:#0f1b13;padding:13px;border-radius:9px}.install b,.install span{display:block}.install b{font-size:10px;color:#8cf2a5}.install span{font-size:9px;color:#728078;margin-top:4px}.field{display:block;width:100%;margin:9px 0;padding:11px;border:1px solid #28342d;background:#070b09;color:#eef5ef;border-radius:8px;outline:none;font:11px Inter}.field{resize:vertical;min-height:45px}footer{border-top:1px solid #1c241f;text-align:center;padding:28px;color:#59645d;font-size:8px;letter-spacing:1.5px}footer a{color:#76ed98;text-decoration:none}
@media(max-width:850px){nav{display:none}.hero{grid-template-columns:1fr;padding:60px 0 30px}.hero-art{height:300px}.gorilla{font-size:120px}.quick{grid-template-columns:1fr 1fr}.grid{grid-template-columns:1fr 1fr}.backend{grid-template-columns:1fr}.flow{flex-wrap:wrap}}@media(max-width:550px){main{padding:0 16px}.grid{grid-template-columns:1fr}.heading{align-items:start;flex-direction:column;gap:12px}.search,.search input{width:100%}.search{width:100%}.hero h1{font-size:55px}.hero-art{height:260px}.circle{width:230px;height:230px}.gorilla{font-size:100px}}
''',

"requirements.txt": "Flask>=3.1,<4\n",
"vercel.py": "from app import app\n",
"vercel.json": r'''{
  "version": 2,
  "builds": [{"src": "vercel.py", "use": "@vercel/python"}],
  "routes": [{"src": "/(.*)", "dest": "vercel.py"}]
}''',
"README.md": r'''# GorillaGuard Anti-Cheat Hub

A Flask/Vercel dashboard for developers making their own Gorilla Tag-style games.

## What it does

- Browse anti-cheat modules.
- Search and filter modules.
- View module details.
- Keep backend anti-cheat separate from revision history.
- Create revision drafts through the API.
- Includes a `/hello-world` endpoint.

## Deploy

Upload the project to a Vercel project and deploy it as a Python project.

This is a dashboard/catalog starter. The "Add to Backend" UI is intentionally a management surface; each actual anti-cheat module must be integrated with the game's real authoritative server and authentication provider.

Do not put Discord webhook secrets or authentication secrets in browser/client code.
'''
}

for path, content in files.items():
    with open(os.path.join(root,path),"w",encoding="utf-8") as f:
        f.write(content.strip()+"\n")

zip_path="/mnt/data/gorillaguard_anti_cheat_hub.zip"
with zipfile.ZipFile(zip_path,"w",zipfile.ZIP_DEFLATED) as z:
    for d,_,fs in os.walk(root):
        for f in fs:
            p=os.path.join(d,f)
            z.write(p,os.path.relpath(p,root))

print(zip_path)
