const enc = new TextEncoder();

const toHex = buf =>
  [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,"0")).join("");
const toB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const encode = (buf, fmt) => fmt === "b64" ? toB64(buf) : toHex(buf);
const currentEnc = () => document.querySelector('input[name=enc]:checked').value;

// ---- feature detection ----
async function supports(algo){
  try { await crypto.subtle.digest(algo, enc.encode("x")); return true; }
  catch(e){ return false; }
}

// digest algorithms to attempt (native + aspirational SHA-3 / SHAKE)
const DIGESTS = [
  {algo:"SHA-1",   label:"SHA-1",   bits:160},
  {algo:"SHA-256", label:"SHA-256", bits:256},
  {algo:"SHA-384", label:"SHA-384", bits:384},
  {algo:"SHA-512", label:"SHA-512", bits:512},
  {algo:"SHA3-256",label:"SHA3-256",bits:256},
  {algo:"SHA3-384",label:"SHA3-384",bits:384},
  {algo:"SHA3-512",label:"SHA3-512",bits:512},
];
// MD5 and RIPEMD-160 are not in SubtleCrypto — they get their own
// external-library section below, so nothing is listed as absent here.
const ABSENT = [];

const HMACS = [
  {algo:"SHA-1",   label:"HMAC-SHA1"},
  {algo:"SHA-256", label:"HMAC-SHA256"},
  {algo:"SHA-384", label:"HMAC-SHA384"},
  {algo:"SHA-512", label:"HMAC-SHA512"},
];

// external-library digests (loaded as separate scripts, namespaced)
const LIBS = [
  {id:"md5",        label:"MD5",          bits:128, fn:s=>MD5lib.hex_md5(s)},
  {id:"hmac-md5",   label:"HMAC-MD5",     bits:128, fn:(s,k)=>MD5lib.hex_hmac_md5(k,s), keyed:true},
  {id:"rmd160",     label:"RIPEMD-160",   bits:160, fn:s=>RMD160lib.hex_rmd160(s)},
  {id:"hmac-rmd160",label:"HMAC-RIPEMD160",bits:160,fn:(s,k)=>RMD160lib.hex_hmac_rmd160(k,s), keyed:true},
];

// SHA-3 family from js-sha3 (loaded via CDN). Functions are globals.
const SHA3S = [
  {id:"sha3-224",   label:"SHA3-224",   bits:224, fn:s=>sha3_224(s)},
  {id:"sha3-256",   label:"SHA3-256",   bits:256, fn:s=>sha3_256(s)},
  {id:"sha3-384",   label:"SHA3-384",   bits:384, fn:s=>sha3_384(s)},
  {id:"sha3-512",   label:"SHA3-512",   bits:512, fn:s=>sha3_512(s)},
  {id:"keccak-224", label:"Keccak-224", bits:224, fn:s=>keccak224(s)},
  {id:"keccak-256", label:"Keccak-256", bits:256, fn:s=>keccak256(s)},
  {id:"keccak-384", label:"Keccak-384", bits:384, fn:s=>keccak384(s)},
  {id:"keccak-512", label:"Keccak-512", bits:512, fn:s=>keccak512(s)},
];

function rowHTML(id, name, sub, bits){
  return `<div class="row" id="wrap-${id}">
    <div class="name">${name}${sub?`<small>${sub}</small>`:""}</div>
    <div class="out" id="${id}"></div>
    <button class="copy" data-for="${id}" title="Copy" aria-label="Copy ${name}"><i>⧉</i></button>
  </div>`;
}

let digestList = [];  // populated after feature detection

async function buildDigestRows(){
  const host = document.getElementById("digestRows");
  let html = "";
  for(const d of DIGESTS){
    const ok = await supports(d.algo);
    if(ok){
      digestList.push(d);
      html += rowHTML("dg-"+d.algo, d.label, d.bits+"-bit");
    } else {
      html += `<div class="row unsupported">
        <div class="name">${d.label}<small>${d.bits}-bit</small></div>
        <div class="out">not supported by this browser</div>
        <span class="bits"></span></div>`;
    }
  }
  for(const a of ABSENT){
    html += `<div class="row unsupported">
      <div class="name">${a.label}<small>${a.bits}-bit</small></div>
      <div class="out">${a.why}</div><span class="bits"></span></div>`;
  }
  host.innerHTML = html;
}

function buildHmacRows(){
  document.getElementById("hmacRows").innerHTML =
    HMACS.map(h => rowHTML("hm-"+h.algo, h.label, "")).join("");
}

function buildLibRows(){
  document.getElementById("libRows").innerHTML =
    LIBS.map(l => rowHTML("lib-"+l.id, l.label,
      (l.bits+"-bit")+(l.keyed?" · keyed":""))).join("");
}

function refreshLib(){
  const msg = document.getElementById("lib-msg").value;
  const key = document.getElementById("lib-key").value;
  for(const l of LIBS){
    const el = document.getElementById("lib-"+l.id);
    try{
      el.textContent = l.keyed ? l.fn(msg, key) : l.fn(msg);
      el.classList.remove("err");
    }catch(e){ el.textContent="error"; el.classList.add("err"); }
  }
}

const sha3Ready = () => typeof sha3_256 === "function";

function buildSha3Rows(){
  document.getElementById("sha3Rows").innerHTML =
    SHA3S.map(s => rowHTML("sha3-out-"+s.id, s.label, s.bits+"-bit")).join("");
}

function refreshSha3(){
  const msg = document.getElementById("sha3-msg").value;
  for(const s of SHA3S){
    const el = document.getElementById("sha3-out-"+s.id);
    if(!sha3Ready()){ el.textContent = "library failed to load"; el.classList.add("err"); continue; }
    try{ el.textContent = s.fn(msg); el.classList.remove("err"); }
    catch(e){ el.textContent="error"; el.classList.add("err"); }
  }
}

async function refreshDigests(){
  const msg = document.getElementById("msg").value;
  const fmt = currentEnc();
  const data = enc.encode(msg);
  for(const d of digestList){
    try{
      const buf = await crypto.subtle.digest(d.algo, data);
      document.getElementById("dg-"+d.algo).textContent = encode(buf, fmt);
    }catch(e){
      const el = document.getElementById("dg-"+d.algo);
      el.textContent = "error"; el.classList.add("err");
    }
  }
}

async function hmacKey(keyStr, hash){
  return crypto.subtle.importKey("raw", enc.encode(keyStr),
    {name:"HMAC", hash}, false, ["sign"]);
}
async function refreshHmac(){
  const msg = enc.encode(document.getElementById("hmac-msg").value);
  const keyStr = document.getElementById("hmac-key").value;
  const fmt = currentEnc();
  for(const h of HMACS){
    const el = document.getElementById("hm-"+h.algo);
    try{
      const key = await hmacKey(keyStr, h.algo);
      const sig = await crypto.subtle.sign("HMAC", key, msg);
      el.textContent = encode(sig, fmt); el.classList.remove("err");
    }catch(e){ el.textContent="error"; el.classList.add("err"); }
  }
}

async function pbkdf2(passStr, saltStr, iterations, bytes, hash, outEl){
  outEl.classList.remove("err");
  if(!passStr || !saltStr){ outEl.textContent="enter a password and salt"; outEl.classList.add("err"); return; }
  outEl.textContent = "computing…";
  try{
    const base = await crypto.subtle.importKey("raw", enc.encode(passStr),
      "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      {name:"PBKDF2", salt:enc.encode(saltStr), iterations:+iterations, hash},
      base, bytes*8);
    outEl.textContent = encode(bits, currentEnc());
  }catch(e){ outEl.textContent = "error: "+e.message; outEl.classList.add("err"); }
}

// ---- wiring ----
function debounce(fn,ms){let t;return()=>{clearTimeout(t);t=setTimeout(fn,ms)}}

(async function init(){
  await buildDigestRows();
  buildHmacRows();
  buildLibRows();
  buildSha3Rows();

  const dq = debounce(refreshDigests,80);
  const hq = debounce(refreshHmac,80);
  const lq = debounce(refreshLib,80);
  const sq = debounce(refreshSha3,80);
  document.getElementById("msg").addEventListener("input", dq);
  document.getElementById("hmac-msg").addEventListener("input", hq);
  document.getElementById("hmac-key").addEventListener("input", hq);
  document.getElementById("lib-msg").addEventListener("input", lq);
  document.getElementById("lib-key").addEventListener("input", lq);
  document.getElementById("sha3-msg").addEventListener("input", sq);
  document.querySelectorAll('input[name=enc]').forEach(r =>
    r.addEventListener("change", ()=>{refreshDigests();refreshHmac();}));

  document.getElementById("p-go").addEventListener("click", ()=>{
    pbkdf2(
      document.getElementById("p-pass").value,
      document.getElementById("p-salt").value,
      document.getElementById("p-iter").value,
      +document.getElementById("p-bytes").value,
      document.querySelector('input[name=pHash]:checked').value,
      document.getElementById("p-out"));
  });
  document.getElementById("w-go").addEventListener("click", ()=>{
    pbkdf2(
      document.getElementById("w-pass").value,
      document.getElementById("w-ssid").value,
      4096, 32, "SHA-1",
      document.getElementById("w-out"));
  });

  // copy buttons
  document.body.addEventListener("click", async (e)=>{
    const btn = e.target.closest(".copy"); if(!btn) return;
    const txt = document.getElementById(btn.dataset.for).textContent;
    if(!txt || txt==="—") return;
    try{ await navigator.clipboard.writeText(txt);
      btn.classList.add("done"); setTimeout(()=>btn.classList.remove("done"),900);
    }catch(e){}
  });

  refreshDigests(); refreshHmac(); refreshLib(); refreshSha3();
})();

// set the footer copyright year
document.getElementById("year").textContent = new Date().getFullYear();
