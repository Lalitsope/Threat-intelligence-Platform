import React, { useState } from 'react';
import {
  Shield, LayoutDashboard, Globe, Network, ScanSearch, FileSearch, Bug,
  ShieldAlert, MailWarning, Rss, Target, Newspaper, Search, Bell, Settings,
  ChevronRight, Activity, AlertTriangle, Radar, FileUp, ExternalLink, Menu
} from 'lucide-react';

const API = 'http://127.0.0.1:8001';
const modules = [
  { id:'dashboard', label:'Dashboard', icon:LayoutDashboard, group:'OVERVIEW' },
  { id:'ip', label:'IP Intelligence', icon:Globe, group:'INVESTIGATION' },
  { id:'domain', label:'Domain Intelligence', icon:Network, group:'INVESTIGATION' },
  { id:'url', label:'URL Scanner', icon:ScanSearch, group:'INVESTIGATION' },
  { id:'hash', label:'Hash Analyzer', icon:FileSearch, group:'INVESTIGATION' },
  { id:'malware', label:'Malware Intelligence', icon:Bug, group:'THREAT ANALYSIS' },
  { id:'cve', label:'CVE Intelligence', icon:ShieldAlert, group:'THREAT ANALYSIS' },
  { id:'phishing', label:'Phishing Intelligence', icon:MailWarning, group:'THREAT ANALYSIS' },
  { id:'feeds', label:'Threat Feeds', icon:Rss, group:'MONITORING' },
  { id:'mitre', label:'MITRE ATT&CK', icon:Target, group:'MONITORING' },
  { id:'news', label:'Cyber Threat News', icon:Newspaper, group:'MONITORING' },
];

const descriptions = {
 ip:'Investigate IPv4 and IPv6 addresses, reputation, ASN and abuse intelligence.',
 domain:'Inspect domain registration, DNS records, certificates and reputation.',
 url:'Check a URL for phishing, malware indicators and reputation matches.',
 hash:'Search a file hash or upload a sample to calculate its cryptographic hashes.',
 malware:'Upload a sample for static inspection or submit it to an isolated dynamic sandbox.',
 cve:'Look up vulnerability intelligence using a CVE identifier.',
 phishing:'Investigate a domain or sender and inspect raw email headers for phishing signals.',
 feeds:'Search and filter indicators collected from trusted threat intelligence feeds.',
 mitre:'Explore adversary tactics, techniques, groups and mitigations.',
 news:'Search cybersecurity incidents, advisories, ransomware and breach reporting.'
};

function App(){
 const [active,setActive] = useState('dashboard');
 const [mobileOpen,setMobileOpen] = useState(false);
 const [busy,setBusy] = useState(false);
 const [result,setResult] = useState(null);
 const [error,setError] = useState('');
 const [form,setForm] = useState({ip:'',domain:'',url:'',hash:'',cve:'',phishMode:'domain',phishValue:'',header:'',scanType:'static',query:'',category:'all',timeframe:'7d'});
 const [file,setFile] = useState(null);
 const [hashMode,setHashMode] = useState('hash');
 const current = modules.find(m=>m.id===active);
 const update = (key,value)=>setForm(old=>({...old,[key]:value}));
 const choose = id=>{setActive(id);setResult(null);setError('');setFile(null);setMobileOpen(false);};

 async function submit(e){
  e.preventDefault(); setBusy(true); setError(''); setResult(null);
  try{
   let response;
   if(active==='hash' && hashMode==='file' && !file) throw new Error('Choose a file to upload.');
   if(active==='hash' && hashMode==='file' && file){
    const fd=new FormData(); fd.append('file',file);
    response=await fetch(`${API}/api/hash/upload`,{method:'POST',body:fd});
   } else if(active==='malware'){
    if(!file) throw new Error('Choose a file first.');
    const fd=new FormData(); fd.append('file',file); fd.append('scan_type',form.scanType);
    response=await fetch(`${API}/api/malware/scan`,{method:'POST',body:fd});
   } else {
    const routes={
     ip:['/api/ip',{ip:form.ip}],
     domain:['/api/domain',{domain:form.domain}],
     url:['/api/url',{url:form.url}],
     hash:['/api/hash',{value:form.hash}],
     cve:['/api/cve',{cve_id:form.cve}],
     phishing:['/api/phishing',{mode:form.phishMode,value:form.phishValue,email_header:form.header}],
     feeds:['/api/feeds/search',{query:form.query,category:form.category,timeframe:form.timeframe}],
     mitre:['/api/mitre/search',{query:form.query,category:form.category,timeframe:form.timeframe}],
     news:['/api/news/search',{query:form.query,category:form.category,timeframe:form.timeframe}]
    };
    const [path,body]=routes[active];
    response=await fetch(API+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
   }
   const data=await response.json();
   if(!response.ok) throw new Error(data.detail||'Request failed.');
   setResult(data);
  }catch(err){setError(err.message.includes('Failed to fetch')?'Cannot reach the backend. Start FastAPI at http://127.0.0.1:8001.':err.message);}
  finally{setBusy(false);}
 }

 const field=(label,key,placeholder,type='text')=><label className="field"><span>{label}</span><input type={type} value={form[key]} onChange={e=>update(key,e.target.value)} placeholder={placeholder} required/></label>;
 const filePicker=<label className="upload"><FileUp size={25}/><strong>{file?file.name:'Drop a sample here or browse files'}</strong><small>Maximum 20 MB in this demo. Uploaded files are not executed.</small><input type="file" onChange={e=>setFile(e.target.files?.[0]||null)}/></label>;
 const select=(label,key,options)=><label className="field"><span>{label}</span><select value={form[key]} onChange={e=>update(key,e.target.value)}>{options.map(o=><option key={o[0]} value={o[0]}>{o[1]}</option>)}</select></label>;

 function renderForm(){
  if(active==='ip') return <>{field('IP ADDRESS','ip','Enter IPv4 or IPv6 address')}</>;
  if(active==='domain') return <>{field('DOMAIN NAME','domain','example.com')}</>;
  if(active==='url') return <>{field('FULL URL','url','https://example.com/path')}</>;
  if(active==='hash') return <><div className="choice"><label><input type="radio" checked={hashMode==='hash'} onChange={()=>{setHashMode('hash');setFile(null);}}/> Enter hash</label><label><input type="radio" checked={hashMode==='file'} onChange={()=>{setHashMode('file');update('hash','');}}/> Upload file</label></div>{hashMode==='hash'?field('HASH VALUE','hash','MD5 / SHA1 / SHA256'):filePicker}</>;
  if(active==='malware') return <>{filePicker}{select('SCAN TYPE','scanType',[['static','Static analysis'],['dynamic','Dynamic analysis (sandbox integration required)']])}<div className="notice"><AlertTriangle size={16}/> Dynamic analysis is not executed by this starter. Connect a separately isolated malware sandbox.</div></>;
  if(active==='cve') return <>{field('CVE IDENTIFIER','cve','CVE-2024-12345')}</>;
  if(active==='phishing') return <>{select('INVESTIGATION TYPE','phishMode',[['domain','Domain name'],['email','Email address']])}{field(form.phishMode==='domain'?'DOMAIN NAME':'EMAIL ADDRESS','phishValue',form.phishMode==='domain'?'suspicious-domain.com':'sender@example.com',form.phishMode==='email'?'email':'text')}<label className="field"><span>PASTE EMAIL HEADER <em>Optional for domain investigations</em></span><textarea rows="6" value={form.header} onChange={e=>update('header',e.target.value)} placeholder={'Received: from mail.example.com...\\nFrom: sender@example.com\\nAuthentication-Results: ...'}/></label></>;
  if(['feeds','mitre','news'].includes(active)) return <>{field('SEARCH QUERY','query',active==='mitre'?'T1059 / PowerShell / APT29':active==='news'?'Ransomware / data breach':'IP / domain / malware')}{select('CATEGORY','category',[['all','All categories'],['malware','Malware'],['phishing','Phishing'],['ransomware','Ransomware'],['vulnerability','Vulnerability'],['apt','Threat actors']])}{select('TIME RANGE','timeframe',[['24h','Last 24 hours'],['7d','Last 7 days'],['30d','Last 30 days']])}</>;
  return null;
 }

 return <div className="app-shell">
  <aside className={`sidebar ${mobileOpen?'open':''}`}>
   <div className="brand"><div className="brand-mark"><Shield size={22}/></div><div><b>THREAT<span>INTEL</span></b><small>INTELLIGENCE PLATFORM</small></div></div>
   <div className="side-status"><i/> SYSTEM OPERATIONAL <span>v1.0</span></div>
   {['OVERVIEW','INVESTIGATION','THREAT ANALYSIS','MONITORING'].map(group=><div className="nav-group" key={group}><div className="nav-label">{group}</div>{modules.filter(m=>m.group===group).map(m=>{const Icon=m.icon;return <button key={m.id} className={`nav-item ${active===m.id?'active':''}`} onClick={()=>choose(m.id)}><Icon size={17}/><span>{m.label}</span>{active===m.id&&<ChevronRight size={15} className="nav-arrow"/>}</button>})}</div>)}
   <div className="sidebar-bottom"><button className="nav-item"><Settings size={17}/> Settings</button><div className="profile"><div className="avatar">A</div><div><b>Security Analyst</b><small>LOCAL WORKSPACE</small></div><span className="online-dot"/></div></div>
  </aside>
  <main className="main">
   <header className="topbar"><button className="mobile-menu" onClick={()=>setMobileOpen(!mobileOpen)}><Menu/></button><div className="crumb">THREAT INTELLIGENCE <span>/</span> <b>{current?.label||'DASHBOARD'}</b></div><div className="top-actions"><div className="live"><i/> LIVE SYSTEM</div><button className="icon-button" title="Notifications"><Bell size={18}/></button><div className="top-avatar">A</div></div></header>
   {active==='dashboard'?<Dashboard choose={choose}/>:<section className="content">
    <div className="page-heading"><div><div className="eyebrow"><span className="pulse"/> INVESTIGATION MODULE</div><h1>{current.label}</h1><p>{descriptions[active]}</p></div><div className="module-icon"><current.icon size={25}/></div></div>
    <div className="work-grid"><section className="panel form-panel"><div className="panel-title"><div><span className="tiny-label">NEW INVESTIGATION</span><h2>Submit an indicator</h2></div><span className="lock-tag"><Shield size={13}/> SECURE INPUT</span></div><form onSubmit={submit}>{renderForm()}<button className="primary-btn" disabled={busy}>{busy?<><span className="spinner"/> ANALYZING...</>:<><Search size={16}/> START INVESTIGATION</>}</button></form><div className="form-foot"><Shield size={13}/> Inputs are sent to your local API service.</div></section>
     <section className="panel result-panel"><div className="panel-title"><div><span className="tiny-label">INTELLIGENCE OUTPUT</span><h2>Analysis report</h2></div><span className="result-state">{result?'RESULT RECEIVED':'AWAITING INPUT'}</span></div>{error?<div className="error-box"><AlertTriangle/>{error}</div>:result?<Result data={result}/>:<div className="empty-result"><div className="radar"><Radar size={45}/></div><b>No investigation yet</b><p>Submit an indicator to view its intelligence report here.</p><small>AWAITING ANALYST INPUT...</small></div>}</section>
    </div>
    <div className="bottom-hint"><Activity size={15}/> <span>TIP:</span> {active==='malware'?'Use static analysis first. Dynamic analysis must run in a dedicated sandbox.':active==='phishing'?'Paste complete raw headers for better sender-path and authentication analysis.':'Connect trusted intelligence providers to replace demo responses with verified findings.'}</div>
   </section>}
   <footer><span>THREATINTEL HUB <b>v1.0.0</b></span><span>BUILT FOR DEFENSIVE SECURITY OPERATIONS <i/></span></footer>
  </main>
 </div>
}

function Result({data}){
 const sources = Array.isArray(data.sources) ? data.sources : [];
 const format = value => value === null || value === undefined || value === '' ? '—' : (typeof value === 'object' ? JSON.stringify(value) : String(value));
 return <div className="report">
  <div className="report-banner"><div><small>ANALYSIS STATUS</small><h3>{data.status}</h3></div><span className="demo-pill">{data.verdict || 'UNKNOWN'}</span></div>
  <div className="report-row"><span>MODULE</span><b>{data.module}</b></div>
  <div className="report-row"><span>SUBMITTED INDICATOR</span><code>{data.submitted}</code></div>
  <div className="report-row"><span>VERDICT</span><b>{data.verdict || 'Unknown'}</b></div>
  <div className="report-message">{data.message}</div>
  {Object.keys(data.details||{}).length>0&&<><h4>INVESTIGATION DETAILS</h4>{Object.entries(data.details||{}).map(([k,v])=><div className="report-row" key={k}><span>{k.replaceAll('_',' ').toUpperCase()}</span><b>{format(v)}</b></div>)}</>}
  <h4>INTELLIGENCE SOURCES</h4>
  {sources.length ? sources.map((source,i)=><div className="source-card" key={`${source.name}-${i}`}>
   <div className="source-head"><b>{source.name}</b><span className={`source-status ${source.status}`}>{source.status.replaceAll('_',' ').toUpperCase()}</span></div>
   <p>{source.summary}</p>
   {Object.entries(source.details||{}).filter(([k,v])=>v!==null&&v!==undefined&&v!=='').map(([k,v])=><div className="report-row" key={k}><span>{k.replaceAll('_',' ').toUpperCase()}</span><b>{format(v)}</b></div>)}
   {source.details?.result_url&&<a className="source-link" href={source.details.result_url} target="_blank" rel="noreferrer">Open urlscan report ↗</a>}
   {source.details?.url&&<a className="source-link" href={source.details.url} target="_blank" rel="noreferrer">Open NVD record ↗</a>}
  </div>) : <p className="muted">No source data returned.</p>}
 </div>
}

function Dashboard({choose}){
 const stats=[['IOCS TRACKED','—','Database not connected'],['MALICIOUS IPS','—','Provider not connected'],['OPEN CVES','—','NVD integration pending'],['ACTIVE ALERTS','—','Feed integration pending']];
 return <section className="content dashboard"><div className="page-heading"><div><div className="eyebrow"><span className="pulse"/> SECURITY OPERATIONS CENTER</div><h1>Threat Overview</h1><p>Centralized visibility into indicators, vulnerabilities and emerging cyber threats.</p></div><div className="date-chip"><Activity size={15}/> LOCAL DEMO ENVIRONMENT</div></div>
 <div className="stats-grid">{stats.map(([name,val,sub],i)=><div className="stat-card" key={name}><div className="stat-top"><span>{name}</span>{[Globe,Bug,ShieldAlert,Bell].map((I,j)=>i===j?<I key={j} size={17}/>:null)}</div><strong>{val}</strong><small>{sub}</small></div>)}</div>
 <div className="dash-grid"><div className="panel module-panel"><div className="panel-title"><div><span className="tiny-label">INTELLIGENCE WORKSPACE</span><h2>Investigation modules</h2></div><span className="result-state">10 MODULES</span></div><div className="module-grid">{modules.filter(m=>m.id!=='dashboard').map(m=>{const I=m.icon;return <button className="module-card" key={m.id} onClick={()=>choose(m.id)}><div className="module-card-icon"><I size={19}/></div><b>{m.label}</b><small>{descriptions[m.id]}</small><span className="module-link">OPEN MODULE <ChevronRight size={13}/></span></button>})}</div></div>
 <div className="panel activity-panel"><div className="panel-title"><div><span className="tiny-label">SYSTEM MONITOR</span><h2>Platform status</h2></div><Activity size={17}/></div><div className="system-line"><span><i/> Frontend interface</span><b>ONLINE</b></div><div className="system-line"><span><i className="yellow"/> Threat API</span><b>LOCAL DEMO</b></div><div className="system-line"><span><i className="muted-dot"/> Intelligence feeds</span><b>NOT CONNECTED</b></div><div className="system-line"><span><i className="muted-dot"/> Sandbox</span><b>NOT CONNECTED</b></div><div className="terminal"><div><i/><i/><i/><span>system://status</span></div><p><em>[OK]</em> UI initialized</p><p><em>[WAIT]</em> provider adapters pending</p><p><em>[INFO]</em> ready for analyst input_</p></div></div></div>
 </section>
}

export default App;
