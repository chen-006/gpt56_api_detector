const state = {bootstrap:null, token:"", mode:"single", preset:"low", basePreset:"low", config:null, customProbes:[], poller:null, resumeSessionId:""};
const $ = id => document.getElementById(id);
const clone = value => JSON.parse(JSON.stringify(value));
const escapeHtml = value => String(value ?? "").replace(/[&<>'"]/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[char]));
const modelLabel = value => ({"gpt-5.6-sol":"Sol","gpt-5.6-terra":"Terra","gpt-5.6-luna":"Luna"})[value]||value||"—";
const effortLabel = value => ({none:"无",minimal:"极低",low:"低",medium:"中",high:"高",xhigh:"超高",max:"最大"})[value]||value;
const probeLabel = value => ({rand_country:"固定随机国家",rand_bird:"固定随机鸟",b80_letter_count:"b80 字符计数",juice_coverage:"Juice 覆盖检测",output_luna_48:"Luna 48 输出控制",output_terra_32:"Terra 32 输出控制"})[value]||String(value||"请求").replaceAll("_"," ");
const profileLabel = value => String(value||"").replace("native_codex","原生 Codex").replace("normal","普通请求").replace("fixed_32k_history","固定 32K 历史").replace("no_history","无历史").replace("+"," · ");
function safeMessageCn(value) {
  const text=String(value||""); const http=text.match(/^upstream_http_error \(HTTP (\d+)\)$/);
  if(http)return `上游返回HTTP错误（HTTP ${http[1]}）`;
  return ({truncated_or_invalid_stream:"流式响应不完整或格式错误",connection_or_transport_error:"网络连接或传输失败",timeout:"等待上游响应超时"})[text]||text;
}
function normalizeApiBaseUrl(value) {
  const text=String(value||"").trim(); if(!text)return "";
  try { const url=new URL(text); if(url.pathname==="/")url.pathname="/v1"; else url.pathname=url.pathname.replace(/\/$/,""); return url.toString().replace(/\/$/,""); }
  catch(_error) { return text; }
}
function friendlyError(message) {
  const text=String(message||"");
  const mappings=[
    [/detector is already running or stopping/i,"检测正在运行或停止中，请等待当前会话结束"],
    [/probe content hash mismatch/i,"自定义探针内容校验失败，请重新导出后再导入"],
    [/runtime catalog is missing/i,"运行资源缺失，请重新下载或重新构建发行包"],
    [/FileNotFoundError/i,"检测所需文件缺失，请重新下载完整发行包"],
    [/unsupported fingerprint baseline/i,"指纹基线版本不受支持，请使用4.1.0生成的探针或完整发行包"],
    [/fingerprint baseline content hash mismatch/i,"指纹基线完整性校验失败，请重新下载完整发行包"],
  ];
  return mappings.find(([pattern])=>pattern.test(text))?.[1]||text;
}

function toast(message) {
  const node=$("toast"); node.textContent=message; node.classList.add("show");
  clearTimeout(toast.timer); toast.timer=setTimeout(()=>node.classList.remove("show"),2600);
}

function showStep(name) {
  document.querySelectorAll(".page-step").forEach(node=>node.classList.toggle("active",node.id===`step-${name}`));
  document.querySelectorAll(".step").forEach(node=>node.classList.toggle("active",node.dataset.step===name));
  window.scrollTo({top:0,behavior:"smooth"});
}

function presetSource() { return state.mode==="single"?state.bootstrap.single_presets:state.bootstrap.continuous_presets; }

function applyPreset(name) {
  if(name==="custom") { markCustom("已切换到自定义档位"); return; }
  state.preset=name; state.basePreset=name; state.config=clone(presetSource()[name]);
  state.config.custom_probes=clone(state.customProbes); syncPlan();
}

function markCustom(reason) {
  if(state.preset!=="custom") state.basePreset=state.preset;
  state.preset="custom"; state.config.preset="custom"; state.config.base_preset=state.basePreset;
  state.config.custom_probes=clone(state.customProbes);
  $("custom-banner").classList.remove("hidden"); $("custom-diff").textContent=reason;
  document.querySelectorAll("[data-preset]").forEach(node=>node.classList.toggle("selected",node.dataset.preset==="custom"));
  updateEstimate();
}

function syncPlan() {
  document.querySelectorAll("[data-mode]").forEach(node=>node.classList.toggle("selected",node.dataset.mode===state.mode));
  document.querySelectorAll("[data-preset]").forEach(node=>node.classList.toggle("selected",node.dataset.preset===state.preset));
  $("custom-banner").classList.toggle("hidden",state.preset!=="custom");
  $("format-normal").checked=state.config.request_formats.includes("normal");
  $("format-native").checked=state.config.request_formats.includes("native_codex");
  $("context-none").checked=state.config.context_modes.includes("no_history");
  $("context-32k").checked=state.config.context_modes.includes("fixed_32k_history");
  $("workers").value=Number(state.config.workers??8);
  $("continuous-settings").classList.toggle("hidden",state.mode!=="continuous");
  if(state.mode==="continuous") {
    $("min-interval").value=Number(state.config.min_interval_seconds??150);
    $("max-interval").value=Number(state.config.max_interval_seconds??210);
    $("slots-per-cycle").value=Number(state.config.slots_per_cycle??1);
  }
  renderProbes(); updateEstimate();
}

function probeMeta(id) {
  const found=(state.bootstrap.probe_catalog||[]).find(item=>item.id===id);
  if(found) return found;
  if(id.startsWith("juice_")) return {name:id.replaceAll("_"," "),type:"Juice",description:"使用已冻结并通过可信筛选的模板池。"};
  if(id.startsWith("output_")) return {name:id.includes("48")?"Luna 48 输出控制":"Terra 32 输出控制",type:"防改写",description:"响应必须精确等于目标字面量。"};
  return {name:id,type:"探针",description:"自定义探测项目"};
}

function metricsText(meta) {
  if(!meta.between_model_jsd) return "";
  const format=items=>(items||[]).filter(value=>value!==null&&value!==undefined&&Number.isFinite(Number(value))).map(value=>Number(value).toFixed(3)).join(" / ")||"—";
  return `可信格式格 ${meta.trusted_profiles||0}；每模型可信窗口至少 ${meta.trusted_windows||0}；模型间差异 S：${format(meta.between_model_jsd)}；时间漂移 D：${format(meta.within_model_jsd)}；参考权重 w：${format(meta.weights)}；最低有效率 ${((meta.minimum_valid_rate||0)*100).toFixed(1)}%。`;
}

function customDocument(value){return value?.probe_file||value;}
function customRuntime(value,sourceJson=""){
  if(value?.probe_file_json||value?.probe_file)return value;
  const document=clone(value),enabled=value?.enabled??true,probability=Number(value?.probability_percent??100),windowSize=Number(value?.window??20),requests=Number(value?.runtime_requests??10);
  delete document.enabled;delete document.probability_percent;delete document.window;
  return {probe_file:document,probe_file_json:sourceJson||JSON.stringify(document),enabled,runtime_requests:requests,probability_percent:probability,window:windowSize};
}
function probeSetting(probe,isCustom=false){
  return state.mode==="single"?`${Number(isCustom?probe.runtime_requests:probe.requests??0)} 次${isCustom?" / 格":""}`:`${Number(probe.probability_percent??0)}% · 窗口 ${Number(probe.window??20)}`;
}
function updateProbeSetting(row,probe,isCustom=false){row.querySelector(".probe-setting").textContent=probeSetting(probe,isCustom);}

function customMetrics(probe){
  probe=customDocument(probe);
  const artifact=probe.baseline_artifact||{},cells=Object.values(artifact.cells||{});
  const format=values=>values.filter(value=>value!=null&&Number.isFinite(Number(value))).map(value=>Number(value).toFixed(3)).join(" / ")||"—";
  const stable=cells.length&&cells.every(value=>value.time_stability_verified);
  return `模型间差异 S：${format(cells.map(value=>value.between_model_jsd))}；时间漂移 D：${format(cells.map(value=>value.within_model_jsd))}；参考权重 w：${format(cells.map(value=>value.weight))}；${stable?"已包含多时间窗稳定性数据":"单时间窗，跨时间稳定性尚未验证"}。`;
}

function renderProbes() {
  const list=$("probe-list"); list.textContent="";
  Object.entries(state.config.probes).forEach(([id,probe])=>{
    const meta=probeMeta(id), row=document.createElement("div"); row.className="probe-row";
    const setting=probeSetting(probe);
    const controls=state.mode==="single"
      ? `<label>请求数<input class="probe-requests" type="number" min="0" value="${Number(probe.requests??0)}"></label>`
      : `<label>每槽概率 %<input class="probe-probability" type="number" min="0" max="100" value="${Number(probe.probability_percent??0)}"></label><label>滚动窗口<input class="probe-window" type="number" min="1" value="${Number(probe.window??20)}"></label>`;
    row.innerHTML=`<div class="probe-summary"><input class="probe-enabled" type="checkbox" ${probe.enabled?"checked":""}><span class="probe-name">${escapeHtml(meta.name)}</span><span class="probe-type">${escapeHtml(meta.type)}</span><span class="probe-setting">${escapeHtml(setting)}</span><button class="expand-probe" title="展开详情" aria-label="展开详情">▸</button></div><div class="probe-details"><p>${escapeHtml(meta.description)}</p>${metricsText(meta)?`<p><small>${escapeHtml(metricsText(meta))}</small></p>`:""}<div class="probe-fields">${controls}<label>思考强度<input value="${escapeHtml(probe.effort??"固定")}" disabled></label></div></div>`;
    row.querySelector(".expand-probe").addEventListener("click",()=>row.classList.toggle("open"));
    row.querySelector(".probe-enabled").addEventListener("change",event=>{probe.enabled=event.target.checked;updateProbeSetting(row,probe);markCustom(`${meta.name} 启用状态已修改`);});
    row.querySelector(".probe-requests")?.addEventListener("input",event=>{probe.requests=Number(event.target.value);updateProbeSetting(row,probe);markCustom(`${meta.name} 请求数已修改`);});
    row.querySelector(".probe-probability")?.addEventListener("input",event=>{probe.probability_percent=Number(event.target.value);updateProbeSetting(row,probe);markCustom(`${meta.name} 持续概率已修改`);});
    row.querySelector(".probe-window")?.addEventListener("input",event=>{probe.window=Number(event.target.value);updateProbeSetting(row,probe);markCustom(`${meta.name} 窗口已修改`);});
    list.appendChild(row);
  });
  state.customProbes=state.customProbes.map(customRuntime);
  state.customProbes.forEach((probe,index)=>{
    const row=document.createElement("div"); row.className="probe-row";
    probe.enabled??=true;probe.runtime_requests??=10; probe.probability_percent??=100; probe.window??=20;
    const probeFile=customDocument(probe),artifact=probeFile.baseline_artifact||{};
    const probeId=probeFile.probe_identity.probe_id,profiles=Object.keys(artifact.raw_counts?.[probeId]?.profiles||{});
    const setting=probeSetting(probe,true);
    const controls=state.mode==="single"
      ? `<label>请求数 / 格<input class="custom-requests" type="number" min="1" value="${Number(probe.runtime_requests)}"></label>`
      : `<label>每槽概率 %<input class="custom-probability" type="number" min="0" max="100" value="${Number(probe.probability_percent)}"></label><label>滚动窗口<input class="custom-window" type="number" min="1" value="${Number(probe.window)}"></label>`;
    row.innerHTML=`<div class="probe-summary"><input class="custom-enabled" type="checkbox" ${probe.enabled?"checked":""}><span class="probe-name">${escapeHtml(probeFile.probe_identity.name)}</span><span class="probe-type">自定义指纹（参考）</span><span class="probe-setting">${escapeHtml(setting)}</span><button class="expand-probe" title="展开详情" aria-label="展开详情">▸</button></div><div class="probe-details"><p>${escapeHtml(probeFile.exact_prompts_and_hashes.user_prompt)}</p><p><small>适用格式格：${escapeHtml(profiles.join("、")||"无")}；参考数据：${probeFile.reference_ready||probeFile.formal_eligible?"可用":"采样不完整"}；本版本导入后固定为参考证据，不参与正式硬结论；${escapeHtml(customMetrics(probeFile))}</small></p><div class="probe-fields">${controls}<button class="remove-probe danger" title="移除此探针" aria-label="移除此探针">×</button></div></div>`;
    row.querySelector(".expand-probe").addEventListener("click",()=>row.classList.toggle("open"));
    row.querySelector(".custom-enabled").addEventListener("change",event=>{probe.enabled=event.target.checked;updateProbeSetting(row,probe,true);markCustom(`${probeFile.probe_identity.name} 启用状态已修改`);});
    row.querySelector(".custom-requests")?.addEventListener("input",event=>{probe.runtime_requests=Number(event.target.value);updateProbeSetting(row,probe,true);markCustom(`${probeFile.probe_identity.name} 请求数已修改`);});
    row.querySelector(".custom-probability")?.addEventListener("input",event=>{probe.probability_percent=Number(event.target.value);updateProbeSetting(row,probe,true);markCustom(`${probeFile.probe_identity.name} 持续概率已修改`);});
    row.querySelector(".custom-window")?.addEventListener("input",event=>{probe.window=Number(event.target.value);updateProbeSetting(row,probe,true);markCustom(`${probeFile.probe_identity.name} 窗口已修改`);});
    row.querySelector(".remove-probe").addEventListener("click",()=>{state.customProbes.splice(index,1);state.config.custom_probes=clone(state.customProbes);markCustom(`${probeFile.probe_identity.name} 已移除`);renderProbes();});
    list.appendChild(row);
  });
}

async function post(path,body) {
  const response=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json","X-GPT56-Session":state.token},body:JSON.stringify(body)});
  const value=await response.json(); if(!response.ok) throw new Error(value.error||`HTTP ${response.status}`); return value;
}

async function updateEstimate() {
  try {
    const estimate=await post("/api/detector/estimate",{config:state.config});
    const items=state.mode==="single"
      ? [["请求数",estimate.total_requests],["32K 请求",estimate.fixed_32k_requests],["长上下文词量",estimate.approximate_fixed_32k_input_tokens?.toLocaleString("zh-CN")]]
      : [["格式格",estimate.profiles],["调度","随机间隔 · 独立概率"],["档位",estimate.official?"官方":"自定义参考"]];
    $("estimate").innerHTML=items.map(([key,value])=>`<div><dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value??"—")}</dd></div>`).join("");
    const costly=state.mode==="single"&&estimate.fixed_32k_requests>0;
    $("high-cost").classList.toggle("hidden",!costly); if(costly) $("high-cost").textContent=`当前含 ${estimate.fixed_32k_requests} 条固定 32K 请求。`;
  } catch(error) { console.warn(error); }
}

function bindCollection(id,collection,value) {
  $(id).addEventListener("change",event=>{
    const values=state.config[collection];
    if(event.target.checked&&!values.includes(value)) values.push(value);
    if(!event.target.checked) state.config[collection]=values.filter(item=>item!==value);
    if(!state.config[collection].length){event.target.checked=true;state.config[collection].push(value);toast("至少保留一个选项");return;}
    markCustom("请求格式或上下文已修改");
  });
}

async function startRun() {
  const baseUrl=normalizeApiBaseUrl($("base-url").value),apiKey=$("api-key").value,model=$("model").value.trim();
  $("base-url").value=baseUrl;
  if(!baseUrl||!apiKey||!model){toast("请完整填写 API 地址、模型名和 key");showStep("connect");return;}
  const retention=$("retention-enabled").checked,retentionPath=$("retention-path").value.trim();
  if(retention&&!retentionPath){toast("开启留存后必须填写绝对目录");return;}
  if(state.config.request_formats.includes("native_codex")&&!confirm("原生 Codex 请求建议配合系统级 TUN VPN。仅设置浏览器代理可能无法覆盖检测器的 Python 和 Node 子进程。确认继续吗？"))return;
  try {
    const result=await post("/api/detector/start",{base_url:baseUrl,model,api_key:apiKey,config:state.config,resume_session_id:state.resumeSessionId||null,retention_enabled:retention,retention_directory:retentionPath||null});
    state.resumeSessionId=""; $("api-key").value=""; $("run-session").textContent=`会话 ${result.session_id}`; showStep("run"); watchStatus();
  } catch(error){toast(friendlyError(error.message));}
}

function watchStatus() {
  clearInterval(state.poller); state.poller=setInterval(pollStatus,1000); pollStatus();
}

async function pollStatus() {
  try {
    const response=await fetch("/api/detector/status",{cache:"no-store"}); if(!response.ok)return;
    const status=await response.json(); renderRunStatus(status);
    if(["complete","stopped","error"].includes(status.status)){clearInterval(state.poller);state.poller=null;if(status.report_available)loadReport();}
  } catch(_) { /* next one-second poll recovers */ }
}

function renderRunStatus(status) {
  $("raw-status").textContent=JSON.stringify(status,null,2);
  if(status.session_id) $("run-session").textContent=`会话 ${status.session_id}`;
  const statusLabel=({running:"运行中",complete:"已完成",error:"运行错误",stopping:"正在停止",stopped:"已停止",interrupted:"进程中断，可输入 key 恢复"})[status.status]||status.status;
  $("run-status").textContent=status.error?`${statusLabel}：${friendlyError(status.error)}`:statusLabel;
  $("run-status").className=`status-dot ${status.status}`; $("run-updated").textContent=status.updated_at||"—";
  const progress=status.progress||{},total=progress.planned||0,done=progress.logical_completed||0;
  $("run-progress").style.width=`${total?Math.min(100,done/total*100):status.status==="complete"?100:5}%`;
  $("run-details").innerHTML=[["逻辑完成",done],["成功",progress.successful??0],["最终错误",progress.errors??0],["取消",progress.cancelled??0],["HTTP尝试",progress.http_attempts??0],["重试",progress.retries??0],["在途",progress.in_flight??0],["计划",total],["结论",status.verdict||"计算中"]].map(([key,value])=>`<div class="metric"><span>${key}</span><strong>${escapeHtml(value)}</strong></div>`).join("");
  $("stop-run").disabled=!['running','stopping'].includes(status.status);
  $("stop-run").textContent=status.status==='stopping'?`正在终止 ${progress.in_flight??0} 条请求`:'停止';
}

async function loadReport() {
  const response=await fetch("/api/detector/report",{cache:"no-store"}); if(!response.ok)return;
  renderReport(await response.json()); showStep("report");
}

function renderReport(report) {
  $("report-empty").classList.add("hidden"); $("report-content").classList.remove("hidden");
  $("verdict-title").textContent=report.title_cn||report.overall_verdict||"未形成正式结论";
  $("verdict-subtitle").textContent=report.subtitle_cn||report.quality_note||(report.common_causes?.length?`常见原因：${report.common_causes.join("；")}`:"");
  const alert=report.outcome_code==="possible_non_gpt"||String(report.outcome_code||"").includes("juice_mismatch");
  $("verdict-band").classList.toggle("alert",alert); $("verdict-band").classList.toggle("warning",String(report.outcome_code||"").includes("insufficient")||String(report.outcome_code||"").includes("unclear"));
  $("report-custom").classList.toggle("hidden",!report.custom_preset);
  if(report.custom_preset) $("report-custom").querySelector("span").textContent=`修改项目：${(report.custom_changes||[]).join("、")||"自定义探针"}。匹配度只能用于参考，不能据此判定是否通过。`;
  const fingerprint=report.fingerprint_summary||{},details=report.fingerprint_details||[];
  const reasons=fingerprint.fingerprint_unclear_reasons_cn||[];
  const reasonCodes=fingerprint.fingerprint_unclear_reasons||[];
  const lowWithoutFingerprint=reasonCodes.includes("builtin_fingerprint_not_enabled")&&report.preset==="low";
  const fingerprintState=report.fingerprint_verdict_state==="strong_match"?`强烈指向 ${modelLabel(report.fingerprint_model)}`:"证据不明确";
  $("fingerprint-status").textContent=fingerprintState;
  $("fingerprint-status").classList.toggle("strong",report.fingerprint_verdict_state==="strong_match");
  $("fingerprint-bars").innerHTML=lowWithoutFingerprint
    ? '<div class="report-item"><strong>低档不运行行为指纹探针</strong><p>低档只检查 Juice、32/48 输出完整性与显式覆盖，因此这里固定为“证据不明确”，不代表线路或模型异常。</p></div>'
    : details.map(item=>{const threshold=item.threshold==null?"当前模式仅参考":`强指向线 >${(item.threshold*100).toFixed(0)}%`;return `<div class="probability-row"><strong>${escapeHtml(item.label_cn)}</strong><div class="bar"><span style="width:${Math.max(0,Math.min(100,item.match*100))}%"></span></div><span class="probability-value">${(item.match*100).toFixed(3)}%<small>${threshold}</small></span></div>`;}).join("")||'<div class="report-item">当前没有取得可比较的行为指纹样本。</div>';
  $("fingerprint-reference").innerHTML=`<p>本地 Plus 账号池中档纯 Sol 正式完整测试：48次中45次的 Sol 匹配度高于70%，48次均由 Sol 排名第一。</p><p>高档纯 Sol 测试：13/13 高于95%，删除二次权重后的离线重放范围98.866%至99.476%。中档映射测试：Luna 18/18 高于90%，Terra 17/17 高于75%。</p><p>这些数字只代表对应账号池和测试时间；官方风控、限流或临时路由可能改变结果。</p>${reasons.length?`<p><strong>本次证据不明确原因：</strong>${reasons.map(escapeHtml).join("；")}</p>`:""}`;
  const efforts=Object.entries(report.juice_summary?.per_effort||{});
  $("juice-result").innerHTML=`<table><thead><tr><th>思考档</th><th>尝试</th><th>有效</th><th>申报型号命中</th><th>型号不一致</th><th>未知输出</th><th>网络错误</th><th>共享值命中</th></tr></thead><tbody>${efforts.map(([effort,value])=>`<tr><td>${escapeHtml(effortLabel(effort))}</td><td>${value.attempted}</td><td>${value.valid_completed}</td><td>${value.current_success}</td><td>${value.mixed}</td><td>${value.unsuccessful}</td><td>${value.network_error}</td><td>${value.shared_current_success}</td></tr>`).join("")}</tbody></table>`;
  const output=report.output_integrity_summary||{},coverage=report.coverage_summary||{};
  const outputAlarm=output.hard_anomaly||output.sticky_hard_anomaly,coverageAlarm=coverage.hard_anomaly||coverage.sticky_hard_anomaly;
  $("deterministic-results").innerHTML=`<div class="report-item"><strong>32/48 输出完整性</strong><p>成功响应 ${output.requests||0} 条，精确返回 ${output.exact||0} 条，格式无效 ${output.invalid||0} 条。${outputAlarm?`检测到40或40开头的输出改写${output.sticky_hard_anomaly&&!output.hard_anomaly?"（来自本会话历史粘性事件）":""}。`:"没有检测到40或40开头的输出改写。"}</p></div><div class="report-item"><strong>Juice 显式覆盖检测</strong><p>成功响应 ${coverage.requests||0} 条。${coverageAlarm?`检测到显式定义可能被隐藏提示覆盖${coverage.sticky_hard_anomaly&&!coverage.hard_anomaly?"（来自本会话历史粘性事件）":""}。`:"没有检测到明确的隐藏覆盖。"}</p></div>`;
  const cells=fingerprint.cell_details||{},families=fingerprint.family_contributions||{};
  const countText=counts=>Object.entries(counts||{}).filter(([,count])=>count>0).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([key,count])=>`${key==="__INVALID_OUTPUT__"?"格式无效":key==="__OTHER__"?"其他合法答案":key} ${count}`).join("；")||"无";
  const contributionText=value=>{if(Number(value.weight||0)<=0)return "不参与匹配";const scores=value.average_log_likelihood||families[value.probe_id]?.model_contributions||{};const ordered=Object.entries(scores).filter(([,score])=>Number.isFinite(Number(score))).sort((a,b)=>Number(b[1])-Number(a[1]));return ordered.length?`更支持 ${modelLabel(ordered[0][0])}`:"方向不明确";};
  const referenceResults=(report.reference_fingerprint_results||[]).map(result=>`<div class="report-item"><strong>${escapeHtml(probeLabel(result.probe_id))}（自定义参考）</strong><p>${Object.entries(result.fingerprint_match||{}).map(([model,value])=>`${escapeHtml(modelLabel(model))} ${(Number(value)*100).toFixed(3)}%`).join("；")||"没有可计算的参考匹配度"}</p><small>自定义探针不参与正式强指向，每个探针单独显示。</small></div>`).join("");
  $("probe-results").innerHTML=`<table><thead><tr><th>探针</th><th>请求方式</th><th>完成/计划</th><th>主要答案</th><th>贡献方向</th><th>模型差异 S</th><th>时间漂移 D</th><th>权重 w</th><th>90%门禁</th></tr></thead><tbody>${Object.values(cells).map(value=>`<tr><td>${escapeHtml(probeLabel(value.probe_id))}</td><td>${escapeHtml(profileLabel(value.profile))}</td><td>${value.sample_count}/${value.planned_samples}</td><td>${escapeHtml(countText(value.counts))}</td><td>${escapeHtml(contributionText(value))}</td><td>${Number(value.between_model_jsd).toFixed(3)}</td><td>${Number(value.within_model_jsd).toFixed(3)}</td><td>${Number(value.weight).toFixed(3)}</td><td>${value.complete?"达到":"未达到"}</td></tr>`).join("")}</tbody></table>${referenceResults}`;
  $("profile-results").innerHTML=`<table><thead><tr><th>请求方式</th><th>任务</th><th>成功</th><th>错误</th><th>取消</th></tr></thead><tbody>${Object.entries(report.profile_summary||{}).map(([profile,value])=>`<tr><td>${escapeHtml(profileLabel(profile))}</td><td>${value.logical_tasks}</td><td>${value.successful}</td><td>${value.final_errors}</td><td>${value.cancelled}</td></tr>`).join("")}</tbody></table>`;
  const network=report.network_summary||{};
  $("network-result").innerHTML=[["逻辑任务",network.logical_tasks],["逻辑完成",network.logical_completed],["成功",network.successful],["最终错误",network.final_errors],["取消",network.cancelled],["HTTP尝试",network.http_attempts],["重试",network.retries]].map(([key,value])=>`<div class="metric"><span>${key}</span><strong>${value??0}</strong></div>`).join("");
  const failures=(report.failed_items||[]).map(item=>{const cells=(item.incomplete_cells||[]).map(value=>{const [probe,profile]=String(value.cell||"").split("|");return `<li>${escapeHtml(probeLabel(probe))} · ${escapeHtml(profileLabel(profile))}：计划 ${value.planned}，完成 ${value.completed}，至少需要 ${value.minimum}，缺少 ${Math.max(0,Number(value.minimum)-Number(value.completed))}</li>`;}).join("");return `<div class="report-item"><strong>${escapeHtml(item.layer)}</strong><p>${escapeHtml(item.reason_cn||"该项目没有形成有效证据。")}</p>${cells?`<ul>${cells}</ul>`:""}</div>`;}).join("");
  const errors=(report.network_error_details||[]).map(item=>`<div class="report-item error-item"><strong>${escapeHtml(probeLabel(item.probe_id))} · ${escapeHtml(item.category_cn||"线路错误")}</strong><p>HTTP ${escapeHtml(item.http_status??"—")}，第 ${escapeHtml(item.attempt)} 次尝试。${escapeHtml(safeMessageCn(item.safe_message))}</p><small>常见原因包括地址或权限配置错误、上游限流、线路中断、响应流未完整结束。</small></div>`).join("");
  $("failed-items").innerHTML=failures+errors||'<div class="report-item">没有未通过或未完成项目。</div>';
  $("limitations").innerHTML=(report.limitations||[]).map(item=>`<p>• ${escapeHtml(item)}</p>`).join("");
  $("report-json").textContent=JSON.stringify(report,null,2);
}

async function init() {
  state.bootstrap=await fetch("/api/bootstrap").then(response=>response.json()); state.token=state.bootstrap.session_token; applyPreset("low");
  if(state.bootstrap.pending_custom_probe){const pending=customRuntime(clone(state.bootstrap.pending_custom_probe));state.customProbes.push(pending);state.config.custom_probes=clone(state.customProbes);markCustom(`已加入 ${customDocument(pending).probe_identity.name}`);renderProbes();}
  document.querySelectorAll(".step").forEach(node=>node.addEventListener("click",()=>node.dataset.step==="report"?loadReport():showStep(node.dataset.step)));
  document.querySelectorAll("[data-mode]").forEach(node=>node.addEventListener("click",()=>{state.mode=node.dataset.mode;applyPreset(state.basePreset);}));
  document.querySelectorAll("[data-preset]").forEach(node=>node.addEventListener("click",()=>applyPreset(node.dataset.preset)));
  $("to-plan").addEventListener("click",()=>showStep("plan")); $("back-connect").addEventListener("click",()=>showStep("connect"));
  $("restore-defaults").addEventListener("click",()=>{if(confirm("恢复本档默认参数会覆盖当前修改，是否继续？"))applyPreset(state.basePreset);});
  $("start-run").addEventListener("click",startRun); $("stop-run").addEventListener("click",async()=>{const button=$("stop-run");button.disabled=true;try{const result=await post("/api/detector/stop",{});if(result.accepted){button.textContent=`正在终止 ${result.active_requests_cancelled||0} 条请求`;toast("已发送停止请求");}else{button.disabled=false;button.textContent="停止";toast("当前没有可停止的运行会话");}}catch(error){button.disabled=false;button.textContent="停止";toast(friendlyError(error.message));}});
  $("new-session").addEventListener("click",()=>{state.resumeSessionId="";showStep("connect");});
  bindCollection("format-normal","request_formats","normal"); bindCollection("format-native","request_formats","native_codex"); bindCollection("context-none","context_modes","no_history"); bindCollection("context-32k","context_modes","fixed_32k_history");
  $("workers").addEventListener("change",event=>{state.config.workers=Number(event.target.value);markCustom("并发数已修改");});
  [["min-interval","min_interval_seconds"],["max-interval","max_interval_seconds"],["slots-per-cycle","slots_per_cycle"]].forEach(([id,key])=>$(id).addEventListener("change",event=>{state.config[key]=Number(event.target.value);markCustom("持续调度参数已修改");}));
  $("retention-enabled").addEventListener("change",event=>$("retention-path-row").classList.toggle("hidden",!event.target.checked));
  $("base-url").addEventListener("blur",event=>{event.target.value=normalizeApiBaseUrl(event.target.value);});
  $("probe-file").addEventListener("change",async event=>{const file=event.target.files[0];if(!file)return;try{const sourceJson=await file.text(),probe=JSON.parse(sourceJson);await post("/api/probe/verify",{probe_file_json:sourceJson});state.customProbes.push(customRuntime(probe,sourceJson));state.config.custom_probes=clone(state.customProbes);markCustom(`已导入 ${probe.probe_identity.name}`);renderProbes();}catch(error){toast(friendlyError(error.message));}});
  const current=await fetch("/api/detector/status",{cache:"no-store"}).then(response=>response.json()).catch(()=>({status:"idle"}));
  if(["running","stopping"].includes(current.status)){showStep("run");watchStatus();}
  else if(["complete","stopped"].includes(current.status)&&current.report_available){await loadReport();}
  else if(current.status==="interrupted"){
    state.resumeSessionId=current.session_id||"";
    if(current.resume_config){state.config=clone(current.resume_config);state.mode=state.config.mode;state.preset=state.config.preset;state.basePreset=state.config.base_preset||state.preset;state.customProbes=clone(state.config.custom_probes||[]);syncPlan();}
    if(current.claimed_model) $("model").value=current.claimed_model;
    if(current.safe_endpoint) $("base-url").value=current.safe_endpoint;
    toast("检测进程曾中断；输入 API key 后会按原冻结任务和剩余尝试预算恢复");
    showStep("connect");
  }
}

init().catch(error=>toast(`初始化失败：${friendlyError(error.message)}`));
