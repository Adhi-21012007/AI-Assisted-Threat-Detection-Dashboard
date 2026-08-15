(() => {
  const csrf=document.body.dataset.csrf;
  document.querySelectorAll('form[method="post"]').forEach(form=>{
    if(!form.querySelector('input[name="_csrf"]')){const input=document.createElement('input');input.type='hidden';input.name='_csrf';input.value=csrf;form.append(input)}
  });
  const raw=document.getElementById('soc-data');if(!raw)return;
  const data=JSON.parse(raw.textContent),palette=['#42d9d0','#65a9ff','#f5cf58','#ff9e4b','#ff5c70','#57d38c'];
  const chart=(canvas,config)=>window.Chart&&new Chart(canvas,{type:config.type||'bar',data:config.data,options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#b9d4d8'}}},scales:config.type==='doughnut'?{}:{x:{ticks:{color:'#8caab4'},grid:{color:'#173747'}},y:{ticks:{color:'#8caab4',precision:0},grid:{color:'#173747'}}}}});
  document.querySelectorAll('.chart').forEach(el=>{let kind=el.dataset.kind,labels=[],datasets=[],type='bar';if(kind==='trend'){labels=data.trend.labels;datasets=[{label:'Events',data:data.trend.events,borderColor:'#42d9d0',backgroundColor:'rgba(66,217,208,.12)',fill:true,tension:.35},{label:'Threats',data:data.trend.threats,borderColor:'#ff5c70',backgroundColor:'transparent',tension:.35},{label:'Suspicious',data:data.trend.suspicious,borderColor:'#f5cf58',backgroundColor:'transparent',tension:.35}];type='line'}else if(kind==='funnel'){labels=['Security events','Firewall alerts','AI analysed','AI threats','Resolved'];datasets=[{label:'Records',data:data.funnel,backgroundColor:palette}]}else{const source=data[kind]||{};labels=Object.keys(source);datasets=[{data:Object.values(source),backgroundColor:palette,borderWidth:0}];type=kind==='attacks'||kind==='severity'?'doughnut':'bar'}chart(el,{type,data:{labels,datasets}})});
  const seconds=Number(document.body.dataset.refresh||0);if(seconds)setTimeout(()=>location.reload(),seconds*1000);
})();
