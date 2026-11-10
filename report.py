"""
report.py — Generates self-contained interactive HTML reports.

Single file, no CDN, no external URLs, no eval/new Function.
Vanilla JS + canvas/SVG, dark theme, responsive with 300-host cap.
"""

import json
import html
import time
from pathlib import Path
from analyze import get_top_hosts


def _escape_json_for_html(obj):
    """Serialize to JSON and escape < as \\u003c for safe HTML embedding."""
    s = json.dumps(obj, default=str, ensure_ascii=True)
    return s.replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')


def _sanitize_for_display(s, max_len=120):
    """Sanitize a string for display in the report."""
    if not isinstance(s, str):
        return str(s)
    # Remove control chars
    cleaned = ''.join(c for c in s if ord(c) >= 32 and ord(c) != 127)
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + '…'
    return cleaned


def _build_report_data(analysis, findings, focus_host=None,
                       protocol_filter=None, time_start=None, time_end=None):
    """Build the data structure embedded in the HTML report."""
    top_hosts, other_info = get_top_hosts(analysis, n=300)

    # Build nodes
    nodes = []
    host_ips = set()
    for h in top_hosts:
        host_ips.add(h.ip)
        nodes.append({
            'id': h.ip,
            'bytes': h.total_bytes,
            'packets': h.total_packets,
            'is_private': h.is_private,
            'dns_names': [_sanitize_for_display(n) for n in sorted(h.dns_names)[:5]],
            'sni_names': [_sanitize_for_display(n) for n in sorted(h.sni_names)[:5]],
            'bytes_in': h.bytes_in,
            'bytes_out': h.bytes_out,
            'protocols': dict(h.protocols),
            'focused': h.ip == focus_host,
        })

    # Build edges (conversations between top hosts only)
    edges = []
    for ck, conv in analysis.conversations.items():
        if ck.ip_a in host_ips and ck.ip_b in host_ips:
            dominant_proto = max(conv.protocols.items(), key=lambda x: x[1])[0] if conv.protocols else 'unknown'
            edges.append({
                'source': ck.ip_a,
                'target': ck.ip_b,
                'bytes': conv.bytes_total,
                'packets': conv.packets,
                'protocols': dict(conv.protocols),
                'dominant_protocol': dominant_proto,
                'first_seen': conv.first_seen if conv.first_seen != float('inf') else 0,
                'last_seen': conv.last_seen,
            })

    # Protocol list
    protocols = sorted(analysis.protocol_counts.items(),
                       key=lambda x: x[1], reverse=True)

    # Timeline
    timeline = []
    for b in analysis.timeline_buckets:
        timeline.append({
            't': b['time_offset'],
            'b': b['bytes'],
            'p': b['packets'],
            'pr': b['protocols'],
        })

    # Findings
    finding_list = []
    for f in findings:
        finding_list.append({
            'kind': f['kind'],
            'severity': f['severity'],
            'confidence': f['confidence'],
            'hosts': f.get('hosts', [])[:5],
            'time_range': f.get('time_range', [0, 0]),
            'why': _sanitize_for_display(f['why'], 500),
        })

    return {
        'summary': {
            'total_packets': analysis.total_packets,
            'total_bytes': analysis.total_bytes,
            'capture_start': analysis.capture_start if analysis.capture_start != float('inf') else 0,
            'capture_end': analysis.capture_end,
            'duration_sec': round(analysis.capture_duration, 3),
            'host_count': analysis.host_count,
            'flow_count': analysis.flow_count,
            'truncated': analysis.truncated,
            'truncation_reason': analysis.truncation_reason,
        },
        'nodes': nodes,
        'edges': edges,
        'protocols': [{'name': n, 'count': c} for n, c in protocols],
        'timeline': timeline,
        'bucket_size': analysis.bucket_size,
        'findings': finding_list,
        'other_hosts': other_info,
        'generated_at': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
    }


_HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:">
<title>netScope Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0f1117;--surface:#1a1d27;--surface2:#252833;--border:#333647;--text:#e0e0e8;--text2:#9095a8;--accent:#4fc3f7;--accent2:#81c784;--warn:#ffb74d;--danger:#e57373;--info:#64b5f6}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:14px;overflow:hidden;height:100vh}
.header{background:var(--surface);border-bottom:1px solid var(--border);padding:12px 20px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.header h1{font-size:18px;color:var(--accent);font-weight:600}
.header .stat{font-size:12px;color:var(--text2);background:var(--surface2);padding:4px 10px;border-radius:12px}
.header .stat b{color:var(--text)}
.heuristic-note{font-size:11px;color:var(--warn);margin-left:auto;font-style:italic}
.main{display:flex;height:calc(100vh - 52px)}
.graph-panel{flex:1;position:relative;overflow:hidden}
.graph-panel canvas{position:absolute;top:0;left:0}
.sidebar{width:320px;background:var(--surface);border-left:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden}
.sidebar-tab{display:flex;border-bottom:1px solid var(--border)}
.sidebar-tab button{flex:1;padding:8px;background:none;border:none;color:var(--text2);cursor:pointer;font-size:12px;border-bottom:2px solid transparent}
.sidebar-tab button.active{color:var(--accent);border-bottom-color:var(--accent)}
.sidebar-content{flex:1;overflow-y:auto;padding:12px}
.proto-chips{display:flex;flex-wrap:wrap;gap:6px;padding:8px 12px;border-bottom:1px solid var(--border);background:var(--surface)}
.proto-chip{font-size:11px;padding:3px 10px;border-radius:12px;background:var(--surface2);color:var(--text2);cursor:pointer;border:1px solid var(--border);transition:all .2s}
.proto-chip.active{background:var(--accent);color:var(--bg);border-color:var(--accent)}
.proto-chip:hover{border-color:var(--accent)}
.timeline-panel{height:120px;background:var(--surface);border-top:1px solid var(--border);position:relative;padding:4px 12px}
.timeline-panel canvas{width:100%;height:100%}
.replay-controls{position:absolute;top:4px;right:12px;display:flex;gap:6px;align-items:center}
.replay-controls button{background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:2px 8px;border-radius:4px;cursor:pointer;font-size:11px}
.replay-controls button:hover{border-color:var(--accent)}
.replay-controls button.active{background:var(--accent);color:var(--bg)}
.replay-controls span{font-size:11px;color:var(--text2)}
.finding{background:var(--surface2);border-radius:6px;padding:10px;margin-bottom:8px;cursor:pointer;border-left:3px solid var(--border);transition:border-color .2s}
.finding:hover{border-left-color:var(--accent)}
.finding.sev-high{border-left-color:var(--danger)}
.finding.sev-medium{border-left-color:var(--warn)}
.finding.sev-low{border-left-color:var(--info)}
.finding.sev-info{border-left-color:var(--text2)}
.finding-kind{font-size:12px;font-weight:600;color:var(--accent);text-transform:capitalize}
.finding-badges{display:flex;gap:4px;margin:4px 0}
.badge{font-size:10px;padding:1px 6px;border-radius:8px;background:var(--surface);color:var(--text2)}
.finding-why{font-size:12px;color:var(--text2);line-height:1.4}
.host-detail{padding:8px}
.host-detail h3{font-size:14px;color:var(--accent);margin-bottom:8px}
.host-detail .row{display:flex;justify-content:space-between;padding:4px 0;font-size:12px;border-bottom:1px solid var(--border)}
.host-detail .label{color:var(--text2)}
.tooltip{position:absolute;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:8px 12px;font-size:12px;pointer-events:none;z-index:100;max-width:300px;box-shadow:0 4px 12px rgba(0,0,0,.4)}
.tooltip .tt-ip{color:var(--accent);font-weight:600;font-size:13px}
.tooltip .tt-row{color:var(--text2);margin-top:2px}
.truncation-notice{background:#332200;color:var(--warn);padding:4px 12px;font-size:11px;text-align:center}
</style>
</head>
<body>
<script type="application/json" id="netscope-data">%%DATA%%</script>
<div id="app"></div>
<script>
"use strict";
(function(){
var D=JSON.parse(document.getElementById("netscope-data").textContent);
var S=D.summary,N=D.nodes,E=D.edges,P=D.protocols,TL=D.timeline,BS=D.bucket_size,F=D.findings;
var app=document.getElementById("app");

// Format helpers
function fmtBytes(b){if(b>1e9)return(b/1e9).toFixed(1)+"GB";if(b>1e6)return(b/1e6).toFixed(1)+"MB";if(b>1e3)return(b/1e3).toFixed(1)+"KB";return b+"B"}
function fmtNum(n){return n.toLocaleString()}
function fmtDur(s){if(s>3600)return(s/3600).toFixed(1)+"h";if(s>60)return(s/60).toFixed(1)+"m";return s.toFixed(1)+"s"}

// Build header
var hdr=document.createElement("div");hdr.className="header";
hdr.innerHTML='<h1>⬡ netScope</h1>'+
'<span class="stat"><b>'+fmtNum(S.total_packets)+'</b> packets</span>'+
'<span class="stat"><b>'+fmtBytes(S.total_bytes)+'</b></span>'+
'<span class="stat"><b>'+fmtDur(S.duration_sec)+'</b> duration</span>'+
'<span class="stat"><b>'+fmtNum(S.host_count)+'</b> hosts</span>'+
'<span class="stat"><b>'+fmtNum(S.flow_count)+'</b> flows</span>'+
'<span class="heuristic-note">Heuristics, not verdicts</span>';
app.appendChild(hdr);

if(S.truncated){var tn=document.createElement("div");tn.className="truncation-notice";tn.textContent="⚠ Capture truncated: "+(S.truncation_reason||"");app.appendChild(tn)}

// Main layout
var main=document.createElement("div");main.className="main";
var gp=document.createElement("div");gp.className="graph-panel";
var canvas=document.createElement("canvas");gp.appendChild(canvas);
var tooltip=document.createElement("div");tooltip.className="tooltip";tooltip.style.display="none";gp.appendChild(tooltip);
main.appendChild(gp);

// Protocol chips
var chipBar=document.createElement("div");chipBar.className="proto-chips";
var activeProto=null;
var allChip=document.createElement("span");allChip.className="proto-chip active";allChip.textContent="All";
allChip.onclick=function(){activeProto=null;updateChips();updateGraph()};
chipBar.appendChild(allChip);
P.slice(0,15).forEach(function(p){
  var c=document.createElement("span");c.className="proto-chip";c.textContent=p.name+" ("+fmtNum(p.count)+")";
  c.onclick=function(){activeProto=(activeProto===p.name)?null:p.name;updateChips();updateGraph()};
  chipBar.appendChild(c);
});
function updateChips(){var chips=chipBar.querySelectorAll(".proto-chip");chips.forEach(function(c){
  if(!activeProto&&c.textContent.startsWith("All"))c.className="proto-chip active";
  else if(activeProto&&c.textContent.startsWith(activeProto))c.className="proto-chip active";
  else c.className="proto-chip";
})}

// Sidebar
var sidebar=document.createElement("div");sidebar.className="sidebar";
var tabBar=document.createElement("div");tabBar.className="sidebar-tab";
var tabs=["Findings","Hosts"];
var activeTab="Findings";
tabs.forEach(function(t){
  var btn=document.createElement("button");btn.textContent=t+(t==="Findings"?" ("+F.length+")":"");
  btn.className=t===activeTab?"active":"";
  btn.onclick=function(){activeTab=t;renderSidebar();tabBar.querySelectorAll("button").forEach(function(b){b.className=b.textContent.startsWith(activeTab)?"active":""})};
  tabBar.appendChild(btn);
});
sidebar.appendChild(tabBar);
var sideContent=document.createElement("div");sideContent.className="sidebar-content";
sidebar.appendChild(sideContent);

main.appendChild(sidebar);
app.appendChild(chipBar);
app.appendChild(main);

// Timeline panel
var tlPanel=document.createElement("div");tlPanel.className="timeline-panel";
var tlCanvas=document.createElement("canvas");tlPanel.appendChild(tlCanvas);
var replayCtrl=document.createElement("div");replayCtrl.className="replay-controls";
var playBtn=document.createElement("button");playBtn.textContent="▶ Play";
var speedBtn=document.createElement("button");speedBtn.textContent="1x";
var timeLabel=document.createElement("span");timeLabel.textContent="0s";
replayCtrl.appendChild(playBtn);replayCtrl.appendChild(speedBtn);replayCtrl.appendChild(timeLabel);
tlPanel.appendChild(replayCtrl);
app.appendChild(tlPanel);

// State
var selectedHost=null;
var playing=false;
var playSpeed=1;
var playTime=0;
var playRAF=null;
var timeWindow=null;
var speeds=[1,4,16];var speedIdx=0;

// Graph simulation
var nodeMap={};
N.forEach(function(n){nodeMap[n.id]=n;n.x=Math.random()*600+100;n.y=Math.random()*400+100;n.vx=0;n.vy=0;n.r=Math.max(4,Math.min(30,Math.sqrt(n.bytes/1e4)))});

var maxEdgeBytes=1;E.forEach(function(e){if(e.bytes>maxEdgeBytes)maxEdgeBytes=e.bytes});

// Dragging
var dragNode=null,dragOX=0,dragOY=0;
var panX=0,panY=0,zoom=1;
var lastMouse={x:0,y:0};

function screenToWorld(sx,sy){return{x:(sx-panX)/zoom,y:(sy-panY)/zoom}}
function worldToScreen(wx,wy){return{x:wx*zoom+panX,y:wy*zoom+panY}}

canvas.onmousedown=function(e){
  var r=canvas.getBoundingClientRect();var sx=e.clientX-r.left,sy=e.clientY-r.top;
  var w=screenToWorld(sx,sy);
  for(var i=0;i<N.length;i++){var n=N[i];var dx=n.x-w.x,dy=n.y-w.y;
    if(dx*dx+dy*dy<(n.r+4)*(n.r+4)){dragNode=n;dragOX=dx;dragOY=dy;return}}
  dragNode=null;lastMouse={x:sx,y:sy};
  canvas.style.cursor="grabbing";
};
canvas.onmousemove=function(e){
  var r=canvas.getBoundingClientRect();var sx=e.clientX-r.left,sy=e.clientY-r.top;
  if(dragNode){var w=screenToWorld(sx,sy);dragNode.x=w.x+dragOX;dragNode.y=w.y+dragOY;dragNode.vx=0;dragNode.vy=0;return}
  if(e.buttons===1){panX+=sx-lastMouse.x;panY+=sy-lastMouse.y;lastMouse={x:sx,y:sy};return}
  // Hover tooltip
  var w=screenToWorld(sx,sy);var found=null;
  for(var i=0;i<N.length;i++){var n=N[i];var dx=n.x-w.x,dy=n.y-w.y;
    if(dx*dx+dy*dy<(n.r+4)*(n.r+4)){found=n;break}}
  if(found){
    tooltip.textContent="";
    var tIp=document.createElement("div");tIp.className="tt-ip";tIp.textContent=found.id;tooltip.appendChild(tIp);
    var tRow=document.createElement("div");tRow.className="tt-row";tRow.textContent=fmtBytes(found.bytes)+" (↑"+fmtBytes(found.bytes_out)+" ↓"+fmtBytes(found.bytes_in)+")";tooltip.appendChild(tRow);
    var names=found.dns_names.concat(found.sni_names).slice(0,3).join(", ");
    if(names){var tN=document.createElement("div");tN.className="tt-row";tN.textContent=names;tooltip.appendChild(tN)}
    var tRole=document.createElement("div");tRole.className="tt-row";tRole.textContent=found.is_private?"Internal":"External";tooltip.appendChild(tRole);
    tooltip.style.display="block";tooltip.style.left=(sx+12)+"px";tooltip.style.top=(sy+12)+"px";
    canvas.style.cursor="pointer";
  }else{tooltip.style.display="none";canvas.style.cursor="default"}
};
canvas.onmouseup=function(){
  if(dragNode){dragNode=null;return}
  canvas.style.cursor="default";
};
canvas.onclick=function(e){
  var r=canvas.getBoundingClientRect();var sx=e.clientX-r.left,sy=e.clientY-r.top;
  var w=screenToWorld(sx,sy);
  for(var i=0;i<N.length;i++){var n=N[i];var dx=n.x-w.x,dy=n.y-w.y;
    if(dx*dx+dy*dy<(n.r+4)*(n.r+4)){selectedHost=n.id;renderSidebar();return}}
  selectedHost=null;renderSidebar();
};
canvas.onwheel=function(e){
  e.preventDefault();var r=canvas.getBoundingClientRect();
  var sx=e.clientX-r.left,sy=e.clientY-r.top;
  var factor=e.deltaY>0?0.9:1.1;
  var newZoom=Math.max(0.1,Math.min(10,zoom*factor));
  panX=sx-(sx-panX)*(newZoom/zoom);panY=sy-(sy-panY)*(newZoom/zoom);
  zoom=newZoom;
};

function escHTML(s){var d=document.createElement("div");d.textContent=s;return d.innerHTML}

// Proto colors
var protoColors={"TCP":"#4fc3f7","UDP":"#81c784","DNS":"#ffb74d","HTTP":"#e57373","TLS":"#ce93d8","HTTPS":"#ce93d8","SSH":"#a5d6a7","ICMP":"#90a4ae","ARP":"#78909c","QUIC":"#80deea","FTP":"#ef9a9a","Telnet":"#ef9a9a","SMTP":"#bcaaa4","NTP":"#b0bec5"};
function getProtoColor(p){return protoColors[p]||"#666"}

// Force simulation
function simulate(){
  var alpha=0.1,repulse=5000,attract=0.0001,damping=0.85,centerForce=0.001;
  var cx=canvas.width/(2*zoom),cy=canvas.height/(2*zoom);
  for(var i=0;i<N.length;i++){
    var a=N[i];
    // Center gravity
    a.vx+=(cx-a.x)*centerForce;a.vy+=(cy-a.y)*centerForce;
    // Repulsion
    for(var j=i+1;j<N.length;j++){
      var b=N[j];var dx=a.x-b.x,dy=a.y-b.y;var d2=dx*dx+dy*dy+1;
      var f=repulse/d2;a.vx+=dx*f*alpha;a.vy+=dy*f*alpha;b.vx-=dx*f*alpha;b.vy-=dy*f*alpha;
    }
  }
  // Attraction along edges
  E.forEach(function(e){
    var s=nodeMap[e.source],t=nodeMap[e.target];if(!s||!t)return;
    var dx=t.x-s.x,dy=t.y-s.y;var d=Math.sqrt(dx*dx+dy*dy)+1;
    var f=attract*d;s.vx+=dx*f;s.vy+=dy*f;t.vx-=dx*f;t.vy-=dy*f;
  });
  // Apply
  N.forEach(function(n){if(n===dragNode)return;n.x+=n.vx*damping;n.y+=n.vy*damping;n.vx*=damping;n.vy*=damping});
}

// Rendering
function drawGraph(){
  var ctx=canvas.getContext("2d");
  canvas.width=gp.clientWidth;canvas.height=gp.clientHeight;
  ctx.clearRect(0,0,canvas.width,canvas.height);
  ctx.save();ctx.translate(panX,panY);ctx.scale(zoom,zoom);

  // Edges
  E.forEach(function(e){
    var s=nodeMap[e.source],t=nodeMap[e.target];if(!s||!t)return;
    if(activeProto&&!e.protocols[activeProto])return;
    var w=Math.max(0.5,Math.min(6,e.bytes/maxEdgeBytes*6));
    ctx.beginPath();ctx.moveTo(s.x,s.y);ctx.lineTo(t.x,t.y);
    ctx.strokeStyle=getProtoColor(e.dominant_protocol);ctx.globalAlpha=0.3;ctx.lineWidth=w;ctx.stroke();ctx.globalAlpha=1;

    // Pulse animation during replay
    if(playing&&timeWindow){
      var et0=e.first_seen-S.capture_start,et1=e.last_seen-S.capture_start;
      if(playTime>=et0&&playTime<=et1){
        var progress=(playTime-et0)/(et1-et0+0.1);
        var px=s.x+(t.x-s.x)*((progress*3)%1),py=s.y+(t.y-s.y)*((progress*3)%1);
        ctx.beginPath();ctx.arc(px,py,3,0,Math.PI*2);ctx.fillStyle=getProtoColor(e.dominant_protocol);ctx.globalAlpha=0.8;ctx.fill();ctx.globalAlpha=1;
      }
    }
  });

  // Nodes
  N.forEach(function(n){
    if(activeProto&&!n.protocols[activeProto])return;
    ctx.beginPath();
    if(n.is_private){ctx.arc(n.x,n.y,n.r,0,Math.PI*2)}
    else{// Diamond for external
      ctx.moveTo(n.x,n.y-n.r);ctx.lineTo(n.x+n.r,n.y);ctx.lineTo(n.x,n.y+n.r);ctx.lineTo(n.x-n.r,n.y);ctx.closePath();
    }
    var col=n.is_private?"#4fc3f7":"#81c784";
    if(n.focused)col="#ffb74d";
    if(selectedHost===n.id)col="#ff7043";
    ctx.fillStyle=col;ctx.globalAlpha=0.8;ctx.fill();ctx.globalAlpha=1;
    ctx.strokeStyle="#fff";ctx.lineWidth=selectedHost===n.id?2:0.5;ctx.stroke();
    // Label for large nodes
    if(n.r>10||selectedHost===n.id){
      ctx.font="10px sans-serif";ctx.fillStyle="#fff";ctx.textAlign="center";
      ctx.fillText(n.id,n.x,n.y+n.r+12);
    }
  });
  ctx.restore();
}

// Timeline drawing
function drawTimeline(){
  var tc=tlCanvas.getContext("2d");
  tlCanvas.width=tlPanel.clientWidth-24;tlCanvas.height=100;
  var w=tlCanvas.width,h=tlCanvas.height;
  tc.clearRect(0,0,w,h);
  if(!TL.length)return;
  var maxB=1;TL.forEach(function(b){if(b.b>maxB)maxB=b.b});
  var barW=Math.max(1,w/TL.length);
  TL.forEach(function(b,i){
    var bh=Math.max(1,(b.b/maxB)*(h-20));
    var x=i*barW;
    tc.fillStyle=(timeWindow&&b.t>=timeWindow[0]&&b.t<=timeWindow[1])?"#4fc3f7":"#333647";
    tc.fillRect(x,h-15-bh,barW-1,bh);
  });
  // Spike markers
  F.forEach(function(f){
    if(f.kind==="traffic_spike"){
      var t0=f.time_range[0]-S.capture_start;
      var idx=Math.floor(t0/BS);
      if(idx>=0&&idx<TL.length){
        var x=idx*barW+barW/2;
        tc.fillStyle="#e57373";tc.beginPath();tc.moveTo(x-4,4);tc.lineTo(x+4,4);tc.lineTo(x,10);tc.fill();
      }
    }
  });
  // Playhead
  if(playing||playTime>0){
    var px=(playTime/(S.duration_sec||1))*w;
    tc.strokeStyle="#ffb74d";tc.lineWidth=2;tc.beginPath();tc.moveTo(px,0);tc.lineTo(px,h);tc.stroke();
  }
  // Time axis
  tc.fillStyle="#9095a8";tc.font="10px sans-serif";tc.textAlign="center";
  var numLabels=Math.min(8,TL.length);
  for(var i=0;i<=numLabels;i++){
    var t=(S.duration_sec||0)*(i/numLabels);
    tc.fillText(fmtDur(t),(i/numLabels)*w,h-2);
  }
}

// Timeline click → select window
tlCanvas.onclick=function(e){
  var r=tlCanvas.getBoundingClientRect();var x=e.clientX-r.left;
  var t=(x/tlCanvas.width)*(S.duration_sec||1);
  var winSize=BS*5;
  timeWindow=[Math.max(0,t-winSize/2),t+winSize/2];
  drawTimeline();
};

// Sidebar rendering
function renderSidebar(){
  sideContent.textContent="";
  if(selectedHost){
    var n=nodeMap[selectedHost];if(!n){sideContent.textContent="Host not found";return}
    var d=document.createElement("div");d.className="host-detail";
    var h3=document.createElement("h3");h3.textContent=n.id;d.appendChild(h3);
    function addRow(label, val){
      var r=document.createElement("div");r.className="row";
      var s1=document.createElement("span");s1.className="label";s1.textContent=label;
      var s2=document.createElement("span");s2.textContent=val;
      r.appendChild(s1);r.appendChild(s2);d.appendChild(r);
    }
    addRow("Role", n.is_private?"Internal":"External");
    addRow("Total", fmtBytes(n.bytes));
    addRow("In / Out", fmtBytes(n.bytes_in)+" / "+fmtBytes(n.bytes_out));
    addRow("Packets", fmtNum(n.packets));
    if(n.dns_names.length) addRow("DNS", n.dns_names.join(", "));
    if(n.sni_names.length) addRow("SNI", n.sni_names.join(", "));
    var hf=F.filter(function(f){return f.hosts.indexOf(n.id)>=0});
    if(hf.length){
      var fh3=document.createElement("h3");fh3.style.marginTop="12px";fh3.textContent="Findings";d.appendChild(fh3);
      hf.forEach(function(f){
        var fdiv=document.createElement("div");fdiv.className="finding sev-"+f.severity;
        var fkind=document.createElement("div");fkind.className="finding-kind";fkind.textContent=f.kind.replace(/_/g," ");
        var fwhy=document.createElement("div");fwhy.className="finding-why";fwhy.textContent=f.why;
        fdiv.appendChild(fkind);fdiv.appendChild(fwhy);d.appendChild(fdiv);
      });
    }
    sideContent.appendChild(d);
    return;
  }
  if(activeTab==="Findings"){
    if(!F.length){sideContent.textContent="No findings";return}
    F.forEach(function(f){
      var el=document.createElement("div");el.className="finding sev-"+f.severity;
      var fkind=document.createElement("div");fkind.className="finding-kind";fkind.textContent=f.kind.replace(/_/g," ");
      var badges=document.createElement("div");badges.className="finding-badges";
      var b1=document.createElement("span");b1.className="badge";b1.textContent=f.severity;
      var b2=document.createElement("span");b2.className="badge";b2.textContent=f.confidence+" confidence";
      badges.appendChild(b1);badges.appendChild(b2);
      var fwhy=document.createElement("div");fwhy.className="finding-why";fwhy.textContent=f.why;
      el.appendChild(fkind);el.appendChild(badges);el.appendChild(fwhy);
      el.onclick=function(){
        if(f.hosts.length)selectedHost=f.hosts[0];
        if(f.time_range){var t0=f.time_range[0]-S.capture_start,t1=f.time_range[1]-S.capture_start;timeWindow=[t0,t1];drawTimeline()}
        renderSidebar();
      };
      sideContent.appendChild(el);
    });
  }else{
    var sorted=N.slice().sort(function(a,b){return b.bytes-a.bytes});
    sorted.slice(0,50).forEach(function(n){
      var el=document.createElement("div");el.className="finding";
      var fkind=document.createElement("div");fkind.className="finding-kind";fkind.textContent=n.id;
      var fwhy=document.createElement("div");fwhy.className="finding-why";
      fwhy.textContent=fmtBytes(n.bytes)+" · "+(n.is_private?"Internal":"External")+(n.dns_names.length?" · "+n.dns_names[0]:"");
      el.appendChild(fkind);el.appendChild(fwhy);
      el.onclick=function(){selectedHost=n.id;renderSidebar()};
      sideContent.appendChild(el);
    });
  }
}

function updateGraph(){drawGraph()}

// Replay
playBtn.onclick=function(){playing=!playing;playBtn.textContent=playing?"⏸ Pause":"▶ Play";if(playing){playTime=0;playLoop()}else{if(playRAF)cancelAnimationFrame(playRAF)}};
speedBtn.onclick=function(){speedIdx=(speedIdx+1)%speeds.length;playSpeed=speeds[speedIdx];speedBtn.textContent=playSpeed+"x"};

var lastFrameTime=0;
function playLoop(){
  if(!playing)return;
  var now=performance.now();
  if(lastFrameTime){var dt=(now-lastFrameTime)/1000;playTime+=dt*playSpeed}
  lastFrameTime=now;
  if(playTime>S.duration_sec){playTime=0}
  timeWindow=[Math.max(0,playTime-BS*3),playTime+BS*3];
  timeLabel.textContent=fmtDur(playTime);
  drawTimeline();drawGraph();
  playRAF=requestAnimationFrame(playLoop);
}

// Main loop
function loop(){simulate();drawGraph();drawTimeline();requestAnimationFrame(loop)}
renderSidebar();
requestAnimationFrame(loop);
})();
</script>
</body>
</html>'''


def generate_report(analysis, findings, output_path, focus_host=None,
                    protocol_filter=None, time_start=None, time_end=None):
    """Generate the HTML report file.

    Args:
        analysis: AnalysisResult object
        findings: List of finding dicts from heuristics
        output_path: Path to write the HTML file
        focus_host: Optional IP to highlight
        protocol_filter: Optional protocol to filter
        time_start: Optional start timestamp
        time_end: Optional end timestamp
    """
    data = _build_report_data(analysis, findings, focus_host,
                               protocol_filter, time_start, time_end)
    data_json = _escape_json_for_html(data)

    html_content = _HTML_TEMPLATE.replace('%%DATA%%', data_json)

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html_content, encoding='utf-8')

