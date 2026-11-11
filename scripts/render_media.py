"""Deterministic motion design for netScope. Requires Pillow and ffmpeg (media authoring only).

Run: python scripts/render_media.py [--stills | --video]
Uses the committed narration and real browser screenshots. No API or network access.
"""
import argparse
import functools
import json
import math
import subprocess
import struct
import wave
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont, ImageOps

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'assets'
W, H = 1920, 1080
BLUE = '#1400ff'
PAPER = '#f3f2ed'
INK = '#11111b'
GREY = '#777786'
SCENES = json.loads((ASSETS / 'demo-script.json').read_text())
DURATION = SCENES[-1]['end'] + 2


@functools.lru_cache(maxsize=128)
def font(size, mono=False):
    return ImageFont.truetype(str(ASSETS / 'fonts' / ('dm-mono.ttf' if mono else 'anton.ttf')), size)


@functools.lru_cache(maxsize=30)
def asset(name, width, height):
    return ImageOps.fit(Image.open(ASSETS / name).convert('RGB'), (width, height), method=Image.Resampling.LANCZOS)


@functools.lru_cache(maxsize=20)
def logo(size, light=False):
    im = Image.open(ASSETS / 'brand/nous-logo.png').convert('RGBA')
    box = im.getbbox()
    im = im.crop(box)
    im.thumbnail((size, int(size * 1.4)), Image.Resampling.LANCZOS)
    if light:
        layer = Image.new('RGBA', im.size, PAPER)
        layer.putalpha(im.getchannel('A'))
        im = layer
    return im


def ease(t):
    t = max(0., min(1., t))
    return 1 - (1 - t) ** 4


def text(draw, xy, value, size=30, fill=INK, mono=False, anchor=None):
    draw.text(xy, str(value), font=font(size, mono), fill=fill, anchor=anchor, spacing=12)


def rule(draw, y, color=BLUE):
    draw.line((72, y, W - 72, y), fill=color, width=2)


def furniture(im, draw, t, idx, dark=False):
    col = PAPER if dark else BLUE
    text(draw, (74, 44), 'NETSCOPE / HERMES AGENT', 22, col, True)
    text(draw, (1846, 44), 'COMMUNITY PLUGIN     /     2026', 20, col, True, 'ra')
    rule(draw, 91, col)
    for x, y, dx, dy in [(25, 25, 25, 25), (1895, 25, -25, 25), (25, 1055, 25, -25), (1895, 1055, -25, -25)]:
        draw.line((x, y, x + dx, y), fill=col, width=2)
        draw.line((x, y, x, y + dy), fill=col, width=2)
    draw.rectangle((72, 1031, 1848, 1034), fill='#35354a' if dark else '#d8d7e3')
    draw.rectangle((72, 1031, 72 + 1776 * min(1, t / DURATION), 1034), fill=col)
    text(draw, (74, 1046), f'{idx+1:02} / 08     OFFLINE NETWORK INTELLIGENCE', 15, col, True)
    text(draw, (1846, 1046), f'{int(t):02}s', 15, col, True, 'ra')


def caption(im, draw, scene, t, dark=False):
    if t < scene['start'] + .25 or t > scene['start'] + .4 + scene['voice_duration']:
        return
    # Split narration into timed phrases, so subtitles remain readable.
    words = scene['text'].split()
    phrases = [words[i:i+11] for i in range(0, len(words), 11)]
    progress = (t - scene['start'] - .25) / scene['voice_duration']
    phrase = ' '.join(phrases[min(len(phrases)-1, int(progress * len(phrases)))])
    box = draw.textbbox((0, 0), phrase, font=font(25, True))
    width = box[2] - box[0]
    draw.rounded_rectangle((W/2-width/2-28, 967, W/2+width/2+28, 1012), 7, fill=INK if not dark else PAPER)
    text(draw, (W/2, 974), phrase, 25, PAPER if not dark else INK, True, 'ma')


def network(draw, t, center=(1280, 480), radius=280, dark=False):
    col = PAPER if dark else BLUE
    nodes = []
    for i in range(21):
        angle = i * 2.39996 + t * .035
        r = radius * math.sqrt((i+1)/21)
        nodes.append((center[0]+math.cos(angle)*r, center[1]+math.sin(angle)*r*.82))
    for i, (x, y) in enumerate(nodes):
        for j in [0, (i*7+3) % len(nodes)]:
            x2, y2 = nodes[j]
            draw.line((x, y, x2, y2), fill='#5a50ff' if dark else '#c0baff', width=2)
            phase = (t * .42 + i * .13) % 1
            px, py = x+(x2-x)*phase, y+(y2-y)*phase
            draw.ellipse((px-4, py-4, px+4, py+4), fill=col)
        r = 12 if i % 7 == 0 else 5
        draw.ellipse((x-r, y-r, x+r, y+r), fill=col)
        if i % 7 == 0:
            text(draw, (x+20, y-10), f'192.168.1.{10+i}', 18, col, True)


def frame(t):
    idx = next((i for i,s in enumerate(SCENES) if s['start'] <= t < s['end']), 0 if t < 2 else 7)
    scene = SCENES[idx]
    local = max(0, t - scene['start'])
    q = ease(local / .75)
    dark = idx in (3, 5)
    bg = INK if dark else (BLUE if idx == 7 else PAPER)
    im = Image.new('RGB', (W, H), bg)
    d = ImageDraw.Draw(im)
    if t < 2:
        mark = logo(160)
        im.paste(mark, (W//2-mark.width//2, 220), mark)
        text(d, (W//2, 500), 'NOUS RESEARCH', 92, BLUE, anchor='ma')
        text(d, (W//2, 643), 'HERMES AGENT PLUGIN HACKATHON', 25, BLUE, True, 'ma')
        text(d, (W//2, 726), 'An independent community project', 22, GREY, True, 'ma')
        d.line((760, 813, 760+400*ease(t/1.6), 813), fill=BLUE, width=4)
        furniture(im, d, t, idx)
        return im
    furniture(im, d, t, idx, dark or idx == 7)
    shift = (1-q)*90
    if idx == 0:
        art = asset('brand/nous-mission.webp', 800, 650)
        im.paste(art, (1040, 190))
        text(d, (74, 150), '01 / A SIGNAL IN THE NOISE', 24, BLUE, True)
        text(d, (62, 237+shift), 'netScope', 247, BLUE)
        text(d, (78, 580+shift), 'MAKE THE NETWORK\nLEGIBLE.', 92, BLUE)
        text(d, (80, 855), 'PACKET CAPTURES  →  CLEARER ANSWERS', 23, BLUE, True)
        mark = logo(75);im.paste(mark, (1735, 120), mark)
    elif idx == 1:
        text(d, (74, 145), '02 / YOUR CAPTURE. YOUR MACHINE.', 24, BLUE, True)
        text(d, (64, 215+shift), 'LOCAL.\nBY DESIGN.', 164, BLUE)
        center=(1350,480)
        for r in [130,205,280]:
            d.ellipse((center[0]-r,center[1]-r,center[0]+r,center[1]+r), outline='#b4aaff', width=2)
        for i,label in enumerate(['.pcap','.pcapng','METADATA','REPORT']):
            a=math.pi*2*i/4+t*.2;r=235
            x,y=center[0]+math.cos(a)*r,center[1]+math.sin(a)*r
            d.rounded_rectangle((x-115,y-42,x+115,y+42),12,fill=BLUE)
            text(d,(x,y-17),label,25,PAPER,True,'ma')
        d.ellipse((1250,380,1450,580),fill=PAPER,outline=BLUE,width=3)
        text(d,(1350,445),'ns',64,BLUE,anchor='ma')
        for i,label in enumerate(['NO CLOUD UPLOADS','ZERO RUNTIME DEPENDENCIES','NO TELEMETRY']):
            text(d,(83,825+i*38),f'+ {label}',22,BLUE,True)
    elif idx == 2:
        text(d,(74,145),'03 / REAL EXECUTION · BUNDLED SYNTHETIC CAPTURE',24,BLUE,True)
        text(d,(65,222+shift),'FROM PACKETS TO CONTEXT.',102,BLUE)
        for i,(value,label) in enumerate([(1480,'PACKETS'),(20,'HOSTS'),(812,'DIRECTIONAL FLOWS')]):
            x=77+i*595;d.line((x,440,x+540,440),fill=BLUE,width=2)
            text(d,(x,465),f'{round(value*ease(local/1.5)):,}',190,BLUE)
            text(d,(x+4,725),label,26,BLUE,True)
        d.rounded_rectangle((78,820,1845,919),12,fill=INK)
        text(d,(108,853),'$ python3 demo.py sample.pcap --report',31,PAPER,True)
    elif idx == 3:
        text(d,(74,145),'04 / NATIVE HERMES TOOLS',24,PAPER,True)
        text(d,(65,212+shift),'ASK. INSPECT. UNDERSTAND.',111,PAPER)
        labels=[('01','netscope_analyze','Parse local captures'),('02','netscope_query','Ask structured questions'),('03','netscope_visualize','Build an offline report')]
        for i,(num,name,desc) in enumerate(labels):
            x=80+i*595;y=460+(1-ease((local-i*.15)/.7))*100
            d.rounded_rectangle((x,y,x+550,y+345),16,fill='#20202e',outline='#454456',width=2)
            text(d,(x+28,y+24),num,48,'#b0a8ff')
            text(d,(x+28,y+151),name,27,PAPER,True)
            text(d,(x+28,y+228),desc,23,'#b2b0c1',True)
            if i<2:text(d,(x+563,y+125),'→',30,PAPER)
        text(d,(82,865),'ANALYZE ONCE. FOLLOW UP WITHOUT RE-PARSING.',24,'#b0a8ff',True)
    elif idx == 4:
        text(d,(74,145),'05 / EXPLAINABLE HEURISTICS',24,BLUE,True)
        text(d,(65,210+shift),'PATTERNS BECOME EVIDENCE.',103,BLUE)
        labels=['SCAN-LIKE ACTIVITY','PERIODIC CONNECTIONS','UNUSUAL DNS LABELS','TRAFFIC BURSTS']
        for i,label in enumerate(labels):
            y=430+i*112;d.line((80,y+93,1840,y+93),fill='#c7c4df',width=2)
            text(d,(84,y+12),f'0{i+1}',34,BLUE,True);text(d,(200,y),label,49,BLUE)
            for j in range(35):
                x=1260+j*16
                h=(10+abs(math.sin(j*.82+i*1.4+t*.55))*45)
                if i==3 and j in [23,24]:h=84
                d.line((x,y+80,x,y+80-h),fill=BLUE,width=6)
        text(d,(84,902),'OBSERVATIONS, NOT SECURITY VERDICTS.',23,GREY,True)
    elif idx == 5:
        text(d,(74,132),'06 / ACTUAL GENERATED HTML REPORT',24,PAPER,True)
        text(d,(74,176+shift*.2),'FOLLOW THE CONVERSATION.',76,PAPER)
        # Real product screenshots, captured by Playwright with synthetic traffic.
        replay_dir=ROOT/'media-work/replay'
        files=sorted(replay_dir.glob('*.png'))
        if files:
            source=Image.open(files[int(local*8)%len(files)]).convert('RGB')
            card=source.resize((1376,688),Image.Resampling.LANCZOS)
        else:
            card=asset('report-overview.png',1376,688)
        im.paste(card,(76,275))
        d.rectangle((75,274,1453,964),outline='#4a475a',width=2)
        for i,word in enumerate(['PROTOCOL FILTERS','HOST INSPECTION','TRAFFIC REPLAY']):
            yy=350+i*170;text(d,(1505,yy),f'0{i+1}',42,'#a89cff');text(d,(1505,yy+65),word,20,PAPER,True)
        # Animated magnifier inset alternates between actual DNS and host views.
        name='report-dns.png' if local<scene['duration']/2 else 'report-host.png'
        if local>3:
            crop=Image.open(ASSETS/name).crop((1075,145,1440,760)).resize((320,650))
            im.paste(crop,(1120,300));d.rectangle((1118,298,1442,952),outline='#a89cff',width=3)
        xx=760+150*math.sin(local*.45);yy=630+100*math.cos(local*.6)
        d.ellipse((xx-17,yy-17,xx+17,yy+17),outline='#b8b2ff',width=3)
    elif idx == 6:
        text(d,(74,145),'07 / SMALL FOOTPRINT. VISIBLE LIMITS.',24,BLUE,True)
        text(d,(65,215+shift),'PRIVATE\nBY DESIGN.',164,BLUE)
        network(d,t,(1360,470),285)
        items=['METADATA, NOT PACKET BODIES','ONE SELF-CONTAINED HTML REPORT','PARSING WARNINGS STAY VISIBLE']
        for i,label in enumerate(items):
            y=787+i*50;d.ellipse((85,y+7,97,y+19),fill=BLUE);text(d,(122,y),label,25,BLUE,True)
    elif idx == 7:
        text(d,(74,145),'08 / OPEN SOURCE · MIT LICENSE',24,PAPER,True)
        text(d,(65,218+shift),'MAKE THE\nNETWORK LEGIBLE.',147,PAPER)
        mark=logo(200,True);im.paste(mark,(1515,290),mark)
        text(d,(1540,610),'NOUS',54,PAPER)
        text(d,(1540,682),'RESEARCH',34,PAPER)
        text(d,(83,809),'netScope for Hermes Agent',38,PAPER,True)
        text(d,(83,880),'github.com/Mxhi-04/Hermes-netscope',25,PAPER,True)
        text(d,(1840,918),'INDEPENDENT COMMUNITY PLUGIN',17,PAPER,True,'ra')
    caption(im,d,scene,t,dark or idx==7)
    # A short directional wipe connects scenes; never a slideshow fade.
    if 0<local<.20 and idx>0:
        x=int(W*ease(local/.20));d.rectangle((x,0,W,H),fill=BLUE)
    return im


def stills():
    # README cover is bespoke editorial artwork, not a product screenshot.
    im=Image.new('RGB',(W,H),PAPER);d=ImageDraw.Draw(im)
    art=asset('brand/nous-mission.webp',850,930);im.paste(art,(1070,75))
    text(d,(77,63),'HERMES AGENT / COMMUNITY PLUGIN',24,BLUE,True)
    d.line((77,112,1846,112),fill=BLUE,width=2)
    text(d,(65,179),'netScope',270,BLUE)
    text(d,(83,532),'MAKE THE\nNETWORK LEGIBLE.',104,BLUE)
    text(d,(86,845),'OFFLINE PACKET CAPTURE ANALYSIS',26,BLUE,True)
    text(d,(86,909),'3 NATIVE TOOLS  /  ZERO RUNTIME DEPENDENCIES',20,BLUE,True)
    im.resize((1600,900),Image.Resampling.LANCZOS).save(ASSETS/'readme-hero.png',optimize=True)
    frame(22).resize((1600,900),Image.Resampling.LANCZOS).save(ASSETS/'demo-poster.png',optimize=True)
    frames=[]
    for t in [1,4,10,17,25,34,44,55,65]:
        shot=frame(t);shot.thumbnail((480,270));frames.append(shot)
    sheet=Image.new('RGB',(1440,810),PAPER)
    for i,shot in enumerate(frames):sheet.paste(shot,((i%3)*480,(i//3)*270))
    sheet.save(ASSETS/'demo-storyboard.jpg',quality=90)
    print('Rendered README cover, poster and storyboard',flush=True)


def sound_bed():
    """Original, quiet synthesized tones under the narration; no audio samples."""
    work=ROOT/'media-work'
    work.mkdir(exist_ok=True)
    output=work/'sound-bed.wav'
    rate=24000
    count=round(DURATION*rate)
    with wave.open(str(output),'wb') as handle:
        handle.setnchannels(1);handle.setsampwidth(2);handle.setframerate(rate)
        chunk=[]
        for i in range(count):
            t=i/rate
            beat=t%.5
            envelope=max(0,min(1,t/1.2,(DURATION-t)/1.2))
            chord=sum(math.sin(2*math.pi*f*t+.2*math.sin(t)) for f in (110,164.81,220,261.63))*.12
            bass=math.sin(2*math.pi*(55+30*math.exp(-beat*22))*t)*math.exp(-beat*18)*.2
            chunk.append(int((chord+bass)*500*envelope))
            if len(chunk)==rate:
                handle.writeframes(struct.pack('<'+'h'*len(chunk),*chunk));chunk=[]
        if chunk:handle.writeframes(struct.pack('<'+'h'*len(chunk),*chunk))
    return output


def mux_video(silent):
    bed=sound_bed()
    subprocess.run(['ffmpeg','-y','-hide_banner','-loglevel','error','-i',str(silent),'-i',str(ASSETS/'demo-narration.wav'),'-i',str(bed),'-filter_complex','[1:a][2:a]amix=inputs=2:duration=first:normalize=0,loudnorm=I=-16:TP=-1.5:LRA=9[a]','-map','0:v:0','-map','[a]','-c:v','copy','-c:a','aac','-b:a','192k','-ar','48000','-ac','2','-movflags','+faststart','-shortest',str(ASSETS/'netscope-demo.mp4')],check=True)


def video():
    fps=30
    work=ROOT/'media-work'
    work.mkdir(exist_ok=True)
    output=work/'netscope-demo-silent.mp4'
    cmd=['ffmpeg','-y','-hide_banner','-loglevel','error','-f','rawvideo','-vcodec','rawvideo','-pix_fmt','rgb24','-s',f'{W}x{H}','-r',str(fps),'-i','-','-an','-c:v','libx264','-preset','veryfast','-crf','21','-pix_fmt','yuv420p','-movflags','+faststart',str(output)]
    proc=subprocess.Popen(cmd,stdin=subprocess.PIPE)
    try:
        for i in range(math.ceil(DURATION*fps)):
            proc.stdin.write(frame(i/fps).tobytes())
            if i%(fps*5)==0:print(f'Rendered {i/fps:.0f}s / {DURATION:.1f}s',flush=True)
    finally:proc.stdin.close()
    if proc.wait():raise RuntimeError('ffmpeg render failed')
    mux_video(output)
    print('Video rendered with female narration',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--stills',action='store_true');parser.add_argument('--video',action='store_true');args=parser.parse_args()
    if args.stills or not args.video:stills()
    if args.video:video()
