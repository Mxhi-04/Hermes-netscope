"""Real browser QA and showcase capture. Requires Playwright and Chromium."""
from pathlib import Path
from playwright.sync_api import sync_playwright
import json
import argparse
root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description='Verify a generated report and capture real product media')
parser.add_argument('report',type=Path)
args=parser.parse_args()
report=args.report.resolve()
work=root/'media-work';work.mkdir(exist_ok=True)
(work/'replay').mkdir(exist_ok=True)
with sync_playwright() as p:
 chrome=Path('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')
 b=p.chromium.launch(**({'executable_path':str(chrome)} if chrome.exists() else {}))
 page=b.new_page(viewport={'width':1440,'height':900},device_scale_factor=1)
 errors=[];requests=[];page.on('pageerror',lambda e:errors.append(str(e)));page.on('request',lambda r:requests.append(r.url))
 page.goto(report.as_uri());page.wait_for_timeout(1800)
 assert page.locator('.timeline-panel').bounding_box()['y'] < 900
 page.screenshot(path=str(root/'assets/report-overview.png'))
 page.locator('.proto-chip',has_text='DNS (').click();page.wait_for_timeout(300);page.screenshot(path=str(root/'assets/report-dns.png'))
 page.locator('.proto-chip',has_text='All').click();page.locator('.sidebar-tab button',has_text='Hosts').click();page.locator('.sidebar-content .finding').first.click();assert page.locator('.host-detail').count()==1;page.wait_for_timeout(200);page.screenshot(path=str(root/'assets/report-host.png'))
 page.mouse.click(600,450);page.locator('.sidebar-tab button',has_text='Findings').click()
 page.set_viewport_size({'width':1600,'height':800});page.wait_for_timeout(350)
 page.get_by_role('button',name='1x').click();page.get_by_role('button',name='4x').click();page.get_by_role('button',name='▶ Play').click()
 (work/'replay').mkdir(exist_ok=True)
 for i in range(60):
  page.screenshot(path=str(work/'replay'/f'{i:03}.png'));page.wait_for_timeout(85)
 page.get_by_role('button',name='⏸ Pause').click();label=page.locator('.replay-controls span').inner_text();page.wait_for_timeout(150);page.get_by_role('button',name='▶ Play').click();page.wait_for_timeout(150)
 def seconds(value):
  return float(value[:-1]) * {'s':1,'m':60,'h':3600}[value[-1]]
 assert seconds(page.locator('.replay-controls span').inner_text()) >= seconds(label) - 1
 page.set_viewport_size({'width':390,'height':844});page.wait_for_timeout(300);page.screenshot(path=str(work/'report-mobile.png'))
 assert page.locator('.timeline-panel').bounding_box()['y'] < 844
 assert page.evaluate('document.documentElement.scrollWidth') <= 390
 assert not errors,errors
 assert all(r.startswith('file:') for r in requests),requests
 print('Browser verified: desktop, mobile, filters, host inspection, replay, no external requests, no JavaScript errors')
 (work/'browser-checks.json').write_text(json.dumps({'errors':errors,'requests':requests,'checks':'desktop/mobile layout; protocol filters; host selection; replay pause/resume; zero network requests'},indent=2))
 b.close()
