#!/usr/bin/env python3
"""
generate_scene_docs.py - scene documentation generator (Case Omega, Part 1)

Produces the digital scene sketch (floor plan with evidence-tag and camera
positions), the evidence-tag sheet, and clearly-labelled SIMULATED photo
placeholders. Everything depicted is fictional.

Usage:
    python3 tools/generate_scene_docs.py [output_dir]
"""
import sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("evidence/scene")
OUT.mkdir(parents=True, exist_ok=True)
FD = "/usr/share/fonts/truetype/dejavu/"


def font(size, bold=False):
    return ImageFont.truetype(FD + ("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"), size)


# Evidence items: id, label, description, make/model(dummy), state, location, seal
ITEMS = [
    ("ET-01", "HOSP-FS01", "File server (clinical shares)", "Rack server 2U (dummy) S/N SIM-FS01-0042",
     "Powered ON; console shows ransom note", "Server Room, rack R1, U12", "TE-30101"),
    ("ET-02", "HOSP-EHR-DB01", "EHR database server", "Rack server 2U (dummy) S/N SIM-DB01-0017",
     "Powered ON; EHR-SQL service stopped", "Server Room, rack R2, U08", "TE-30102"),
    ("ET-03", "BKP-APL-01", "Backup appliance", "Storage appliance (dummy) S/N SIM-BKP-0003",
     "Powered ON; last good backup 2026-10-13 01:00", "Server Room, rack R3, U04", "TE-30103"),
    ("ET-04", "FW-EDGE-01", "Edge firewall (config + logs)", "Firewall appliance (dummy) S/N SIM-FW-0001",
     "Powered ON; isolation policy active", "Network Closet, rack R4", "TE-30104"),
    ("ET-05", "BILLING-WS-07", "Billing workstation (suspected entry point)", "Desktop PC (dummy) S/N SIM-WS-0107",
     "Powered ON; screen locked", "Billing Office, desk W-07", "TE-30105"),
    ("ET-06", "USB-UNREG-01", "Unregistered USB flash drive", "Kingston DataTraveler 3.0 (dummy) serial 0019E06B1C2A9F31",
     "Still inserted in front port of ET-05", "Billing Office, desk W-07", "TE-30106"),
    ("ET-07", "NURSE-WS-B1", "Nurse-station terminal (first report of outage)", "Thin client (dummy) S/N SIM-TC-0231",
     "Powered ON; EHR login error on screen", "Nurse Station B", "TE-30107"),
    ("ET-08", "SW-CORE-01", "Core switch (config + MAC/ARP tables)", "Switch (dummy) S/N SIM-SW-0002",
     "Powered ON; no changes made", "Network Closet, rack R4", "TE-30108"),
    ("CLD-01", "M365-AUDIT", "Cloud: Microsoft 365 audit + sign-in logs (export)", "Tenant sunrisemed-example (fictional)",
     "Remote; exported by tenant admin under supervision", "Cloud (non-physical)", "n/a (hash only)"),
]


def draw_sketch(path):
    W, H = 1500, 960
    img = Image.new("RGB", (W, H), (250, 248, 240))
    d = ImageDraw.Draw(img)
    d.text((30, 18), "SCENE SKETCH - Sunrise Medical Centre (fictional), Level 2 IT & Admin Wing", font=font(24, True), fill=(20, 20, 20))
    d.text((30, 52), "Case OMG-2026-047  |  Sketched by FA-1  |  2026-10-14 04:05 IST  |  NOT TO SCALE  |  SIMULATED", font=font(15), fill=(80, 80, 80))

    def room(x1, y1, x2, y2, name, fill):
        d.rectangle([x1, y1, x2, y2], fill=fill, outline=(40, 40, 40), width=4)
        d.text((x1 + 12, y1 + 8), name, font=font(17, True), fill=(30, 30, 30))

    room(40, 100, 520, 430, "SERVER ROOM", (226, 232, 245))
    room(520, 100, 900, 430, "IT OFFICE", (238, 238, 238))
    room(900, 100, 1460, 430, "BILLING OFFICE", (240, 232, 220))
    room(40, 430, 1460, 520, "CORRIDOR", (255, 255, 255))
    room(40, 520, 600, 900, "NURSE STATION B", (226, 240, 230))
    room(600, 520, 900, 900, "NETWORK CLOSET (MDF)", (226, 232, 245))
    room(900, 520, 1460, 900, "RECEPTION / ENTRANCE / STAIRS", (238, 238, 238))

    # doors (gaps drawn as white bars)
    for (x1, y1, x2, y2) in [(250, 426, 330, 434), (680, 426, 760, 434), (1100, 426, 1180, 434),
                             (250, 516, 330, 524), (700, 516, 780, 524), (1100, 516, 1180, 524)]:
        d.rectangle([x1, y1, x2, y2], fill=(255, 255, 255))

    # racks in server room
    for i, (rx, rn) in enumerate([(70, "R1"), (170, "R2"), (270, "R3")]):
        d.rectangle([rx, 160, rx + 70, 330], fill=(120, 130, 150), outline=(30, 30, 30), width=3)
        d.text((rx + 22, 335), rn, font=font(15, True), fill=(20, 20, 20))
    d.text((70, 365), "R1 HOSP-FS01   R2 EHR-DB01   R3 BKP-APL-01", font=font(13), fill=(40, 40, 40))
    # closet rack
    d.rectangle([660, 600, 730, 780], fill=(120, 130, 150), outline=(30, 30, 30), width=3)
    d.text((665, 785), "R4 FW + SW-CORE", font=font(13, True), fill=(20, 20, 20))
    # billing desks
    for i, name in enumerate(["W-05", "W-06", "W-07", "W-08"]):
        x = 940 + i * 130
        d.rectangle([x, 220, x + 100, 290], fill=(180, 150, 110), outline=(30, 30, 30), width=3)
        d.text((x + 28, 296), name, font=font(14, True), fill=(20, 20, 20))
    # nurse station desk
    d.rectangle([120, 640, 420, 720], fill=(150, 190, 160), outline=(30, 30, 30), width=3)
    d.text((170, 730), "Terminal B1", font=font(14, True), fill=(20, 20, 20))

    # evidence tags (red circles)
    pos = {"ET-01": (105, 245), "ET-02": (205, 245), "ET-03": (305, 245), "ET-04": (695, 640),
           "ET-05": (1210, 255), "ET-06": (1250, 330), "ET-07": (270, 680), "ET-08": (695, 740)}
    for tid, (px, py) in pos.items():
        d.ellipse([px - 22, py - 22, px + 22, py + 22], fill=(200, 30, 30), outline=(255, 255, 255), width=3)
        d.text((px - 16, py - 9), tid[3:], font=font(15, True), fill=(255, 255, 255))
        d.text((px - 24, py + 24), tid, font=font(12, True), fill=(160, 20, 20))

    # camera positions (blue triangles) with view lines
    cams = {"P1": ((200, 400), (205, 270)), "P2": ((120, 600), (270, 670)), "P3": ((1100, 400), (1210, 260)),
            "P4": ((1300, 400), (1250, 335)), "P5": ((760, 560), (705, 650)), "P6": ((100, 130), (105, 220))}
    for pid, ((cx, cy), (tx, ty)) in cams.items():
        d.line([cx, cy, tx, ty], fill=(30, 90, 200), width=2)
        d.polygon([(cx, cy - 14), (cx - 13, cy + 11), (cx + 13, cy + 11)], fill=(30, 90, 200), outline=(255, 255, 255))
        d.text((cx - 10, cy + 13), pid, font=font(13, True), fill=(20, 60, 160))

    # north arrow
    d.polygon([(1420, 880), (1405, 920), (1435, 920)], fill=(30, 30, 30))
    d.text((1412, 925), "N", font=font(18, True), fill=(30, 30, 30))

    # legend
    lx, ly = 960, 560
    d.rectangle([lx - 10, ly - 10, 1450, 880], outline=(60, 60, 60), width=2, fill=(255, 255, 255))
    d.text((lx, ly), "LEGEND", font=font(16, True), fill=(20, 20, 20))
    d.ellipse([lx, ly + 34, lx + 26, ly + 60], fill=(200, 30, 30))
    d.text((lx + 36, ly + 36), "Evidence tag (ET-xx) - see tag sheet", font=font(14), fill=(30, 30, 30))
    d.polygon([(lx + 13, ly + 74), (lx, ly + 98), (lx + 26, ly + 98)], fill=(30, 90, 200))
    d.text((lx + 36, ly + 76), "Photo position (Px) and direction", font=font(14), fill=(30, 30, 30))
    d.text((lx, ly + 112), "ET-01 HOSP-FS01        ET-05 BILLING-WS-07", font=font(13), fill=(30, 30, 30))
    d.text((lx, ly + 134), "ET-02 HOSP-EHR-DB01    ET-06 Unregistered USB", font=font(13), fill=(30, 30, 30))
    d.text((lx, ly + 156), "ET-03 BKP-APL-01       ET-07 NURSE-WS-B1", font=font(13), fill=(30, 30, 30))
    d.text((lx, ly + 178), "ET-04 FW-EDGE-01       ET-08 SW-CORE-01", font=font(13), fill=(30, 30, 30))
    d.text((lx, ly + 206), "CLD-01 (cloud M365 logs) is non-physical - not shown", font=font(13), fill=(90, 90, 90))
    d.text((lx, ly + 232), "Distances approximate. Doors shown as gaps in walls.", font=font(13), fill=(90, 90, 90))
    img.save(path)
    print("saved", path)


def draw_tag_sheet(path):
    cols, cw, ch, pad = 3, 480, 330, 20
    rows = (len(ITEMS) + cols - 1) // cols
    img = Image.new("RGB", (cols * (cw + pad) + pad, rows * (ch + pad) + pad + 50), (235, 235, 235))
    d = ImageDraw.Draw(img)
    d.text((pad, 14), "EVIDENCE TAG SHEET - Case OMG-2026-047 (SIMULATED)", font=font(20, True), fill=(20, 20, 20))
    for i, (tid, name, desc, model, state, loc, seal) in enumerate(ITEMS):
        x = pad + (i % cols) * (cw + pad)
        y = 50 + pad + (i // cols) * (ch + pad)
        d.rectangle([x, y, x + cw, y + ch], fill=(255, 250, 225), outline=(60, 60, 60), width=3)
        d.rectangle([x, y, x + cw, y + 44], fill=(200, 30, 30))
        d.text((x + 12, y + 8), f"{tid}   {name}", font=font(20, True), fill=(255, 255, 255))
        lines = [("Item", desc), ("Model", model), ("State", state), ("Found", loc),
                 ("When", "2026-10-14 04:05-04:40 IST"), ("Found by", "FA-1 (witness W-1)"), ("Seal no.", seal)]
        yy = y + 54
        for k, v in lines:
            d.text((x + 12, yy), f"{k}:", font=font(13, True), fill=(40, 40, 40))
            txt = v if len(v) <= 54 else v[:52] + ".."
            d.text((x + 92, yy), txt, font=font(13), fill=(30, 30, 30))
            yy += 36
    img.save(path)
    print("saved", path)


def draw_photo_placeholders(outdir):
    photos = [("P1", "Server Room - racks R1-R3, wide view from door", "04:07"),
              ("P2", "Nurse Station B - terminal B1 showing EHR error", "04:12"),
              ("P3", "Billing Office - desk W-07 with BILLING-WS-07", "04:18"),
              ("P4", "BILLING-WS-07 front panel - USB drive in situ (ET-06)", "04:19"),
              ("P5", "Network Closet - rack R4 (firewall + core switch)", "04:24"),
              ("P6", "HOSP-FS01 console - ransom note displayed", "04:09")]
    for pid, caption, tm in photos:
        img = Image.new("RGB", (800, 500), (62, 66, 74))
        d = ImageDraw.Draw(img)
        for k in range(14):  # abstract shapes only - not a depiction of anything real
            x = 40 + k * 52
            d.rectangle([x, 90 + (k % 3) * 40, x + 30, 330 + (k % 4) * 20], outline=(95, 100, 110), width=2)
        d.rectangle([0, 0, 799, 499], outline=(255, 180, 0), width=5)
        d.text((16, 14), "SIMULATED PHOTO PLACEHOLDER", font=font(16, True), fill=(255, 180, 0))
        d.rectangle([0, 420, 800, 500], fill=(20, 20, 20))
        d.text((16, 428), f"{pid}  |  {caption}", font=font(17, True), fill=(255, 255, 255))
        d.text((16, 458), f"2026-10-14 {tm} IST  |  Case OMG-2026-047  |  Scale ref: none (placeholder)", font=font(14), fill=(190, 190, 190))
        p = outdir / f"photo_{pid}.png"
        img.save(p)
        print("saved", p)


if __name__ == "__main__":
    draw_sketch(OUT / "scene_sketch.png")
    draw_tag_sheet(OUT / "evidence_tag_sheet.png")
    (OUT / "photos").mkdir(exist_ok=True)
    draw_photo_placeholders(OUT / "photos")
