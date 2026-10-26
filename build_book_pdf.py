#!/usr/bin/env python3
"""Build CyberRakshak book PDFs (English + Hinglish) from markdown sources.
Two-pass: pass 1 collects TOC entries, pass 2 renders TOC after title page."""
import math
import re
from fpdf import FPDF

BOOK_TITLE = "CyberRakshak"
BOOK_SUBTITLE = "The Complete Defensive Cybersecurity Handbook"
TAGLINE = "Hacker se pehle \u2014 CyberRakshak!"
AUTHOR = "Dinesh Singh"
EDITION = "First Edition \u2014 October 2026"
ACCENT = (20, 60, 120)
BASE_DIR = "/home/hatch/workspace/cyberrakshak"
TITLE_ART = BASE_DIR + "/images/title-art.png"


class BookPDF(FPDF):
    def __init__(self, lang_label):
        super().__init__(format="A4")
        self.lang_label = lang_label
        # Unicode fonts (DejaVu ships with most Linux distros)
        fd = "/usr/share/fonts/truetype/dejavu/"
        self.add_font("DejaVu", "", fd + "DejaVuSans.ttf", uni=True)
        self.add_font("DejaVu", "B", fd + "DejaVuSans-Bold.ttf", uni=True)
        self.add_font("DejaVu", "I", fd + "DejaVuSans.ttf", uni=True)
        self.add_font("DejaVu", "BI", fd + "DejaVuSans-Bold.ttf", uni=True)
        self.add_font("DejaVuMono", "", fd + "DejaVuSansMono.ttf", uni=True)
        self.add_font("DejaVuMono", "B", fd + "DejaVuSansMono-Bold.ttf", uni=True)
        self.set_auto_page_break(True, margin=25)
        self.toc_entries = []
        self.in_toc = False
        self.collect_only = False  # pass 1: don't render TOC yet

    def header(self):
        if self.page_no() == 1 or self.in_toc:
            return
        self.set_font("DejaVu", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 8, f"{BOOK_TITLE}  |  {self.lang_label}", align="R")
        self.ln(12)

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-18)
        self.set_font("DejaVu", "", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 8, f"Page {self.page_no()}", align="C")

    # ---------- inline markdown ----------
    def _write_md_line(self, text, size=11, style=""):
        self.set_font("DejaVu", style, size)
        self.set_text_color(30, 30, 30)
        parts = re.split(r"(\*\*.+?\*\*|\*[^*]+?\*|`.+?`)", text)
        for p in parts:
            if not p:
                continue
            if p.startswith("**") and p.endswith("**") and len(p) > 4:
                self.set_font("DejaVu", "B", size)
                self.set_text_color(30, 30, 30)
                self.write(6, p[2:-2])
            elif p.startswith("*") and p.endswith("*") and len(p) > 2 and not p.startswith("**"):
                self.set_font("DejaVu", "I", size)
                self.set_text_color(30, 30, 30)
                self.write(6, p[1:-1])
            elif p.startswith("`") and p.endswith("`") and len(p) > 2:
                self.set_font("DejaVuMono", "", size - 0.5)
                self.set_text_color(140, 30, 30)
                self.write(6, p[1:-1])
            else:
                self.set_font("DejaVu", style, size)
                self.set_text_color(30, 30, 30)
                self.write(6, p)
        self.ln(7 if size <= 11 else 9)

    # ---------- block elements ----------
    def chapter_heading(self, text, level, record=True):
        if level == 1:
            self.add_page()
            self.ln(10)
            self.set_font("DejaVu", "B", 22)
            self.set_text_color(*ACCENT)
            self.multi_cell(0, 11, text, align="C")
            self.ln(6)
            if record:
                self.toc_entries.append((1, text, self.page_no()))
        elif level == 2:
            self.add_page()
            self.set_font("DejaVu", "B", 17)
            self.set_text_color(*ACCENT)
            self.multi_cell(0, 9, text)
            self.ln(2)
            self.set_draw_color(*ACCENT)
            self.set_line_width(0.8)
            self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
            self.ln(6)
            if record:
                self.toc_entries.append((2, text, self.page_no()))
        else:
            self.ln(3)
            self.set_font("DejaVu", "B", 13)
            self.set_text_color(40, 40, 40)
            self.multi_cell(0, 8, text)
            self.ln(2)

    def code_block(self, lines):
        x = self.l_margin
        w = self.w - self.l_margin - self.r_margin
        h = 6 * len(lines) + 6
        if self.get_y() + h > self.h - 25:
            self.add_page()
        y0 = self.get_y()
        self.set_fill_color(245, 245, 245)
        self.rect(x, y0, w, h, style="F")
        self.set_font("DejaVuMono", "", 9)
        self.set_text_color(30, 30, 30)
        self.set_xy(x + 3, y0 + 3)
        for ln in lines:
            self.set_x(x + 3)
            self.cell(w - 6, 6, ln[:115])
            self.ln(6)
        self.set_xy(x, y0 + h + 3)

    def bullet(self, text):
        self.set_x(self.l_margin)
        self.set_font("DejaVu", "", 11)
        self.set_text_color(30, 30, 30)
        self.cell(8, 6, "\u2022")
        parts = re.split(r"(\*\*.+?\*\*)", text)
        for p in parts:
            if not p:
                continue
            if p.startswith("**") and p.endswith("**") and len(p) > 4:
                self.set_font("DejaVu", "B", 11)
                self.set_text_color(30, 30, 30)
                self.write(6, p[2:-2])
            else:
                self.set_font("DejaVu", "", 11)
                self.set_text_color(30, 30, 30)
                self.write(6, p.replace("`", ""))
        self.ln(7)

    def table(self, rows):
        if not rows:
            return
        cols = len(rows[0])
        w = self.w - self.l_margin - self.r_margin
        cw = w / cols
        max_chars = max(8, int(cw / 2.2))
        self.set_font("DejaVu", "B", 9)
        self.set_fill_color(*ACCENT)
        self.set_text_color(255, 255, 255)
        for c in rows[0]:
            self.cell(cw, 8, c.strip()[:max_chars], border=1, fill=True)
        self.ln()
        self.set_font("DejaVu", "", 9)
        self.set_text_color(30, 30, 30)
        self.set_fill_color(240, 244, 250)
        fill = False
        for r in rows[1:]:
            if self.get_y() > self.h - 35:
                self.add_page()
            # row height for wrapped text: keep simple single-line truncation
            for c in r:
                self.cell(cw, 7, c.strip().replace("`", "")[:max_chars], border=1, fill=fill)
            self.ln()
            fill = not fill
        self.ln(4)

    def quote_block(self, lines):
        self.set_draw_color(*ACCENT)
        x = self.l_margin
        for ln in lines:
            y0 = self.get_y()
            self.set_font("DejaVu", "I", 10)
            self.set_text_color(80, 80, 80)
            self.set_x(x + 6)
            self.multi_cell(self.w - self.l_margin - self.r_margin - 6, 6, ln)
            y1 = self.get_y()
            self.set_line_width(0.8)
            self.line(x + 2, y0, x + 2, y1)
        self.ln(3)
        self.set_text_color(30, 30, 30)

    def illustration(self, rel_path, caption=""):
        import os
        full = os.path.join(BASE_DIR, rel_path)
        if not os.path.exists(full):
            return
        # keep image + caption together on one page
        if self.get_y() > self.h - 110:
            self.add_page()
        self.ln(4)
        img_w = 150
        x = (self.w - img_w) / 2
        try:
            self.image(full, x=x, w=img_w)
        except Exception:
            return
        self.ln(4)
        if caption:
            self.set_font("DejaVu", "I", 9)
            self.set_text_color(100, 100, 100)
            self.cell(0, 6, caption, align="C", new_x="LMARGIN", new_y="NEXT")
            self.ln(4)
        self.set_text_color(30, 30, 30)

    # ---------- front matter ----------
    def title_page(self):
        self.add_page()
        self.ln(22)
        self.set_draw_color(*ACCENT)
        self.set_line_width(1.2)
        self.line(60, self.get_y(), 150, self.get_y())
        self.ln(8)
        self.set_font("DejaVu", "B", 40)
        self.set_text_color(*ACCENT)
        self.cell(0, 18, BOOK_TITLE, align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(2)
        self.set_font("DejaVu", "", 15)
        self.set_text_color(60, 60, 60)
        self.multi_cell(0, 9, BOOK_SUBTITLE, align="C")
        self.ln(4)
        self.set_font("DejaVu", "BI", 14)
        self.set_text_color(150, 40, 40)
        self.cell(0, 10, f'"{TAGLINE}"', align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(6)
        import os
        if os.path.exists(TITLE_ART):
            try:
                img_w = 85
                self.image(TITLE_ART, x=(self.w - img_w) / 2, w=img_w)
                self.ln(6)
            except Exception:
                pass
        self.set_font("DejaVu", "", 13)
        self.set_text_color(40, 40, 40)
        self.cell(0, 9, f"By {AUTHOR}", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(4)
        self.set_font("DejaVu", "I", 11)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, f"{self.lang_label} Edition", align="C", new_x="LMARGIN", new_y="NEXT")
        self.cell(0, 8, EDITION, align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(20)
        self.set_draw_color(*ACCENT)
        self.line(60, self.get_y(), 150, self.get_y())

    def render_toc(self, entries):
        self.in_toc = True
        self.add_page()
        start_page = self.page_no()
        title = "Table of Contents" if self.lang_label == "English" else "Vishay-Suchi"
        self.set_font("DejaVu", "B", 20)
        self.set_text_color(*ACCENT)
        self.cell(0, 12, title, align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(6)
        for level, t, pg in entries:
            if self.get_y() > self.h - 30:
                self.add_page()
            if level == 1:
                self.ln(3)
                self.set_font("DejaVu", "B", 12)
                self.set_text_color(*ACCENT)
            else:
                self.set_font("DejaVu", "", 10.5)
                self.set_text_color(40, 40, 40)
            indent = 10 if level == 1 else 20
            self.set_x(self.l_margin + indent)
            t2 = t if len(t) <= 58 else t[:56] + ".."
            self.cell(115, 7, t2)
            self.cell(0, 7, str(pg), align="R", new_x="LMARGIN", new_y="NEXT")
        self.in_toc = False
        return self.page_no() - start_page + 1


def render_content(pdf, lines, record):
    started = False
    i = 0
    in_code = False
    code_lines = []
    in_quote = False
    quote_lines = []
    table_rows = []
    in_table = False
    para_buf = []

    def flush_para():
        if para_buf:
            text = " ".join(para_buf).strip()
            if text and text != "---":
                pdf._write_md_line(text)
            para_buf.clear()

    def flush_table():
        nonlocal table_rows, in_table
        if table_rows:
            rows = [r for r in table_rows if not re.match(r"^\|?[\s\-\:|]+\|?$", r)]
            parsed = [[c.strip() for c in r.strip().strip("|").split("|")] for r in rows]
            # normalize column counts
            n = max(len(r) for r in parsed)
            parsed = [r + [""] * (n - len(r)) for r in parsed]
            pdf.table(parsed)
            table_rows = []
        in_table = False

    def flush_quote():
        nonlocal quote_lines, in_quote
        if quote_lines:
            pdf.quote_block(quote_lines)
            quote_lines = []
        in_quote = False

    while i < len(lines):
        ln = lines[i]
        s = ln.strip()

        if not started:
            if re.match(r"^#{1,2}\s+(PART|BHAG|Preface|Prastavna)", s):
                started = True
            else:
                i += 1
                continue

        if s.startswith("```"):
            if in_code:
                pdf.code_block(code_lines)
                code_lines = []
                in_code = False
            else:
                flush_para()
                flush_table()
                in_code = True
            i += 1
            continue
        if in_code:
            code_lines.append(ln.rstrip("\n"))
            i += 1
            continue

        if s.startswith(">"):
            flush_para()
            in_quote = True
            quote_lines.append(s[1:].strip())
            i += 1
            continue
        elif in_quote:
            flush_quote()

        if re.match(r"^\|.*\|$", s):
            flush_para()
            in_table = True
            table_rows.append(s)
            i += 1
            continue
        elif in_table:
            flush_table()

        if s == "---":
            flush_para()
            pdf.ln(4)
            i += 1
            continue

        m_img = re.match(r"^!\[(.*?)\]\((.*?)\)$", s)
        if m_img:
            flush_para()
            flush_table()
            pdf.illustration(m_img.group(2).strip(), m_img.group(1).strip())
            i += 1
            continue

        m = re.match(r"^(#{1,4})\s+(.*)", s)
        if m:
            flush_para()
            level = len(m.group(1))
            title = m.group(2).strip()
            if re.match(r"(Table of Contents|Vishay-Suchi)", title, re.I):
                i += 1
                while i < len(lines):
                    s2 = lines[i].strip()
                    if re.match(r"^#{1,2}\s+", s2):
                        break
                    i += 1
                continue
            pdf.chapter_heading(title, level, record=record)
            i += 1
            continue

        if re.match(r"^[-*]\s+", s):
            flush_para()
            pdf.bullet(re.sub(r"^[-*]\s+", "", s))
            i += 1
            continue

        if re.match(r"^\d+\.\s+", s):
            flush_para()
            pdf.bullet(re.sub(r"^\d+\.\s+", "", s))
            i += 1
            continue

        if s == "":
            flush_para()
            i += 1
            continue

        para_buf.append(s)
        i += 1

    flush_para()
    flush_table()
    flush_quote()


def build_book(md_path, out_path, lang_label):
    with open(md_path, encoding="utf-8") as f:
        lines = f.read().split("\n")

    # Pass 1: render content only, collect TOC entries (page numbers relative to content start)
    p1 = BookPDF(lang_label)
    p1.set_title(f"{BOOK_TITLE} - {lang_label}")
    p1.set_author(AUTHOR)
    render_content(p1, lines, record=True)
    entries_rel = list(p1.toc_entries)

    # Estimate TOC pages, iterate until stable
    toc_pages = max(1, math.ceil(len(entries_rel) / 38))
    for _ in range(4):
        p2 = BookPDF(lang_label)
        p2.set_title(f"{BOOK_TITLE} - {lang_label}")
        p2.set_author(AUTHOR)
        p2.title_page()
        offset = p2.page_no() + toc_pages  # content starts after title + TOC
        entries_abs = [(lv, t, pg + offset) for lv, t, pg in entries_rel]
        used = p2.render_toc(entries_abs)
        if used == toc_pages:
            break
        toc_pages = used
    else:
        # fallback: one more build with last estimate
        pass

    render_content(p2, lines, record=False)
    p2.output(out_path)
    print(f"Wrote {out_path} ({p2.page_no()} pages, {len(entries_rel)} TOC entries)")


if __name__ == "__main__":
    base = "/home/hatch/workspace/cyberrakshak"
    build_book(f"{base}/BOOK-ENGLISH.md", f"{base}/CyberRakshak-Book-English.pdf", "English")
    build_book(f"{base}/BOOK-HINGLISH.md", f"{base}/CyberRakshak-Book-Hinglish.pdf", "Hinglish")
