#!/usr/bin/env python3
"""Merge expansion parts + image placements into BOOK-ENGLISH.md / BOOK-HINGLISH.md."""
import re

BASE = "/home/hatch/workspace/cyberrakshak"
PARTS = BASE + "/parts"

# (heading-regex, image-file, caption-en, caption-hi)
PART_IMAGES = [
    (r"^# PART 1:", "images/part1-fundamentals.png", "Cybersecurity fundamentals", "Cybersecurity ke mool siddhant"),
    (r"^# PART 2:", "images/part2-toolguide.png", "The CyberRakshak tool guide", "CyberRakshak tool guide"),
    (r"^# PART 3:", "images/part3-labs.png", "Practical labs", "Practical labs"),
    (r"^# PART 4:", "images/part4-advanced.png", "Advanced topics", "Advanced topics"),
    (r"^# PART 5:", "images/part5-soc.png", "Security Operations Center", "Security Operations Center"),
    (r"^# PART 6:", "images/part6-career.png", "Career and mastery", "Career aur mastery"),
    (r"^# PART 7:", "images/part7-mastery.png", "Defender mastery", "Defender mastery"),
    (r"^# BHAG 1:", "images/part1-fundamentals.png", "Cybersecurity fundamentals", "Cybersecurity ke mool siddhant"),
    (r"^# BHAG 2:", "images/part2-toolguide.png", "The CyberRakshak tool guide", "CyberRakshak tool guide"),
    (r"^# BHAG 3:", "images/part3-labs.png", "Practical labs", "Practical labs"),
    (r"^# BHAG 4:", "images/part4-advanced.png", "Advanced topics", "Advanced topics"),
    (r"^# BHAG 5:", "images/part5-soc.png", "Security Operations Center", "Security Operations Center"),
    (r"^# BHAG 6:", "images/part6-career.png", "Career and mastery", "Career aur mastery"),
    (r"^# BHAG 7:", "images/part7-mastery.png", "Defender mastery", "Defender mastery"),
]
CHAPTER_IMAGES = [
    (r"^## Chapter 2\b:", r"^## Adhyay 2\b:", "images/network-topology.png", "Network topology", "Network topology"),
    (r"^## Chapter 3\b:", r"^## Adhyay 3\b:", "images/hacker-vs-defender.png", "Hacker vs defender", "Hacker vs defender"),
    (r"^## Chapter 8\b:", r"^## Adhyay 8\b:", "images/tls-lock.png", "TLS encryption", "TLS encryption"),
    (r"^## Chapter 16\b:", r"^## Adhyay 16\b:", "images/incident-response.png", "Incident response cycle", "Incident response cycle"),
]

NEW_ORDER = ["expA_ch15-16", "expB_ch17-18", "expC_ch19-20", "expD_ch21-22",
             "expG_ch23-26", "expE_appDE", "expF_appFG"]

ABOUT_EN = "## About the Author"
ABOUT_HI = "## Lekhak ke Baare Me"


def insert_images(lines, is_hindi):
    out = []
    for ln in lines:
        out.append(ln)
        s = ln.strip()
        for pat, img, cap_en, cap_hi in PART_IMAGES:
            if re.match(pat, s):
                cap = cap_hi if is_hindi else cap_en
                out.append(f"\n![{cap}]({img})\n")
                break
        for pat_en, pat_hi, img, cap_en, cap_hi in CHAPTER_IMAGES:
            pat = pat_hi if is_hindi else pat_en
            if re.match(pat, s):
                cap = cap_hi if is_hindi else cap_en
                out.append(f"\n![{cap}]({img})\n")
                break
    return out


def build(md_path, lang_suffix, about_marker, is_hindi):
    with open(md_path, encoding="utf-8") as f:
        text = f.read()
    idx = text.find(about_marker)
    assert idx != -1, f"about marker not found in {md_path}"
    head, tail = text[:idx], text[idx:]

    new_parts = []
    for name in NEW_ORDER:
        p = f"{PARTS}/{name}_{lang_suffix}.md"
        with open(p, encoding="utf-8") as f:
            new_parts.append(f.read().strip())
    new_text = "\n\n---\n\n".join(new_parts)

    combined = head.rstrip() + "\n\n---\n\n" + new_text + "\n\n---\n\n" + tail.lstrip()
    lines = insert_images(combined.split("\n"), is_hindi)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"merged {md_path}")


build(BASE + "/BOOK-ENGLISH.md", "en", ABOUT_EN, False)
build(BASE + "/BOOK-HINGLISH.md", "hi", ABOUT_HI, True)
