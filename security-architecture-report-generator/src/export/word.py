from __future__ import annotations

from io import BytesIO

from docx import Document


def markdown_to_docx_bytes(markdown_text: str, title: str = "Security Architecture Recommendation") -> bytes:
    doc = Document()
    doc.add_heading(title, level=0)

    for raw_line in markdown_text.splitlines():
        line = raw_line.strip()
        if not line:
            doc.add_paragraph("")
            continue

        if line.startswith("# "):
            doc.add_heading(line[2:].strip(), level=1)
            continue
        if line.startswith("## "):
            doc.add_heading(line[3:].strip(), level=2)
            continue
        if line.startswith("### "):
            doc.add_heading(line[4:].strip(), level=3)
            continue

        if line.startswith("- [ ] "):
            doc.add_paragraph(line[6:].strip(), style="List Bullet")
            continue
        if line.startswith("- "):
            doc.add_paragraph(line[2:].strip(), style="List Bullet")
            continue

        doc.add_paragraph(line)

    output = BytesIO()
    doc.save(output)
    output.seek(0)
    return output.getvalue()

