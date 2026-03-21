"""Shared PDF text export helpers."""

import textwrap

PDF_LINES_PER_PAGE = 52
PDF_LINE_WIDTH = 95


def escape_pdf_text(value: str) -> str:
    """Escape text for PDF content streams."""
    escaped = value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return "".join(char if 32 <= ord(char) <= 126 else "?" for char in escaped)


def build_page_stream(lines: list[str]) -> bytes:
    """Build a PDF text stream for a single page."""
    commands: list[bytes] = [b"BT", b"/F1 11 Tf", b"40 800 Td"]

    for index, line in enumerate(lines):
        encoded = f"({escape_pdf_text(line)}) Tj".encode("latin-1", "replace")
        if index > 0:
            commands.append(b"0 -14 Td")
        commands.append(encoded)

    commands.append(b"ET")
    return b"\n".join(commands)


def chunk_lines(lines: list[str], chunk_size: int) -> list[list[str]]:
    """Split text lines into PDF pages."""
    if not lines:
        return [[""]]

    return [lines[index : index + chunk_size] for index in range(0, len(lines), chunk_size)]


def build_pdf(title: str, body_lines: list[str]) -> bytes:
    """Build a minimal multi-page PDF document."""
    lines = [title, "", *body_lines]
    pages = chunk_lines(lines, PDF_LINES_PER_PAGE)

    objects: dict[int, bytes] = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }

    page_object_ids: list[int] = []
    next_object_id = 4

    for page_lines in pages:
        page_object_id = next_object_id
        content_object_id = next_object_id + 1
        next_object_id += 2

        page_object_ids.append(page_object_id)
        page_stream = build_page_stream(page_lines)

        objects[page_object_id] = (
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            "/Resources << /Font << /F1 3 0 R >> >> "
            f"/Contents {content_object_id} 0 R >>"
        ).encode("ascii")
        objects[content_object_id] = (
            b"<< /Length " + str(len(page_stream)).encode("ascii") + b" >>\nstream\n" + page_stream + b"\nendstream"
        )

    kids = " ".join(f"{page_object_id} 0 R" for page_object_id in page_object_ids)
    objects[2] = f"<< /Type /Pages /Count {len(page_object_ids)} /Kids [ {kids} ] >>".encode("ascii")

    total_objects = next_object_id - 1
    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}

    for object_id in range(1, total_objects + 1):
        offsets[object_id] = len(pdf)
        pdf.extend(f"{object_id} 0 obj\n".encode("ascii"))
        pdf.extend(objects[object_id])
        pdf.extend(b"\nendobj\n")

    xref_start = len(pdf)
    pdf.extend(f"xref\n0 {total_objects + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")

    for object_id in range(1, total_objects + 1):
        pdf.extend(f"{offsets[object_id]:010d} 00000 n \n".encode("ascii"))

    pdf.extend(f"trailer\n<< /Size {total_objects + 1} /Root 1 0 R >>\n".encode("ascii"))
    pdf.extend(f"startxref\n{xref_start}\n%%EOF".encode("ascii"))

    return bytes(pdf)


def append_wrapped(lines: list[str], prefix: str, value: str | None) -> None:
    """Append wrapped key/value text lines for PDF output."""
    if value is None:
        return

    wrapped = textwrap.wrap(value, width=PDF_LINE_WIDTH) or [""]
    lines.append(f"{prefix}: {wrapped[0]}")

    for continuation in wrapped[1:]:
        lines.append(f"{prefix} (cont.): {continuation}")
