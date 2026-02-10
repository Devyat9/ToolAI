#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lnk_dump.py — Volcado rápido de campos clave desde un archivo .LNK (Windows Shell Link)
Referencia de formato: MS-SHLLINK (estructura general). Este script extrae:
- Flags, atributos, tamaño, icon index, showcmd, hotkey
- Timestamps (FILETIME) del .lnk
- StringData: Name, RelativePath, WorkingDir, Arguments, IconLocation
- LinkInfo: LocalBasePath (si existe) y/o ruta de red (UNC) básica

Nota: No resuelve el IDList (objetos shell) ni todos los campos avanzados.
Suficiente para análisis forense inicial y reversing de accesos directos maliciosos.
"""

import sys
import struct
from datetime import datetime, timezone

LNK_HEADER_SIZE = 0x4C
LNK_CLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00F"  # {00021401-0000-0000-C000-000000000046}

def filetime_to_dt(ft):
    # FILETIME: 100-ns since 1601-01-01; 0 => None
    if ft == 0:
        return None
    us = ft / 10
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return epoch + timedelta_microseconds(us)

def timedelta_microseconds(us):
    # evitar overflow con floats grandes
    from datetime import timedelta
    return timedelta(microseconds=int(us))

def fmt_dt(dt):
    return dt.isoformat() if dt else None

def read_unicode_or_ansi(f, is_unicode):
    if is_unicode:
        # Longitud en caracteres (UINT16), luego UTF-16LE sin terminador nulo
        (chars,) = struct.unpack("<H", f.read(2))
        raw = f.read(chars * 2)
        return raw.decode("utf-16le", errors="replace")
    else:
        # Longitud en bytes (UINT16), luego ANSI sin terminador nulo
        (length,) = struct.unpack("<H", f.read(2))
        raw = f.read(length)
        return raw.decode("cp1252", errors="replace")

def read_nullterm_str_at(buf, offset, encoding="ansi"):
    # Lee string terminada en 0 desde un buffer a partir de offset
    end = offset
    if encoding == "unicode":
        # UTF-16LE terminada en 0x0000
        while end + 1 < len(buf):
            if buf[end] == 0 and buf[end+1] == 0:
                break
            end += 2
        return buf[offset:end].decode("utf-16le", errors="replace")
    else:
        # ANSI terminada en 0x00
        while end < len(buf) and buf[end] != 0:
            end += 1
        return buf[offset:end].decode("cp1252", errors="replace")

def parse_linkinfo(f):
    # Devuelve dict con LocalBasePath y/o ruta de red (UNC) básica si se encuentra
    start = f.tell()
    hdr = f.read(4)
    if len(hdr) < 4:
        return {}, 0
    (size,) = struct.unpack("<I", hdr)
    if size < 0x1C:
        # Tamaño mínimo esperado para LinkInfo header
        f.seek(start + size)
        return {}, size
    rest = f.read(size - 4)
    buf = hdr + rest
    # Offsets relativos al inicio de LinkInfo
    LinkInfoHeaderSize, LinkInfoFlags, \
    VolumeIDOffset, LocalBasePathOffset, \
    CommonNetworkRelativeLinkOffset, CommonPathSuffixOffset = struct.unpack("<IIIIII", buf[4:4+24])

    out = {}
    # LocalBasePath (si existe)
    if LocalBasePathOffset != 0 and LocalBasePathOffset < size:
        lbp = read_nullterm_str_at(buf, LocalBasePathOffset, "ansi")
        if lbp:
            out["LocalBasePath"] = lbp

    # CommonNetworkRelativeLink (si existe) — extraemos UNC si está presente
    if CommonNetworkRelativeLinkOffset != 0 and CommonNetworkRelativeLinkOffset < size:
        # CommonNetworkRelativeLink estructura: ver MS-SHLLINK; el Nombre del recurso suele estar tras varios campos
        cnrl_off = CommonNetworkRelativeLinkOffset
        # Comprobación mínima para no romper
        if cnrl_off + 20 <= size:
            # Offsets internos dentro de CNrL
            try:
                # Layout básico (no exhaustivo)
                (cnrl_size,) = struct.unpack("<I", buf[cnrl_off:cnrl_off+4])
                # NameOffset a partir de cnrl_off + 20 (aprox), robustez básica:
                # La especificación define varios offsets; aquí intentamos ubicarlos de forma defensiva
                # Buscamos una cadena ANSI terminada en 0 cerca del final de CNrL
                # Heurística: leer desde cnrl_off+20 como nombre
                candidate = read_nullterm_str_at(buf, cnrl_off + 20, "ansi")
                if candidate and "\\" in candidate:
                    out["UNCPath"] = candidate
            except Exception:
                pass

    # CommonPathSuffix (parte final del path combinado)
    if CommonPathSuffixOffset != 0 and CommonPathSuffixOffset < size:
        cps = read_nullterm_str_at(buf, CommonPathSuffixOffset, "ansi")
        if cps:
            out["CommonPathSuffix"] = cps

    # Avanzar el file pointer al final de LinkInfo
    f.seek(start + size)
    return out, size

def main(path):
    with open(path, "rb") as f:
        # Header
        header = f.read(LNK_HEADER_SIZE)
        if len(header) < LNK_HEADER_SIZE:
            print("Archivo demasiado corto para ser .LNK")
            return

        (hdr_size,) = struct.unpack("<I", header[:4])
        if hdr_size != LNK_HEADER_SIZE:
            print("Tamaño de cabecera inesperado; no parece .LNK válido.")
            return

        clsid = header[4:4+16]
        if clsid != LNK_CLSID:
            print("CLSID no corresponde a Shell Link; no es un .LNK.")
            return

        (LinkFlags, FileAttrs,
         CreationTime, AccessTime, WriteTime,
         FileSize, IconIndex, ShowCmd, HotKey) = struct.unpack("<IIQQQIIIH", header[20:20+4+4+8+8+8+4+4+4+2])

        # Flags
        flags = {
            "HasTargetIDList":    bool(LinkFlags & 0x00000001),
            "HasLinkInfo":        bool(LinkFlags & 0x00000002),
            "HasName":            bool(LinkFlags & 0x00000004),
            "HasRelativePath":    bool(LinkFlags & 0x00000008),
            "HasWorkingDir":      bool(LinkFlags & 0x00000010),
            "HasArguments":       bool(LinkFlags & 0x00000020),
            "HasIconLocation":    bool(LinkFlags & 0x00000040),
            "IsUnicode":          bool(LinkFlags & 0x00000080),
        }
        is_unicode = flags["IsUnicode"]

        # Tras el Header viene (opcional) el IDList si HasTargetIDList
        if flags["HasTargetIDList"]:
            (idlist_size,) = struct.unpack("<H", f.read(2))
            f.seek(f.tell() + idlist_size)

        # LinkInfo (opcional)
        linkinfo_data = {}
        if flags["HasLinkInfo"]:
            ld, _ = parse_linkinfo(f)
            linkinfo_data.update(ld)

        # StringData (varía si IsUnicode o ANSI)
        name = relpath = workdir = args = iconloc = None
        try:
            if flags["HasName"]:
                name = read_unicode_or_ansi(f, is_unicode)
            if flags["HasRelativePath"]:
                relpath = read_unicode_or_ansi(f, is_unicode)
            if flags["HasWorkingDir"]:
                workdir = read_unicode_or_ansi(f, is_unicode)
            if flags["HasArguments"]:
                args = read_unicode_or_ansi(f, is_unicode)
            if flags["HasIconLocation"]:
                iconloc = read_unicode_or_ansi(f, is_unicode)
        except Exception:
            # Algunos .lnk malformados pueden truncar StringData; continuar con lo posible
            pass

        # Salida
        from pprint import pprint
        out = {
            "LinkFlags": flags,
            "FileAttributes(hex)": f"0x{FileAttrs:08X}",
            "Size(bytes)": FileSize,
            "IconIndex": IconIndex,
            "ShowCmd": ShowCmd,
            "HotKey": HotKey,
            "CreationTime": CreationTime,
            "AccessTime": AccessTime,
            "WriteTime": WriteTime,
            "CreationTime(UTC)": fmt_dt(filetime_to_dt(CreationTime)),
            "AccessTime(UTC)": fmt_dt(filetime_to_dt(AccessTime)),
            "WriteTime(UTC)": fmt_dt(filetime_to_dt(WriteTime)),
            "Name": name,
            "RelativePath": relpath,
            "WorkingDir": workdir,
            "Arguments": args,
            "IconLocation": iconloc,
        }
        out.update(linkinfo_data)

        pprint(out)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 lnk_dump.py <archivo.lnk>")
        sys.exit(1)
    main(sys.argv[1])

