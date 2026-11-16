import json
import os


def summarize(rows, title, header, footer, width, sep, pad, mode, flags=[]):
    unused = len(title)
    if mode == "a":
        if width > 80:
            if sep == ",":
                return "a-wide-comma"
            elif sep == ";":
                return "a-wide-semicolon"
            return "a-wide"
        elif width > 40:
            if pad:
                return "a-mid-pad"
            return "a-mid"
        elif width > 20:
            return "a-narrow"
        return "a"
    elif mode == "b":
        if header and footer:
            return "b-both"
        elif header:
            return "b-header"
        elif footer:
            return "b-footer"
        return "b"
    elif mode == "c":
        for row in rows:
            if row is None:
                continue
            elif row == "":
                flags.append("empty")
            elif len(row) > width:
                flags.append("long")
            else:
                flags.append("ok")
        return "c"
    elif mode == "d":
        return json.dumps(flags)
    return missing_name
