# Based on @danvk work.
#     - https://github.com/danvk/RangeHTTPServer
import argparse
import http.server as SimpleHTTPServer
import os
import re

from http.server import SimpleHTTPRequestHandler


BYTE_RANGE_RE = re.compile(r"bytes=(\d+)-(\d+)?$")


def copy_byte_range(infile, outfile, start=None, stop=None, bufsize=16*1024):
    if start is not None: infile.seek(start)
    while 1:
        to_read = min(bufsize, stop + 1 - infile.tell() if stop else bufsize)
        buf = infile.read(to_read)
        if not buf:
            break
        outfile.write(buf)


def parse_byte_range(byte_range):
    if byte_range.strip() == "":
        return None, None

    m = BYTE_RANGE_RE.match(byte_range)
    if not m:
        raise ValueError("Invalid byte range %s" % byte_range)

    first, last = [x and int(x) for x in m.groups()]
    if last and last < first:
        raise ValueError("Invalid byte range %s" % byte_range)
    return first, last


class RangeRequestHandler(SimpleHTTPRequestHandler):
    def send_head(self):
        if "Range" not in self.headers:
            self.range = None
            return SimpleHTTPRequestHandler.send_head(self)
        try:
            self.range = parse_byte_range(self.headers["Range"])
        except ValueError as e:
            self.send_error(400, "Invalid byte range")
            return None
        first, last = self.range

        path = self.translate_path(self.path)
        f = None
        ctype = self.guess_type(path)
        try:
            f = open(path, "rb")
        except IOError:
            self.send_error(404, "File not found")
            return None

        fs = os.fstat(f.fileno())
        file_len = fs[6]
        if first >= file_len:
            self.send_error(416, "Requested Range Not Satisfiable")
            return None

        self.send_response(206)
        self.send_header("Content-type", ctype)

        if last is None or last >= file_len:
            last = file_len - 1
        response_length = last - first + 1

        self.send_header("Content-Range",
                         "bytes %s-%s/%s" % (first, last, file_len))
        self.send_header("Content-Length", str(response_length))
        self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
        self.end_headers()
        return f

    def end_headers(self):
        self.send_header("Accept-Ranges", "bytes")
        return SimpleHTTPRequestHandler.end_headers(self)

    def copyfile(self, source, outputfile):
        if not self.range:
            return SimpleHTTPRequestHandler.copyfile(self, source, outputfile)

        start, stop = self.range
        copy_byte_range(source, outputfile, start, stop)

parser = argparse.ArgumentParser()
parser.add_argument("port", action="store",
                    default=8000, type=int,
                    nargs="?", help="Specify alternate port [default: 8000]")

args = parser.parse_args()
SimpleHTTPServer.test(HandlerClass=RangeRequestHandler, port=args.port)
