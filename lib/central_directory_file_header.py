import struct

import lib.constants as LC


class CentralDirectoryFileHeader:
    """
    The contents of the sctrucure are described by the following URL:
        - https://en.wikipedia.org/wiki/ZIP_(file_format)#Central_directory_file_header
    """

    # Offset 0, Bytes 4
    CentralDirectoryFileHeaderSignature = b"\x50\x4b\x01\x02"

    # Header length
    StructLength = 0

    def __init__(self, datas):
        """
        This function parses the central directory file header and calculates
        its total length.
        """

        try:
            if self.CentralDirectoryFileHeaderSignature != datas[0:4]:
                raise Exception(
                    "[x] Bad signature for: Central directory " + \
                    "file header signature."
                )

            # Offset 20, Bytes 4 (0xffffffff for ZIP64)
            self.CompressedSize = datas[20:24]

            # Offset 28, Bytes 2 (n)
            self.FileNameLength = datas[28:30]
            n = struct.unpack("I", self.FileNameLength + b"\x00"*2)[0]

            # Offset 30, Bytes 2 (m)
            self.ExtraFieldLength = datas[30:32]
            m = struct.unpack("I", self.ExtraFieldLength + b"\x00"*2)[0]

            # Offset 32, Bytes 2 (k)
            self.FileCommentLength = datas[32:34]
            k = struct.unpack("I", self.FileCommentLength + b"\x00"*2)[0]

            # Offset 42, Bytes 4 (0xffffffff for ZIP64)
            # This is the number of bytes between the start of the first disk on
            # which the file occurs, and the start of the local file header.
            # This allows software reading the central directory to locate the
            # position of the file inside the ZIP file. 
            self.RelativeOffsetOfLocalFileHeader = datas[42:46]

            # Offset 46, Bytes n
            self.FileName = datas[46:46+n]

            # Offset 46+n, Bytes m
            self.ExtraField = datas[46+n:46+n+m]

            # Offset 46+n+m, Bytes k
            self.FileComment  = datas[46+n+m:46+n+m+k]

        except Exception as error:
            print(error)
            exit(-1)

        self.StructLength = 46 + n + m + k

        if LC.DEBUG:
            print("[*] Central directory file header of size " + \
                 f"{hex(self.StructLength)} parsed."
            )

    """
    Thoses functions displays the information contained in the header.
    It is based on the information referenced by the following URL:
        - https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html
    """
    def get_compressed_size(self, remote_call=0):
        # Compressed size.
        CompressedSize = struct.unpack("I", self.CompressedSize)[0]

        if LC.DEBUG and not remote_call:
            print(f"\t- Compressed size: {hex(CompressedSize)} bytes")

        return CompressedSize

    def get_file_name_length(self, remote_call=0):
        # File name length.
        FileNameLength = struct.unpack("I", self.FileNameLength + b"\x00"*2)[0]

        if LC.DEBUG and not remote_call:
            print(f"\t- File name length: {FileNameLength}")

        return FileNameLength

    def get_extra_field_length(self, remote_call=0):
        # Extra field length.
        ExtraFieldLength = struct.unpack(
            "I",
            self.ExtraFieldLength + b"\x00"*2
        )[0]

        if LC.DEBUG and not remote_call:
            print(f"\t- Extra field length: {ExtraFieldLength}")

        return ExtraFieldLength

    def get_relative_offset_of_local_file_header(self, remote_call=0):
        # Offset of local header.
        RelativeOffsetOfLocalFileHeader = struct.unpack(
            "I",
            self.RelativeOffsetOfLocalFileHeader
        )[0]

        if LC.DEBUG and not remote_call:
            print("\t- Relative offset of local file header: " + \
                 f"{hex(RelativeOffsetOfLocalFileHeader)}"
            )

        return RelativeOffsetOfLocalFileHeader

    def get_file_name(self, remote_call=0):
        # File name.
        FileName = self.FileName.decode()
 
        if not remote_call:
            print(f"\t- File name: {FileName}")

        return FileName