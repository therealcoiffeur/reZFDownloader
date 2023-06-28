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

            # Offset 4, Bytes 2
            self.VersionMadeBy = datas[4:6]

            # Offset 6, Bytes 2
            self.VersionNeededToExtract = datas[6:8]

            # Offset 8, Bytes 2
            self.GeneralPurposeBitFlag = datas[8:10]

            # Offset 10, Bytes 2
            self.CompressionMethod = datas[10:12]

            # Offset 12, Bytes 2
            self.FileLastModificationTime = datas[12:14]

            # Offset 14, Bytes 2
            self.FileLastModificationDate = datas[14:16]

            # Offset 16, Bytes 4
            self.CRC32OfUncompressedData = datas[16:20]

            # Offset 20, Bytes 4 (0xffffffff for ZIP64)
            self.CompressedSize = datas[20:24]

            # Offset 24, Bytes 4 (0xffffffff for ZIP64)
            self.UncompressedSize = datas[24:28]

            # Offset 28, Bytes 2 (n)
            self.FileNameLength = datas[28:30]
            n = struct.unpack("I", self.FileNameLength + b"\x00"*2)[0]

            # Offset 30, Bytes 2 (m)
            self.ExtraFieldLength = datas[30:32]
            m = struct.unpack("I", self.ExtraFieldLength + b"\x00"*2)[0]

            # Offset 32, Bytes 2 (k)
            self.FileCommentLength = datas[32:34]
            k = struct.unpack("I", self.FileCommentLength + b"\x00"*2)[0]

            # Offset 34, Bytes 2 (0xffff for ZIP64)
            self.DiskNumberWhereFileStarts = datas[34:36]

            # Offset 36, Bytes 2
            self.InternalFileAttributes = datas[36:38]

            # Offset 38, Bytes 4
            self.ExternalFileAttributes = datas[38:42]

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
    def get_signature(self):
        # Signature.
        CentralDirectoryFileHeaderSignature = self.CentralDirectoryFileHeaderSignature

        if LC.DEBUG:
            print("\t- Central directory file header signature: " + \
                 f"{CentralDirectoryFileHeaderSignature}"
            )

        return CentralDirectoryFileHeaderSignature

    def get_version(self):
        # Version.
        VersionMadeBy = self.VersionMadeBy[::-1]
        version = ""
        try:
            version = LC.VERSION_MADE_BY[int(VersionMadeBy[0])]
        except Exception:
            pass

        if LC.DEBUG:
            print(f"\t- Version made by:\n\t    - {version} (upper byte)")
            print("\t    - " + \
                 f"{str(int(VersionMadeBy[1]))[0]}" + \
                  "." + \
                 f"{str(int(VersionMadeBy[1]))[1::]} " + \
                  "(lower byte)"
            )

        return VersionMadeBy

    def get_version_needed(self):
        # Version needed.
        VersionNeededToExtract = self.VersionNeededToExtract[::-1]

        if LC.DEBUG:
            print("\t- Version needed to extract: " + \
                 f"{self.VersionNeededToExtract}"
            )
            print("\t    - " + \
                 f"{str(int(VersionNeededToExtract[1]))[0]}" + \
                  "." + \
                 f"{str(int(VersionNeededToExtract[1]))[1]}"
            )

        return VersionNeededToExtract

    def get_flags(self):
        # Flags.
        GeneralPurposeBitFlag = []
        GeneralPurposeBitFlag.append(
            "{0:08b}".format(self.GeneralPurposeBitFlag[::-1][0])
        )
        GeneralPurposeBitFlag.append(
            "{0:08b}".format(self.GeneralPurposeBitFlag[::-1][1])
        )
        GeneralPurposeBitFlag = "".join(GeneralPurposeBitFlag)

        if LC.DEBUG:
            print(f"\t- General purpose bit flag: {GeneralPurposeBitFlag}")

        return GeneralPurposeBitFlag

    def get_compression_method(self):
        # Compression method.
        CompressionMethod = struct.unpack(
            "I",
            self.CompressionMethod + b"\x00"*2
        )[0]
        compression = ""
        try:
            compression = LC.COMPRESSION_METHOD[int(CompressionMethod)]
        except Exception:
            pass

        if LC.DEBUG:
            print(f"\t- Compression method: {compression}")

        return CompressionMethod

    def get_file_modification_time(self):
        # File modification time (stored in standard MS-DOS format).
        FileLastModificationTime = []
        FileLastModificationTime.append(
            "{0:08b}".format(self.FileLastModificationTime[::-1][0])
        )
        FileLastModificationTime.append(
            "{0:08b}".format(self.FileLastModificationTime[::-1][1])
        )
        FileLastModificationTime = "".join(FileLastModificationTime)

        hour = int(FileLastModificationTime[0:5], 2)
        minute = int(FileLastModificationTime[5:11], 2)
        seconde = int(FileLastModificationTime[11::], 2)
        time = f"{hour}:{minute}:{seconde}"

        if LC.DEBUG:
            print(f"\t- File last modification time: {time}")

        return FileLastModificationTime

    def get_file_modification_date(self):
        # File modification date (stored in standard MS-DOS format).
        FileLastModificationDate = []
        FileLastModificationDate.append(
            "{0:08b}".format(self.FileLastModificationDate[::-1][0])
        )
        FileLastModificationDate.append(
            "{0:08b}".format(self.FileLastModificationDate[::-1][1])
        )
        FileLastModificationDate = "".join(FileLastModificationDate)

        year = 2000 - 20 + int(FileLastModificationDate[0:7], 2)
        month = int(FileLastModificationDate[7:11], 2)
        day = int(FileLastModificationDate[11::], 2)
        date = f"{day}/{month}/{year}"

        if LC.DEBUG:
            print(f"\t- File last modification date: {date}")
        return FileLastModificationDate

    def getcrc32_checksum(self):
        # Crc-32 checksum.
        CRC32OfUncompressedData = struct.unpack(
            "I",
            self.CRC32OfUncompressedData
        )[0]

        if LC.DEBUG:
            print("\t- CRC32 of uncompressed data: " + \
                 f"{hex(CRC32OfUncompressedData)}"
            )

        return CRC32OfUncompressedData

    def get_compressed_size(self, remote_call=0):
        # Compressed size.
        CompressedSize = struct.unpack("I", self.CompressedSize)[0]

        if LC.DEBUG and not remote_call:
            print(f"\t- Compressed size: {hex(CompressedSize)} bytes")

        return CompressedSize

    def get_uncompressed_size(self):
        # Uncompressed size.
        UncompressedSize = struct.unpack("I", self.UncompressedSize)[0]

        if LC.DEBUG:
            print(f"\t- Uncompressed size: {hex(UncompressedSize)} bytes")

        return UncompressedSize

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

    def get_file_comment_length(self, remote_call=0):
        # File comment length.
        FileCommentLength = struct.unpack(
            "I",
            self.FileCommentLength + b"\x00"*2
        )[0]

        if LC.DEBUG and not remote_call:
            print(f"\t- File comment length: {FileCommentLength}")

        return FileCommentLength

    def get_disk_number_where_file_starts(self):
        # Disk # start.
        DiskNumberWhereFileStarts = struct.unpack(
            "I",
            self.DiskNumberWhereFileStarts + b"\x00"*2
        )[0]

        if LC.DEBUG:
            print("\t- Disk number where file starts: " + \
                 f"{DiskNumberWhereFileStarts}"
            )

        return DiskNumberWhereFileStarts

    def get_internal_file_attributes(self):
        # Internal attributes.
        if LC.DEBUG:
            print("\t- Internal file attributes: " + \
                 f"{self.InternalFileAttributes}"
            )

        return self.InternalFileAttributes

    def get_external_file_attributes(self):
        # External attributes.
        if LC.DEBUG:
            print("\t- External file attributes: " + \
                 f"{self.ExternalFileAttributes}"
            )

        return self.ExternalFileAttributes

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

    def get_extra_field(self):
        # Extra field.
        if LC.DEBUG:
            print(f"\t- Extra field: {self.ExtraField}")

        return self.ExtraField

    def get_file_comment(self):
        # File comment.
        FileComment = self.FileComment.decode()

        if LC.DEBUG:
            print(f"\t- File comment: {FileComment}")

        return FileComment