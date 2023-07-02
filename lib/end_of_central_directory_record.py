import struct

import lib.constants as LC


class EndOfCentralDirectoryRecord:
    """
    The contents of the sctrucure are described by the following URL:
        - https://en.wikipedia.org/wiki/ZIP_(file_format)#End_of_central_directory_record_(EOCD)
    """

    # Offset 0, Bytes 4
    EndOfCentralDirectorySignature = b"\x50\x4b\x05\x06"

    # Total header length
    StructLength = 0

    def __init__(self, datas, zip_size):
        """
        This function parses the end of central directory record and calculates
        its total length.
        """

        self.ZipSize = zip_size

        try:
            if self.EndOfCentralDirectorySignature != datas[0:4]:
                raise Exception(
                    "[x] Bad signature for: End of central directory signature."
                )

            # Offset 10, Bytes 2 (0xffff for ZIP64)
            self.TotalNumberOfCentralDirectoryRecords = datas[10:12]

            # Offset 16, Bytes 4 (relative to start of archive) (0xffffffff for
            # ZIP64)
            self.OffsetOfStartOfCentralDirectory = datas[16:20]

            # Offset 20, Bytes 2 (n)
            self.CommentLength = datas[20:22]
            n = struct.unpack("I", self.CommentLength + b"\x00"*2)[0]

            # Offset 20, Bytes n
            self.Comment = datas[22:22+n]

        except Exception as error:
            print(error)
            exit(-1)

        self.StructLength = 22 + n

        if LC.DEBUG:
            print("[*] End of central directory record of size " + \
                 f"{hex(self.StructLength)} parsed."
            )

    """
    Thoses functions displays the information contained in the header.
    It is based on the information referenced by the following URL:
        - https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html
    """
    def get_total_number_of_central_directory_records(self, remote_call=0):
        # Total entries.
        TotalNumberOfCentralDirectoryRecords = struct.unpack(
            "I",
            self.TotalNumberOfCentralDirectoryRecords + b"\x00"*2
        )[0]

        if LC.DEBUG and not remote_call:
            print("\t- Total number of central directory records: " + \
                 f"{TotalNumberOfCentralDirectoryRecords}"
            )

        return TotalNumberOfCentralDirectoryRecords

    def get_offset_of_start_of_central_directory(self):
        # Offset of cd wrt to starting.
        OffsetOfStartOfCentralDirectory = struct.unpack(
            "I",
            self.OffsetOfStartOfCentralDirectory
        )[0]

        if LC.DEBUG:
            print("\t- Offset of start of central directory: " + \
                 f"{hex(OffsetOfStartOfCentralDirectory)}"
            )

        return OffsetOfStartOfCentralDirectory

    def get_relative_offset_of_start_of_central_directory(self):
        RelativeOffsetOfStartOfCentralDirectory = self.ZipSize - self.get_offset_of_start_of_central_directory()

        if LC.DEBUG:
            print("\t- Relative offset of start of central directory: " + \
                 f"{hex(RelativeOffsetOfStartOfCentralDirectory)} " + \
                  "(relative to the archive end)"
            )

        return RelativeOffsetOfStartOfCentralDirectory