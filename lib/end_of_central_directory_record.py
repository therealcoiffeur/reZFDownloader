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

            # Offset 4, Bytes 2 (0xffff for ZIP64)
            self.NumberOfThisDisk = datas[4:6]

            # Offset 6, Bytes 2 (0xffff for ZIP64)
            self.DiskWhereCentralDirectoryStarts = datas[6:8]

            # Offset 8, Bytes 2 (0xffff for ZIP64)
            self.NumberOfCentralDirectoryRecordsOnThisDisk = datas[8:10]

            # Offset 10, Bytes 2 (0xffff for ZIP64)
            self.TotalNumberOfCentralDirectoryRecords = datas[10:12]

            # Offset 12, Bytes 4 (0xffffffff for ZIP64)
            self.SizeOfCentralDirectory = datas[12:16]

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
    def get_signature(self):
        # Signature.
        EndOfCentralDirectorySignature = self.EndOfCentralDirectorySignature

        if LC.DEBUG:
            print("\t- End of central directory record signature: " + \
                 f"{EndOfCentralDirectorySignature}"
            )

        return EndOfCentralDirectorySignature

    def get_number_of_this_disk(self):
        # Disk Number.
        NumberOfThisDisk = struct.unpack(
            "I",
            self.NumberOfThisDisk + b"\x00"*2
        )[0]

        if LC.DEBUG:
            print(f"\t- Number of this disk: {NumberOfThisDisk}")

        return NumberOfThisDisk

    def get_disk_where_central_directory_starts(self):
        # Disk # w/cd.
        DiskWhereCentralDirectoryStarts = struct.unpack(
            "I",
            self.DiskWhereCentralDirectoryStarts + b"\x00"*2
        )[0]

        if LC.DEBUG:
            print("\t- Disk where central directory starts: " + \
                 f"{DiskWhereCentralDirectoryStarts}"
            )

        return DiskWhereCentralDirectoryStarts

    def get_number_of_central_directory_records_on_this_disk(self):
        # Disk entries.
        NumberOfCentralDirectoryRecordsOnThisDisk = struct.unpack(
            "I",
            self.NumberOfCentralDirectoryRecordsOnThisDisk + b"\x00"*2
        )[0]

        if LC.DEBUG:
            print("\t- Number of central directory records on this disk: " + \
                 f"{NumberOfCentralDirectoryRecordsOnThisDisk}"
            )

        return NumberOfCentralDirectoryRecordsOnThisDisk

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

    def get_size_of_central_directory(self):
        # Central directory size.
        SizeOfCentralDirectory = struct.unpack(
            "I",
            self.SizeOfCentralDirectory
        )[0]

        if LC.DEBUG:
            print("\t- Size of central directory: " + \
                 f"{SizeOfCentralDirectory} bytes"
            )

        return SizeOfCentralDirectory

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