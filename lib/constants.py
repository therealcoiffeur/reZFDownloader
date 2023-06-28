# This variable is used to switch to debug mode and increase verbosity.
DEBUG = 0

JUNK_FILENAME = "last_bytes"

# We assume that the end of central directory record is located
# in the last 100 bytes of the file.
END_OF_CENTRAL_DIRECTORY_RECORD_RANGE = 100

# This dictionary lists platforms by version number as referenced by the URL:
#     - https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html
VERSION_MADE_BY = {
    0: "MS-DOS and OS/2 (FAT / VFAT / FAT32 file systems)",
    1: "Amiga",
    2: "OpenVMS",
    3: "UNIX",
    4: "VM/CMS",
    5: "Atari ST",
    6: "OS/2 H.P.F.S.",
    7: "Macintosh",
    8: "Z-System",
    9: "CP/M",
    10: "Windows NTFS",
    11: "MVS (OS/390 - Z/OS)",
    12: "VSE",
    13: "Acorn Risc",
    14: "VFAT",
    15: "alternate MVS",
    16: "BeOS",
    17: "Tandem",
    18: "OS/400",
    19: "OS/X (Darwin)"
}

# This dictionary lists compression methods as referenced by the URL:
#     - https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html
COMPRESSION_METHOD = {
    0: "no compression",
    1: "shrunk",
    2: "reduced with compression factor 1",
    3: "reduced with compression factor 2",
    4: "reduced with compression factor 3",
    5: "reduced with compression factor 4",
    6: "imploded",
    7: "reserved",
    8: "deflated",
    9: "enhanced deflated",
    10: "PKWare DCL imploded",
    11: "reserved",
    12: "compressed using BZIP2",
    13: "reserved",
    14: "LZMA",
    15: "reserved",
    16: "reserved",
    17: "reserved",
    18: "compressed using IBM TERSE",
    19: "IBM LZ77 z",
    98: "PPMd version I, Rev 1"
}