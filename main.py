import argparse
import lib.constants as LC
import requests

from lib.central_directory_file_header import CentralDirectoryFileHeader
from lib.end_of_central_directory_record import EndOfCentralDirectoryRecord
from lib.utils import clean


def main(options):
    # Extract file name from options["url"].
    zip_name = options["url"].split("/")[-1]
    print(f"[*] ZIP name: {zip_name}")

    # Using an HTTP HEAD request, we retrieve the size of the ZIP file.
    zip_size = 0
    r = requests.head(options["url"])
    for key in r.headers:
        if key.lower() == "content-length":
            zip_size = int(r.headers[key])
    if zip_size == 0:
        print(f"[x] Can't find Content-Length HTTP header.")
        exit(-1)
    print(f"[*] ZIP size: {hex(zip_size)} bytes")


    # Then we search for the end of central directory record by downloading only
    # the last LC.END_OF_CENTRAL_DIRECTORY_RECORD_RANGE bytes.
    last_bytes = open(LC.JUNK_FILENAME, "bw")
    headers = {
        "Range": f"bytes={zip_size-LC.END_OF_CENTRAL_DIRECTORY_RECORD_RANGE}-{zip_size}"
    }
    with requests.get(url=options["url"], headers=headers, stream=True) as r:
        last_bytes.write(r.content)
    last_bytes.close()

    # Once the end of the file has been downloaded, we'll explore the written
    # file looking for a signature. The signature (0x504b0506) of interest is
    # that of structure end of central directory record.
    last_bytes = open(LC.JUNK_FILENAME, "br")
    signature = b"\x50\x4b\x05\x06"
    datas = last_bytes.read()
    if datas.find(signature) == -1:
        print(f"[x] Can't find end of central directory signature.")
        clean()
        exit(-1)
    index = datas.find(signature)
    eocdr_offset = zip_size - index
    if LC.DEBUG:
        print("[*] End of central directory record found at " + \
             f"offset: {hex(eocdr_offset)}"
        )
    eocdr = EndOfCentralDirectoryRecord(datas[index::], zip_size)

    # Thanks to the structure end of central directory record, we can calculate the
    # offset at which the structure central directory file header is located.
    cdfhs_offset = eocdr.get_relative_offset_of_start_of_central_directory()

    # We then retrieve only the bytes corresponding to this structure.
    last_bytes = open(LC.JUNK_FILENAME, "bw")
    headers = {
        "Range": f"bytes={zip_size-cdfhs_offset}-{zip_size-eocdr.StructLength}"
    }
    with requests.get(url=options["url"], headers=headers, stream=True) as r:
        last_bytes.write(r.content)
    last_bytes.close()

    # Once the end of the file has been downloaded, we'll explore the written
    # file looking for a signature. The signature (0x504b0102) of interest is
    # that of structure central directory file header.
    last_bytes = open(LC.JUNK_FILENAME, "br")
    signature = b"\x50\x4b\x01\x02"
    datas = last_bytes.read()
    cdfhs = []
    start = 0
    while datas[start::].find(signature) != -1:
        index = datas[start::].find(signature)
        cdfh = CentralDirectoryFileHeader(datas[start + index::])
        cdfhs.append(cdfh)
        start += index + cdfh.StructLength

    # We check that the number of central directory record headers identified is
    # equal to the number of files expected. If this is not the case, a problem
    # has occurred.
    if eocdr.get_total_number_of_central_directory_records(1) != len(cdfhs):
        print(f"[x] Can't find all central directory file header.")
        clean()
        exit(-1)

    # Once the central directory record headers have been extracted, we can
    # identify the files in the ZIP and retrieve their names.
    for cdfh in cdfhs:
        cdfh.get_file_name(0)

    # The user is then asked which file to download inside the ZIP file.
    filename = input("Which file do you want to download:\n> ")
    # We go through the structures to check that the filename entered by the
    # user is indeed a valdid filename. If not, a problem has occurred.
    current_cdfh = None
    for i in range(len(cdfhs)):
        if filename == cdfhs[i].get_file_name(1):
            current_cdfh = i
            break
    if current_cdfh == None:
        print(f"[x] \"{filename}\" does not exist in \"{zip_name}\".")
        clean()
        exit(-1)

    # Depending on the choice made by the user, a range is calculated in which
    # the local file header structure is supposed to be located. The range only
    # needs to be larger than the structure + the compressed file + the data
    # descriptor if it exists.
    start = cdfhs[current_cdfh].get_relative_offset_of_local_file_header(1)
    end = cdfhs[current_cdfh].get_relative_offset_of_local_file_header(1) + \
        30 + \
        cdfhs[current_cdfh].get_file_name_length(1) + \
        cdfhs[current_cdfh].get_extra_field_length(1) + \
        cdfhs[current_cdfh].get_compressed_size(1) + \
        12
    truncated_filename = filename.split("/")[-1]
    last_bytes = open(f"outputs/{truncated_filename}.zip", "bw")
    headers = {
        "Range": f"bytes={start}-{end}"
    }
    with requests.get(url=options["url"], headers=headers, stream=True) as r:
        last_bytes.write(r.content)
    last_bytes.close()

    clean()
    print(f"[i] Use command: \"7z x outputs/{truncated_filename}.zip\" to " + \
           "recover file."
    )
    print("[+] Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="This tool allows you to download the files inside a" + \
                    " ZIP file individually, thus saving bandwidth."
    )
    parser.add_argument(
        "url",
        default="http://127.0.0.1:8000/junk_file.zip",
        type=str
    )
    args = parser.parse_args()

    options = {}
    options["url"] = args.url

    main(options)
