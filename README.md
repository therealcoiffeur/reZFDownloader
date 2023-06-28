# reZFDownloader

Instead of downloading an entire ZIP, this tool lets you download only the files you're interested in. To do this, it parses structures present in the ZIP file:

- End of central directory record

![alt-text](https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip-images/end-of-central-directory-record.png)

- Central directory file header

![alt-text](https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip-images/central-file-header.png)

Structures are parsed in the following order:

- End of central directory record
    - Central directory file header

The project code isn't perfect, and strucutre parsing is based solely on 2 source of information.

## Development and experimentation

The file <span style="color:red">help/server/main.py</span> is supplied and allows you to setup the same lab I used to develop this tool. This tool has been tested on MacBook Pro M1.

## References

- [https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html](https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html)
- [https://en.wikipedia.org/wiki/ZIP_(file_format)](https://en.wikipedia.org/wiki/ZIP_(file_format))