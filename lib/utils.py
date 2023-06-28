import lib.constants as LC
import os


def clean():
    if os.path.exists(LC.JUNK_FILENAME):
        os.remove(LC.JUNK_FILENAME)