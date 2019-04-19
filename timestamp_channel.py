#!/usr/bin/env python

"""
Author: Jason Stratman
Storage covert channel steganography file timestamp implementation.
"""

import math
import random
import os
import sys
import traceback
import time
import datetime

# Used for argument management when running the program.
import argparse

# Used for correction of minor errors.
import reedsolo

# Used to check file types when determining suitable
# files for data storage.
from stat import S_ISREG, ST_MODE

# Used to alter the creation date time value.
# Can only alter up to a millisecond precision.
import pywintypes
import win32file
import win32con


def arguments():
    description = """
    Covert channel steganography tool to send and receive
    data using file timestamps.

    Send data:
    python timestamp_channel.py -p <storage_path> -i <input_path>

    Receive data:
    python timestamp_channel.py -p <storage_path> -o <output_path>
    """
    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-p',
                        dest='storage_path',
                        type=str,
                        default=None,
                        help='Path at which data will be stored in timestamps.')
    parser.add_argument('-i',
                        dest='input_path',
                        type=str,
                        default=None,
                        help='Data file to be stored.')
    parser.add_argument('-o',
                        dest='output_path',
                        type=str,
                        default=None,
                        help='Where to place retrieved data.')

    args = parser.parse_args()

    if args.storage_path is None:
        print('[!] Please specify a storage_path.')
        parser.print_help()
        exit(0)
    if args.input_path is None and args.output_path is None:
        print('[!] Please specify an input or output path.')
        parser.print_help()
        exit(0)

    return args


def chunk_list(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def change_file_creation_time(fname, newtime):
    wintime = pywintypes.Time(newtime).replace(microsecond=newtime.microsecond)
    winfile = win32file.CreateFile(
        fname, win32con.GENERIC_WRITE,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
        None, win32con.OPEN_EXISTING,
        win32con.FILE_ATTRIBUTE_NORMAL, None)

    win32file.SetFileTime(winfile, wintime, None, None)

    winfile.close()


def floor_thousands(value):
    return math.floor(value / 1000) * 1000


def floor_hundred_thousands(value):
    return math.floor(value / 100000) * 100000


def floor_billionths(value):
    return math.floor(value / 1000000000) * 1000000000


def prepend_zeroes(num_string, n):
    while len(num_string) < n:
        num_string = '0' + num_string
    return num_string


def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def int_from_bytes(xbytes):
    return int.from_bytes(xbytes, 'big')


def int_byte_size(digits):
    return int(int('9'*digits).bit_length() / 8)


DIGITS_FOR_INDEX = 4
STORABLE_DIGITS_PER_FILE = 17 - DIGITS_FOR_INDEX
STORABLE_BYTES_PER_FILE = int_byte_size(STORABLE_DIGITS_PER_FILE - 1)
# Bytes out of 255 that should be used for error correction
ERROR_CORRECTING_BYTES = 50


class CovertChannel:

    @staticmethod
    def hide(storage_path: str, input_path: str):
        """
        Used to hide data at the specified input path in the specified
        storage path directory of files.
        """
        # Read file data
        file_data = CovertChannel.file_to_binary(input_path)
        file_and_path = file_data + b'.' + \
            str.encode(input_path.split('.')[-1])

        # Apply error correcting code
        encoded_data = reedsolo.RSCodec(
            ERROR_CORRECTING_BYTES).encode(file_and_path)

        while len(encoded_data) % STORABLE_BYTES_PER_FILE != 0:
            encoded_data = bytearray(b'\x00') + encoded_data

        index = 0
        int_str_chunks = []

        print('Able to store {} bytes per file'.format(STORABLE_BYTES_PER_FILE))
        print('Max able to store in {} files is {} bytes'.format(
            '9'*DIGITS_FOR_INDEX, STORABLE_BYTES_PER_FILE*(int('9'*DIGITS_FOR_INDEX))))

        data_chunks = list(chunk_list(encoded_data, STORABLE_BYTES_PER_FILE))

        remaining_chunks = len(data_chunks)

        if remaining_chunks > int('9'*DIGITS_FOR_INDEX) - 1:
            raise Exception('Can only store up to {} files worth of data, need {}'.format(
                int('9'*DIGITS_FOR_INDEX) - 1, remaining_chunks))

        for c in data_chunks:
            s = str(int_from_bytes(c))

            if len(s) > STORABLE_DIGITS_PER_FILE:
                raise Exception('Data too long: {}'.format(len(s)))

            if index == 0 or index == int('9'*DIGITS_FOR_INDEX) - 1:
                # Index chunk indicates the number of files
                index_string = CovertChannel.prepend_chunk(
                    str(0), str(remaining_chunks))
                int_str_chunks.append(index_string)
                index = 1
                remaining_chunks -= (int('9'*DIGITS_FOR_INDEX) - 1)

            data_string = CovertChannel.prepend_chunk(str(index), s)
            int_str_chunks.append(data_string)
            index += 1

        # Get the sorted list of files
        files = CovertChannel.get_file_list(storage_path)

        print('Data storage will require {} files'.format(
            len(int_str_chunks)))

        if (len(files) < len(int_str_chunks)):
            raise Exception(
                'Not enough files to store data. Need {}, found {}'.format(len(int_str_chunks), len(files)))

         # Set all files microseconds time to 999999
        for file in files:
            path = file[1]
            ctimestamp = file[0]
            change_file_creation_time(
                path, ctimestamp.replace(microsecond=999999))

            atime_ns = file[2]
            mtime_ns = file[3]
            # ms through hundred ns places (7 values)
            new_atime_ns = floor_billionths(
                atime_ns) + (9999999 * 100)
            # ms through hundred ns places (7 values)
            new_mtime_ns = floor_billionths(
                mtime_ns) + (9999999 * 100)
            os.utime(path, ns=(new_atime_ns, new_mtime_ns))

        # Choose random offset to start at
        offset = random.randint(
            0, len(files) - len(int_str_chunks))
        del files[:offset]

        files_count = 0

        for c in int_str_chunks:
            file = files.pop(0)

            ctime = file[0]
            atime_ns = file[2]
            mtime_ns = file[3]
            path = file[1]

            # ms places (3 values)
            new_ctime = int(c[0:3]) * 1000
            # ms through hundred ns places (7 values)
            new_atime_ns = floor_billionths(
                atime_ns) + (int(c[3:10]) * 100)
            # ms through hundred ns places (7 values)
            new_mtime_ns = floor_billionths(
                mtime_ns) + (int(c[10:17]) * 100)

            change_file_creation_time(
                path, ctime.replace(microsecond=new_ctime))

            os.utime(path, ns=(new_atime_ns, new_mtime_ns))

            files_count += 1

        print('Successfully embedded data in {} files'.format(files_count))

    @staticmethod
    def prepend_chunk(index_val: str, data_val: str):
        # Pad index to be 4 digits long
        index = prepend_zeroes(index_val, DIGITS_FOR_INDEX)
        # Pad data to be 13 digits long
        data = prepend_zeroes(data_val, STORABLE_DIGITS_PER_FILE)
        return index + data

    @staticmethod
    def extract(storage_path: str, output_path: str):
        """
        Used to extract data from the specified directory at the storage
        path, and will write the extracted data to a file at the specified
        output path.
        """
        encoded_int_strings = CovertChannel.get_encoded_int_string(
            storage_path)

        found_start = False
        next_index = 0
        encoded_data = bytearray()
        files_remaining = 0
        files_captured = 0

        for string in sorted(encoded_int_strings):
            index = int(string[0:DIGITS_FOR_INDEX])

            if index != 0:
                if not found_start:
                    continue
                elif files_remaining > 0:

                    files_remaining -= 1
                    files_captured += 1

                    byte = bytearray(int_to_bytes(
                        int(string[DIGITS_FOR_INDEX:])))

                    newbyte = bytes(byte)
                    while len(newbyte) < STORABLE_BYTES_PER_FILE:
                        newbyte = b'\x00' + bytes(newbyte)

                    encoded_data += bytearray(newbyte)
                    next_index += 1
                else:
                    break
            else:
                found_start = True
                files_remaining = int(string[DIGITS_FOR_INDEX:])
                next_index = 1
                files_captured += 1

        print('Found data for {} files'.format(files_captured))

        # Trim leading zero bytes
        while bytes(encoded_data)[0] == 0:
            encoded_data = encoded_data[1:]

        # Decode the message from ECC message
        decoded_message = reedsolo.RSCodec(
            ERROR_CORRECTING_BYTES).decode(encoded_data)

        # Retrieve original file extension
        message_and_data = decoded_message.rsplit(b'.', 1)
        message = message_and_data[0]
        ext = message_and_data[1]

        to_save = open(output_path + '.' + ext.decode("utf-8"), 'wb')
        to_save.write(message)

    @staticmethod
    def pad_byte(byte):
        while len(byte) < STORABLE_BYTES_PER_FILE:
            byte = bytearray(b'\x00') + byte

        return byte

    @staticmethod
    def get_encoded_int_string(storage_path: str):
        encoded_int_strings = []

        for file in CovertChannel.get_file_list(storage_path):

            ctimestamp = file[0]
            atime_ns = file[2]
            mtime_ns = file[3]

            ctime_str_val = prepend_zeroes(
                str(int(ctimestamp.microsecond / 1000)), 3)
            atime_str_val = prepend_zeroes(
                str(int((atime_ns % 1000000000) / 100)), 7)
            mtime_str_val = prepend_zeroes(
                str(int((mtime_ns % 1000000000) / 100)), 7)

            int_string_val = ctime_str_val + atime_str_val + mtime_str_val

            encoded_int_strings.append(int_string_val)

        return encoded_int_strings

    @staticmethod
    def file_to_binary(file_path: str):
        try:
            with open(file_path, 'rb') as file:
                text = file.read()
            file.close()
        except Exception as e:
            raise Exception('Could not open file: {}'.format(str(e)))

        return text

    @staticmethod
    def get_file_list(file_path: str):
        entries = (os.path.join(file_path, fn) for fn in os.listdir(file_path))
        entries = ((os.stat(path), path) for path in entries)

        entries = ((datetime.datetime.fromtimestamp(stat.st_ctime), path, stat.st_atime_ns, stat.st_mtime_ns)
                   for stat, path in entries if S_ISREG(stat[ST_MODE]))

        return sorted(entries)


if __name__ == '__main__':
    try:
        args = arguments()
        storage_path = args.storage_path
        input_path = args.input_path
        output_path = args.output_path

        if input_path is not None:
            CovertChannel.hide(storage_path, input_path)
        elif output_path is not None:
            CovertChannel.extract(storage_path, output_path)
        else:
            raise Exception(
                'Invalid arguments provided; please specify input or output path')
    except Exception as e:
        traceback.print_exc()
        print(e)
