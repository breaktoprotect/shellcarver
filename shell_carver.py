#!/usr/bin/python

# Author: Jeremy S. @breaktoprotect
# Purpose:
# To calculate possible sub eax statements to help assist in carving code (or encoding)
# within memory based on a list of "allowed" bytes when during exploitation.
# msfvenom's -b usually works well, but in this case manual encoding is required.
# Remarks:
# Very raw code, some data type conversion logic may be lengthy - feel free to refine them.

import sys

# Global Variables
subEAX = '\\x2d'

# Known good character for exploitation/shell
''' 
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x31\x32\x33\x34\x35\x36\x37\x38"
"\x39\x3b\x3c\x3d\x3e\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c"
"\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d"
"\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e"
"\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f")
'''
allowed = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
    , 0x39, 0x3b, 0x3c, 0x3d, 0x3e, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c
    , 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d
    , 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e
    , 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f]


def toHex(val, nbits):
    return hex((val + (1 << nbits)) % (1 << nbits))


def toBits(val, nbits):
    return (val + (1 << nbits)) % (1 << nbits)

# Take in argument
# Expecting: e.g. \xde\xad\xbe\xef
# But when fed into argument, '\' will be omitted
rawInput = sys.argv[1]

# debug
print "rawInput: " + rawInput

rawInput = rawInput.replace('\\', '')
stringInput = rawInput.replace("x", '')

# debug
#print "replaced string: " + stringInput

neededByteArray = bytearray.fromhex(stringInput)

# debug
#print hex(neededByteArray[0]) + ", " + hex(neededByteArray[1])

byte1 = neededByteArray[3]
byte2 = neededByteArray[2]
byte3 = neededByteArray[1]
byte4 = neededByteArray[0]

code1 = byte4
code2 = byte4 + byte3 * 256
code3 = byte4 + byte3 * 256 + byte2 * 256 * 256
code4 = byte4 + byte3 * 256 + byte2 * 256 * 256 + byte1 * 256 * 256 * 256


# Reverse bytes and store to byte array
# withComments (boolean) true or false to return or not return ;comments
def getReversedHexString(hexValue, withComments):
    rawStringValue = str(hex(hexValue))

    # debug
    # print rawStringValue

    stringValue = rawStringValue.replace('0x', '')


    # Pad prefix 0
    if (len(stringValue) < 8):
        stringValue = '0' + stringValue

    # debug
    # print stringValue

    theBA = bytearray.fromhex(stringValue)

    # Reverse the bytearray
    reverseBA = theBA[::-1]

    # debug
    # for i in reverseBA:
    #	print hex(i)


    reverseString = ''.join('\\x' + '{:02x}'.format(x) for x in reverseBA)

    if withComments == True:
        return subEAX + reverseString + ' ;SUB EAX, ' + rawStringValue
    else:
        return subEAX + reverseString

# Progressive search algo
# Search starts on the first order
def searchOne():
    for hex1 in allowed:
        for hex2 in allowed:
            for hex3 in allowed:
                result = 0xFF + 1 - hex1 - hex2 - hex3
                if toBits(result, 8) == code1:
                    # print "Found 1st orderfor: " + str(hex(code1))
                    # print hex(hex1)
                    # print hex(hex2)
                    # print hex(hex3)

                    searchTwo(hex1, hex2, hex3)


def searchTwo(lsb1, lsb2, lsb3):
    for hex1 in allowed:
        for hex2 in allowed:
            for hex3 in allowed:
                order2byte1 = hex1 * 256 + lsb1
                order2byte2 = hex2 * 256 + lsb2
                order2byte3 = hex3 * 256 + lsb3
                result = 0xFFFF + 1 - order2byte1 - order2byte2 - order2byte3

                if toBits(result, 16) == code2:
                    # print "Found 2nd order match: " + str(hex(code2))
                    # print hex(hex1*256 + lsb1)
                    # print hex(hex2*256 + lsb2)
                    # print hex(hex3*256 + lsb3)
                    searchThree(hex1 * 256 + lsb1, hex2 * 256 + lsb2, hex3 * 256 + lsb3)


def searchThree(lsb1, lsb2, lsb3):
    for hex1 in allowed:
        for hex2 in allowed:
            for hex3 in allowed:
                order3byte1 = hex1 * 256 * 256 + lsb1
                order3byte2 = hex2 * 256 * 256 + lsb2
                order3byte3 = hex3 * 256 * 256 + lsb3
                result = 0xFFFFFF + 1 - order3byte1 - order3byte2 - order3byte3

                if toBits(result, 24) == code3:
                    # print "Found 3rd order match: " + str(hex(code3))
                    # print hex(order3byte1)
                    # print hex(order3byte2)
                    # print hex(order3byte3)
                    searchFour(order3byte1, order3byte2, order3byte3)


def searchFour(lsb1, lsb2, lsb3):
    for hex1 in allowed:
        for hex2 in allowed:
            for hex3 in allowed:
                order4byte1 = hex1 * 256 * 256 * 256 + lsb1
                order4byte2 = hex2 * 256 * 256 * 256 + lsb2
                order4byte3 = hex3 * 256 * 256 * 256 + lsb3
                result = 0xFFFFFFFF + 1 - order4byte1 - order4byte2 - order4byte3

                if toBits(result, 32) == code4:
                    print "Found full match: " + stringInput
                    #print hex(order4byte1)
                    #print hex(order4byte2)
                    #print hex(order4byte3)

                    print getReversedHexString(order4byte1, True)
                    print getReversedHexString(order4byte2, True)
                    print getReversedHexString(order4byte3, True)

                    print ''
                    print "Python style string:"
                    print '\"' + getReversedHexString(order4byte1, False) + getReversedHexString(order4byte2, False) + \
                          getReversedHexString(order4byte3, False) + '\"'

                    sys.exit(1)


searchOne()
