#!/usr/bin/python
# -*- coding: utf-8 -*-
#-----------------------------------------------------------------------------------------------
# Name:        hash2tie.py
# Purpose:     Send hash information to McAfee TIE
#
# Author:      Carlos Munoz (charly.munoz@gmail.com)
#                           (carlos.munoz@intel.com)
#
# Created:     06/06/2016
# Copyright:   (c) Carlos M 2016
#-----------------------------------------------------------------------------------------------
# Pendiente: Desarrollo de fihero ejecutable
#-----------------------------------------------------------------------------------------------
# Version: V.0.0.1
#-----------------------------------------------------------------------------------------------


# -----------------------------------------------------------------------------------------------
# PROCESO DE REPLICA EN GIT
#
# git status        --> Muestra el estado de sincronizacion de los distintos archivos
# git add file_name --> Añade un archivo a ser incorporado en la siguiente sincronizacion
# git commit -m "comentario" --> Comentario que queda registrado en bitbucket sobre el commit
# git push -u origin master  --> Sube el archivo al que previamente hemos hecho add a bitbucket
# -----------------------------------------------------------------------------------------------


import mcafee
import argparse
import base64
import csv
import sys
import hashlib
import os


def parseargs():
    '''
    Description: Function in charge of the CLI parameters
    Input:       No input
    Output:      Parsed arguments
    '''
    description = 'Set reputations to TIE Database'
    prog = 'hash2tie.py'
    usage = '\nhash2tie.py -ip ePO_IP_Address -port port -u Username -p Password -sha1 sha1_string ' \
                  '-md5 md5_string -value reputation_value -comment file_comment -name file_name'
    epilog = 'Carlos Munoz (carlos.munoz@intel.com)\n%(prog)s 1.0 (06/02/2016)'

    parser = argparse.ArgumentParser(epilog=epilog, usage=usage, prog=prog, description=description, formatter_class=argparse.RawTextHelpFormatter)

    auth_group = parser.add_argument_group("Authentication parameters")

    arg_help = "Ip address of ePolicy Orchestrator"
    auth_group.add_argument('-ip', required=True, action='store', dest='ipaddress', help=arg_help, metavar= "")

    arg_help = "ePolicy Orchestrator Listening port"
    auth_group.add_argument('-port', required=True, action='store', dest='port', help=arg_help, metavar="")

    arg_help = "Username for ePolicy Orchestrator"
    auth_group.add_argument('-u', required=True, action='store', dest='username', help=arg_help, metavar="")

    arg_help = "Password for ePolicy Orchestrator"
    auth_group.add_argument('-p', required=True, action='store', dest='password', help=arg_help, metavar="")

    arg_help = "SHA-1 string"
    parser.add_argument('-sha1', required=False, default = "", action='store', dest='sha1_string', help=arg_help,
                        metavar="")

    arg_help = "MD5 string"
    parser.add_argument('-md5', required=False, default = "", action='store', dest='md5_string', help=arg_help,
                        metavar="")

    arg_help = "File Comment"
    parser.add_argument('-comment', required=False, default = "", action='store', dest='file_comment', help=arg_help,
                        metavar="")

    arg_help = "File Name"
    parser.add_argument('-name', required=False, default = "", action='store', dest='file_name', help=arg_help,
                        metavar="")

    arg_help = "Reputation value - Default = 50\n"
    arg_help = arg_help + 'Possible values:\n'
    arg_help = arg_help + ' - 99 --> Known Trusted\n'
    arg_help = arg_help + ' - 85 --> Most Likely Trusted\n'
    arg_help = arg_help + ' - 70 --> Might be Trusted\n'
    arg_help = arg_help + ' - 50 --> Unknown\n'
    arg_help = arg_help + ' - 30 --> Might be Malicious\n'
    arg_help = arg_help + ' - 15 --> Most Likely Malicious\n'
    arg_help = arg_help + ' - 1  --> Known Malicious\n'
    arg_help = arg_help + ' - 0  --> Not set\n'

    parser.add_argument('-value', choices = [99, 85, 70, 50, 30, 15, 1, 0], type= int, default='50',
                        required=False, action='store', dest='value', help=arg_help, metavar="")

    arg_help = "File to import"
    parser.add_argument('-import', required=False, default="", action='store', dest='import_file', help=arg_help,
                        metavar="")

    arg_help = "Path to file or folder"
    parser.add_argument('-path', required=False, default="", action='store', dest='object_path', help=arg_help,
                        metavar="")

    parser.add_argument('--version', action='version', version='Carlos Munoz (carlos.munoz@intel.com)\n%(prog)s 1.0 (06/02/2016)')

    return parser.parse_args()


def base_64(hash_value):
    '''
    Description: Function in charge of the b64 coding of the hash values
    Input:       Digest value
    Output:      b64encode value
    '''
    codec_hash = base64.b64encode(hash_value)
    return codec_hash


def get_hash(filename):
    '''
    Description: Function in charge of getting the digest of the file
    Input:       path to file, for the digest to be calculated
    Output:      tuple with sha1 and md5 values
    '''
    # Note it is important to close and open the file again when calculating the digest, if I use the same
    # with open function the value that I obtain for the second operation (in this case the calculation of the md5)
    # wont be the correct one.
    with open(filename, 'rb') as myfile:
        sha1_value = hashlib.sha1(myfile.read()).hexdigest().upper()
    with open(filename, 'rb') as myfile:
        md5_value = hashlib.md5(myfile.read()).hexdigest().upper()
    return sha1_value, md5_value


def isfile(object_path):
    if os.path.lexists(object_path):
        if os.path.isfile(object_path):
            return True
        else:
            return False
    else:
        print "Error path doesn't exit"
        sys.exit(0)


def get_files(path_to_folder):
    '''
    Description: Function in charge of getting all the files in a folder
    Input:       path to folder
    Output:      list with the files on the folder
    '''
    list_of_files = []

    try:
        items = os.listdir(path_to_folder)
    except Exception as er:
        print 'Error getting the list of files: %s' % er
        sys.exit()

    for item in items:
        file_name = path_to_folder + os.sep + item
        if isfile(file_name):
            list_of_files.append(file_name)

    return list_of_files


def send_reputation(mc, sha1, md5, reputation, file_comment, file_name):
    '''
    Description: Function in charge of two things:
                    1.- Decode in hex the digest value
                    2.- Connect to ePO/Tie and send reputation
    Input:       epo connection object, sha1 digest, md5 digest, reputation, comment, and file name
    Output:      No output
    '''
    if sha1:
        sha1 = base_64(sha1.decode('hex'))

    if md5:
        md5 = base_64(md5.decode('hex'))

    repstring = '[{"sha1":"' + sha1 + '","md5":"' + md5 + '","reputation":"' + str(
        reputation) + '","comment":"' \
                + file_comment + '","name":"' + file_name + '"}]"'
    print 'String to be imported: \n%s' % repstring

    try:
        mc.tie.setReputations(repstring)
    except Exception as e:
        print 'Returned error: %s ' % e


def main():
    '''
    The main functiona allows different operations:
        1.- Manually import of hash
        2.- Import a list of hashes via csv file
        3.- Automatic calculation of the hash of a file and further submission
        4.- Automatic calculation of the hashed of a folder and further submission
    '''
    option = parseargs()
    ipaddress = option.ipaddress
    port = option.port
    username = option.username
    password = option.password

    path_to_file = option.import_file
    path_to_object = option.object_path

    mc = mcafee.client(ipaddress, port, username, password, 'https','json')

    if path_to_file:
        try:
            with open(path_to_file, 'rb') as csvfile:
                lines = csv.reader(csvfile)
                for line in lines:
                    try:
                        sha1 = line[0]
                        md5 = line[1]
                        reputation = line[2]
                        file_comment = line[3]
                        file_name = line[4]

                    except Exception as er:
                        print "Error - Format file error"
                        break

                    send_reputation(mc, sha1, md5, reputation, file_comment, file_name)

        except Exception as er:
            print 'Error opening file: %s' % er

    elif path_to_object:
        if isfile(path_to_object):
            sha1, md5 = get_hash(path_to_object)
            file_name = path_to_object.split(os.sep)[-1]
            file_comment = option.file_comment
            reputation = option.value

            send_reputation(mc, sha1, md5, reputation, file_comment, file_name)

        else:
            list_of_files = get_files(path_to_object)

            for unique_file in list_of_files:
                sha1, md5 = get_hash(unique_file)
                file_name = unique_file.split(os.sep)[-1]
                file_comment = option.file_comment
                reputation = option.value

                send_reputation(mc, sha1, md5, reputation, file_comment, file_name)

    else:
        sha1 = option.sha1_string
        md5 = option.md5_string
        reputation = option.value
        file_name = option.file_name
        file_comment = option.file_comment

        send_reputation(mc, sha1, md5, reputation, file_comment, file_name)


if __name__ == "__main__":
    main()

