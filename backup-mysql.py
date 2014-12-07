#!/usr/bin/env python
"""mysql-backup.py: Backups up all MySQL databases and sends them to Dropbox"""

##
# Copyright (C) 2012 Yudi Rosen (yrosen@wireandbyte.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
# and associated documentation files (the "Software"), to deal in the Software without restriction, 
# including without limitation the rights to use, copy, modify, merge, publish, distribute, 
# sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is 
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or 
# substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT 
# LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
##

import os
import re
import socket
import sys
import time

from logentries import LogentriesHandler
import logging
import time
import pyminizip

try:
    from dropbox import client, rest, session
except ImportError:
    print "Need Dropbox! (https://www.dropbox.com/developers/reference/sdk)"
    sys.exit(1)

try:
    from hurry.filesize import size
except ImportError:
    print "Need hurry.filesize! (http://pypi.python.org/pypi/hurry.filesize/)"
    sys.exit(1)

    
# - - - - - - - - - - CONFIGURATION OPTIONS! - - - - - - - - - - #

# MySQL login info:
MYSQL_ROOT_USER = 'root'
MYSQL_ROOT_PASS = 'my-root-passsword'
MYSQL_HOSTNAME  = 'localhost'
MYSQL_PORT      = 3306

# Dropbox (see documentation on how to do this):
DROPBOX_KEY     = 'dropbox-app-key'      # Dropbox API Key
DROPBOX_SECRET  = 'dropbox-app-secret'   # Dropbox API Secret
DROPBOX_ACCESS  = 'dropbox'              # Can be 'app_folder' or 'dropbox'
DROPBOX_FOLDER  = '/backups/mysql/'      # Folder to use in Dropbox - with trailing slash

# Other Options:
OPTION_COMPRESS   = True                  # compress the resulting SQL file before uploading?
COMPRESS_PASSWORD = 'password'            # password for compressed file
OPTION_USE_HOST   = True                  # Prepend the system hostname to the output filename?
OPTION_USE_DATETIME = False                # Use current datetime in the output filename?

LOGENTRIES_TOKEN  = 'logentries-token'

# - - - - - - - - - - END OF CONFIG OPTIONS! - - - - - - - - - - #

CURRENT_PATH = os.path.dirname(os.path.realpath(__file__))
# Dropbox token file - stores our oauth info for re-use:
DROPBOX_TOKEN_FILE = CURRENT_PATH + '/dropbox.tokens.txt'

# Directory to work in (include trailing slash)
# Will be created if it doesn't exist.
TMP_DIR = CURRENT_PATH + '/tmp/'


def get_timestamp():
    """Returns a MySQL-style timestamp from the current time"""
    return time.strftime("%Y-%m-%d %T") if OPTION_USE_DATETIME == True else ''


def do_mysql_backup(tmp_file):
    """Backs up the MySQL server (all DBs) to the specified file"""
    os.system("/usr/bin/mysqldump -u %s -p\"%s\" -h %s -P %d --opt --all-databases > %s" % (MYSQL_ROOT_USER, MYSQL_ROOT_PASS, MYSQL_HOSTNAME, MYSQL_PORT, TMP_DIR + tmp_file))

def connect_to_dropbox():
    """Authorizes the app with Dropbox. Returns False if we can't connect"""

    # No I will not care about scope.
    global dropbox_session
    global dropbox_client
    global dropbox_info

    token_key = ''

    dropbox_session = session.DropboxSession(DROPBOX_KEY, DROPBOX_SECRET, DROPBOX_ACCESS)

    # Do we have access tokens?
    while len(token_key) == 0:
        try:
            token_file = open(DROPBOX_TOKEN_FILE, 'r')
        except IOError:
            # Re-build the file and try again, maybe?
            get_new_dropbox_tokens()
            token_file = open(DROPBOX_TOKEN_FILE, 'r')
        
        token_key, token_secret = token_file.read().split('|')
        token_file.close()

    # Hopefully now we have token_key and token_secret...
    dropbox_session.set_token(token_key, token_secret)
    dropbox_client = client.DropboxClient(dropbox_session)

    # Double-check that we've logged in
    try:
        dropbox_info = dropbox_client.account_info()
    except:
        # If we're at this point, someone probably deleted this app in their DB 
        # account, but didn't delete the tokens file. Clear everything and try again.
        os.unlink(DROPBOX_TOKEN_FILE)
        token_key = ''
        connect_to_dropbox()    # Who doesn't love a little recursion?


def get_new_dropbox_tokens():
    """Helps the user auth this app with Dropbox, and stores the tokens in a file"""

    request_token   = dropbox_session.obtain_request_token()

    print "Looks like you haven't allowed this app to access your Dropbox account yet!"
    print "Please visit: " + dropbox_session.build_authorize_url(request_token)
    print "and press the 'allow' button, and then press Enter here."
    raw_input()

    access_token = dropbox_session.obtain_access_token(request_token)

    token_file = open(DROPBOX_TOKEN_FILE, 'w')
    token_file.write("%s|%s" % (access_token.key, access_token.secret))
    token_file.close()


def main():
    # logentries config
    log = logging.getLogger('logentries')
    log.setLevel(logging.INFO)
    handler = LogentriesHandler(LOGENTRIES_TOKEN)
    log.addHandler(handler)

    # Make tmp dir if needed...
    if not os.path.exists(TMP_DIR):
	    os.makedirs(TMP_DIR)

    # Are we prepending hostname to filename?
    hostname = (socket.gethostname() + '-') if(OPTION_USE_HOST == True) else ''

    MYSQL_TMP_FILE = re.sub('[\\/:\*\?"<>\|\ ]', '-', hostname + 'backup' + get_timestamp()) + '.sql'

    # Got final filename, continue on...
    log.info("Connecting to Dropbox...")
    connect_to_dropbox()

    log.info("Connected to Dropbox as " + dropbox_info['display_name'])

    log.info("Creating MySQL backup, please wait...")
    do_mysql_backup(MYSQL_TMP_FILE)

    log.info("Backup done. File is " + size(os.path.getsize(TMP_DIR + MYSQL_TMP_FILE)))

    if OPTION_COMPRESS == True:
        log.info("compressing enabled - compressing file...")

        compression_level = 9 # 1-9
        srcFile = TMP_DIR + MYSQL_TMP_FILE
        dstFile = srcFile + '.zip'
        pyminizip.compress(srcFile, dstFile, COMPRESS_PASSWORD, compression_level)

        # Delete uncompressed TMP_FILE, set to .zip
        os.unlink(srcFile)
        MYSQL_TMP_FILE = MYSQL_TMP_FILE + '.zip'

        # Tell the user how big the compressed file is:
        log.info("File compressed. New filesize: " + size(os.path.getsize(TMP_DIR + MYSQL_TMP_FILE)))


    log.info("Uploading backup to Dropbox...")
    tmp_file = open(TMP_DIR + MYSQL_TMP_FILE)

    result = dropbox_client.put_file(DROPBOX_FOLDER + MYSQL_TMP_FILE, tmp_file, True)
    # TODO: Check for dropbox.rest.ErrorResponse

    log.info("File uploaded as '" + result['path'] + "', size: " + result['size'])

    log.info("Cleaning up...")
    os.unlink(TMP_DIR + MYSQL_TMP_FILE)

    log.info("Backup completed")

    # need some time to ensure logentries
    time.sleep(10)

if __name__ == "__main__":
    main()
