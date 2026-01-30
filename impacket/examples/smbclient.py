# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Mini shell using some of the SMB funcionality of the library
#
# Author:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   SMB DCE/RPC
#
from __future__ import division
from __future__ import print_function
from io import BytesIO
import sys
import time
import cmd
import os
import ntpath

from six import PY2
from impacket.dcerpc.v5 import samr, transport, srvs
from impacket.dcerpc.v5.dtypes import NULL
from impacket import LOG
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError, \
    FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE
from impacket.smb3structs import FILE_DIRECTORY_FILE, FILE_LIST_DIRECTORY

import charset_normalizer as chardet
import re


class DFSConnectionManager:
    """Manages multiple SMB connections for DFS navigation"""

    def __init__(self, primary_connection, username, password, domain, lmhash, nthash, aesKey=None, doKerberos=False, kdcHost=None):
        self.connections = {}  # server -> (SMBConnection, tree_id, share_name)
        self.primary = primary_connection
        self.primary_host = primary_connection.getRemoteHost()
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.aesKey = aesKey
        self.doKerberos = doKerberos
        self.kdcHost = kdcHost

    def get_connection(self, server):
        """Get or create connection to a server"""
        server_lower = server.lower()
        if server_lower == self.primary_host.lower():
            return self.primary
        if server_lower in self.connections:
            return self.connections[server_lower][0]

        # Create new connection
        conn = SMBConnection(server, server)
        if self.doKerberos:
            conn.kerberosLogin(self.username, self.password, self.domain,
                             self.lmhash, self.nthash, self.aesKey, self.kdcHost)
        else:
            conn.login(self.username, self.password, self.domain, self.lmhash, self.nthash)

        self.connections[server_lower] = (conn, None, None)
        return conn

    def parse_unc_path(self, unc_path):
        """
        Parse a UNC path into (server, share, path) components.

        :param unc_path: UNC path like \\\\server\\share\\path
        :return: (server, share, path) tuple
        """
        # Remove leading backslashes and normalize
        path = unc_path.lstrip('\\')
        parts = path.split('\\')

        if len(parts) < 2:
            return None, None, None

        server = parts[0]
        share = parts[1]
        remaining_path = '\\' + '\\'.join(parts[2:]) if len(parts) > 2 else '\\'

        return server, share, remaining_path

    def resolve_dfs_path(self, dfs_path, max_depth=5, _visited=None):
        """
        Resolve a DFS path to actual (server, share, path).
        Handles recursive DFS referrals with loop detection.

        :param dfs_path: Full DFS path
        :param max_depth: Maximum recursion depth for nested DFS referrals
        :param _visited: Internal set of visited paths (for loop detection)
        :return: (server, share, path) tuple or None
        """
        if _visited is None:
            _visited = set()

        # Normalize path for comparison
        normalized_path = dfs_path.lower().rstrip('\\')

        # Check for loops and depth limit
        if normalized_path in _visited:
            LOG.warning("DFS loop detected at: %s" % dfs_path)
            return None
        if max_depth <= 0:
            LOG.warning("DFS max depth exceeded at: %s" % dfs_path)
            return None

        _visited.add(normalized_path)

        try:
            referral = self.primary.getDfsReferral(dfs_path)
            if referral and referral.get('referrals'):
                target = referral['referrals'][0]['network_address']
                server, share, path = self.parse_unc_path(target)

                if server is None:
                    return None

                # Check if target is also a DFS link (nested DFS)
                # Try to get referral for the target to see if it's another DFS link
                try:
                    conn = self.get_connection(server)
                    target_full_path = "\\\\%s\\%s%s" % (server, share, path if path != '\\' else '')
                    nested_referral = conn.getDfsReferral(target_full_path)
                    if nested_referral and nested_referral.get('referrals'):
                        # It's a nested DFS link, resolve recursively
                        nested_target = nested_referral['referrals'][0]['network_address']
                        return self.resolve_dfs_path(nested_target, max_depth - 1, _visited)
                except:
                    # Not a DFS link or error - return the current target
                    pass

                return server, share, path
        except Exception as e:
            LOG.debug("DFS referral failed for %s: %s" % (dfs_path, str(e)))
        return None

    def close_all(self):
        """Close all managed connections"""
        for server, (conn, tid, share) in self.connections.items():
            try:
                if tid:
                    conn.disconnectTree(tid)
                conn.close()
            except:
                pass
        self.connections.clear()


class MiniImpacketShell(cmd.Cmd):
    def __init__(self, smbClient, tcpShell=None, outputfile=None):
        #If the tcpShell parameter is passed (used in ntlmrelayx),
        # all input and output is redirected to a tcp socket
        # instead of to stdin / stdout
        if tcpShell is not None:
            cmd.Cmd.__init__(self, stdin=tcpShell.stdin, stdout=tcpShell.stdout)
            sys.stdout = tcpShell.stdout
            sys.stdin = tcpShell.stdin
            sys.stderr = tcpShell.stdout
            self.use_rawinput = False
            self.shell = tcpShell
        else:
            cmd.Cmd.__init__(self)
            self.shell = None

        self.prompt = '# '
        self.smb = smbClient
        self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey, self.TGT, self.TGS = smbClient.getCredentials()
        self.tid = None
        self.intro = 'Type help for list of commands'
        self.pwd = ''
        self.share = None
        self.loggedIn = True
        self.last_output = None
        self.completion = []
        self.outputfile = outputfile
        # DFS support
        self.dfs_follow = False
        self.dfs_manager = None
        self._dfs_referral_cache = {}  # Cache for DFS referrals

    def emptyline(self):
        pass

    def precmd(self,line):
        # switch to unicode
        if self.outputfile is not None:
            f = open(self.outputfile, 'a')
            f.write('> ' + line + "\n")
            f.close()
        if PY2:
            return line.decode('utf-8')
        return line

    def onecmd(self,s):
        retVal = False
        try:
           retVal = cmd.Cmd.onecmd(self,s)
        except Exception as e:
           LOG.error(e)
           LOG.debug('Exception info', exc_info=True)

        return retVal

    def do_exit(self,line):
        if self.shell is not None:
            self.shell.close()
        return True

    def do_shell(self, line):
        output = os.popen(line).read()
        print(output)
        self.last_output = output

    def do_help(self,line):
        print("""
 open {host,port=445} - opens a SMB connection against the target host/port
 reconnect - reconnect connection, useful for broken pipes & interrupted sessions
 login {domain/username,passwd} - logs into the current SMB connection, no parameters for NULL connection. If no password specified, it'll be prompted
 kerberos_login {domain/username,passwd} - logs into the current SMB connection using Kerberos. If no password specified, it'll be prompted. Use the DNS resolvable domain name
 login_hash {domain/username,lmhash:nthash} - logs into the current SMB connection using the password hashes
 logoff - logs off
 shares - list available shares
 use {sharename} - connect to an specific share
 cd {path} - changes the current directory to {path}
 lcd {path} - changes the current local directory to {path}
 pwd - shows current remote directory
 password - changes the user password, the new password will be prompted for input
 ls {wildcard} - lists all the files in the current directory
 lls {dirname} - lists all the files on the local filesystem.
 tree {filepath} - recursively lists all files in folder and sub folders
 rm {file} - removes the selected file
 mkdir {dirname} - creates the directory under the current path
 rmdir {dirname} - removes the directory under the current path
 put {filename} - uploads the filename into the current path
 get {filename} - downloads the filename from the current path
 mget {mask} - downloads all files from the current directory matching the provided mask
 cat {filename} - reads the filename from the current path
 mount {target,path} - creates a mount point from {path} to {target} (admin required)
 umount {path} - removes the mount point at {path} without deleting the directory (admin required)
 list_snapshots {path} - lists the vss snapshots for the specified path
 dfs_info {path} - shows DFS referral information for the specified path
 info - returns NetrServerInfo main results
 who - returns the sessions currently connected at the target host (admin required)
 close - closes the current SMB Session
 exit - terminates the server process (and this session)

""")

    def do_password(self, line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        from getpass import getpass
        newPassword = getpass("New Password:")
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename = r'\samr', smb_connection = self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        samr.hSamrUnicodeChangePasswordUser2(dce, '\x00', self.username, self.password, newPassword, self.lmhash, self.nthash)
        self.password = newPassword
        self.lmhash = None
        self.nthash = None

    def do_open(self,line):
        l = line.split(' ')
        port = 445
        if len(l) > 0:
           host = l[0]
        if len(l) > 1:
           port = int(l[1])


        if port == 139:
            self.smb = SMBConnection('*SMBSERVER', host, sess_port=port)
        else:
            self.smb = SMBConnection(host, host, sess_port=port)

        dialect = self.smb.getDialect()
        if dialect == SMB_DIALECT:
            LOG.info("SMBv1 dialect used")
        elif dialect == SMB2_DIALECT_002:
            LOG.info("SMBv2.0 dialect used")
        elif dialect == SMB2_DIALECT_21:
            LOG.info("SMBv2.1 dialect used")
        else:
            LOG.info("SMBv3.0 dialect used")

        self.share = None
        self.tid = None
        self.pwd = ''
        self.loggedIn = False
        self.password = None
        self.lmhash = None
        self.nthash = None
        self.username = None

    def do_reconnect(self, line):
        if self.smb:
            self.smb.reconnect()
        else:
            LOG.warning("Not reconnecting a closed connection.")
    
    def do_login(self,line):
        if self.smb is None:
            LOG.error("No connection open")
            return
        l = line.split(' ')
        username = ''
        password = ''
        domain = ''
        if len(l) > 0:
           username = l[0]
        if len(l) > 1:
           password = l[1]

        if username.find('/') > 0:
           domain, username = username.split('/')

        if password == '' and username != '':
            from getpass import getpass
            password = getpass("Password:")

        self.smb.login(username, password, domain=domain)
        self.password = password
        self.username = username

        if self.smb.isGuestSession() > 0:
            LOG.info("GUEST Session Granted")
        else:
            LOG.info("USER Session Granted")
        self.loggedIn = True

    def do_kerberos_login(self,line):
        if self.smb is None:
            LOG.error("No connection open")
            return
        l = line.split(' ')
        username = ''
        password = ''
        domain = ''
        if len(l) > 0:
           username = l[0]
        if len(l) > 1:
           password = l[1]

        if username.find('/') > 0:
           domain, username = username.split('/')

        if domain == '':
            LOG.error("Domain must be specified for Kerberos login")
            return

        if password == '' and username != '':
            from getpass import getpass
            password = getpass("Password:")

        self.smb.kerberosLogin(username, password, domain=domain)
        self.password = password
        self.username = username

        if self.smb.isGuestSession() > 0:
            LOG.info("GUEST Session Granted")
        else:
            LOG.info("USER Session Granted")
        self.loggedIn = True

    def do_login_hash(self,line):
        if self.smb is None:
            LOG.error("No connection open")
            return
        l = line.split(' ')
        domain = ''
        if len(l) > 0:
           username = l[0]
        if len(l) > 1:
           hashes = l[1]
        else:
           LOG.error("Hashes needed. Format is lmhash:nthash")
           return

        if username.find('/') > 0:
           domain, username = username.split('/')

        lmhash, nthash = hashes.split(':')

        self.smb.login(username, '', domain,lmhash=lmhash, nthash=nthash)
        self.username = username
        self.lmhash = lmhash
        self.nthash = nthash

        if self.smb.isGuestSession() > 0:
            LOG.info("GUEST Session Granted")
        else:
            LOG.info("USER Session Granted")
        self.loggedIn = True

    def do_logoff(self, line):
        if self.smb is None:
            LOG.error("No connection open")
            return
        self.smb.logoff()
        del self.smb
        self.share = None
        self.smb = None
        self.tid = None
        self.pwd = ''
        self.loggedIn = False
        self.password = None
        self.lmhash = None
        self.nthash = None
        self.username = None

    def do_info(self, line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename = r'\srvsvc', smb_connection = self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrServerGetInfo(dce, 102)

        print("Version Major: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_major'])
        print("Version Minor: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_minor'])
        print("Server Name: %s" % resp['InfoStruct']['ServerInfo102']['sv102_name'])
        print("Server Comment: %s" % resp['InfoStruct']['ServerInfo102']['sv102_comment'])
        print("Server UserPath: %s" % resp['InfoStruct']['ServerInfo102']['sv102_userpath'])
        print("Simultaneous Users: %d" % resp['InfoStruct']['ServerInfo102']['sv102_users'])

    def do_who(self, line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename = r'\srvsvc', smb_connection = self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)

        for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
            print("host: %15s, user: %5s, active: %5d, idle: %5d" % (
            session['sesi10_cname'][:-1], session['sesi10_username'][:-1], session['sesi10_time'],
            session['sesi10_idle_time']))

    def do_shares(self, line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        resp = self.smb.listShares()
        if self.outputfile is not None:
            f = open(self.outputfile, 'a')
        for i in range(len(resp)):
            if self.outputfile:
                f.write(resp[i]['shi1_netname'][:-1] + '\n')
            print(resp[i]['shi1_netname'][:-1])
        if self.outputfile:
            f.close()

    def do_use(self,line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        self.share = line
        self.tid = self.smb.connectTree(line)
        self.pwd = '\\'
        self.do_ls('', False)

    def complete_cd(self, text, line, begidx, endidx):
        return self.complete_get(text, line, begidx, endidx, include = 2)

    def do_cd(self, line):
        if self.tid is None:
            LOG.error("No share selected")
            return
        p = line.replace('/','\\')
        oldpwd = self.pwd
        old_smb = self.smb
        old_tid = self.tid
        old_share = self.share

        if p[0] == '\\':
           self.pwd = line
        else:
           self.pwd = ntpath.join(self.pwd, line)
        self.pwd = ntpath.normpath(self.pwd)

        # Check if target is DFS link and dfs_follow is enabled
        if self.dfs_follow and self.dfs_manager:
            try:
                # Check if the target directory is a DFS link
                target = self._get_dfs_target(line)
                if target:
                    # Parse the DFS target path
                    server, share, path = self.dfs_manager.parse_unc_path(target)
                    if server and share:
                        LOG.info("Following DFS link to %s" % target)
                        # Get connection to target server
                        new_conn = self.dfs_manager.get_connection(server)
                        new_tid = new_conn.connectTree(share)
                        # Successfully connected, update state
                        self.smb = new_conn
                        self.tid = new_tid
                        self.share = share
                        self.pwd = path if path else '\\'
                        return
            except Exception as e:
                LOG.debug("DFS follow failed: %s" % str(e))
                # Continue with normal cd

        # Let's try to open the directory to see if it's valid
        try:
            fid = self.smb.openFile(self.tid, self.pwd, creationOption = FILE_DIRECTORY_FILE, desiredAccess = FILE_READ_DATA |
                                   FILE_LIST_DIRECTORY, shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE )
            self.smb.closeFile(self.tid,fid)
        except SessionError:
            self.pwd = oldpwd
            self.smb = old_smb
            self.tid = old_tid
            self.share = old_share
            raise

    def do_lcd(self, s):
        print(s)
        if s == '':
           print(os.getcwd())
        else:
           os.chdir(s)

    def do_pwd(self,line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        print(self.pwd.replace("\\","/"))
        if self.outputfile is not None:        
            f = open(self.outputfile, 'a')
            f.write(self.pwd.replace("\\","/"))
            f.close()

    def do_ls(self, wildcard, display = True):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        if self.tid is None:
            LOG.error("No share selected")
            return
        if wildcard == '':
           pwd = ntpath.join(self.pwd,'*')
        else:
           pwd = ntpath.join(self.pwd, wildcard)
        self.completion = []
        pwd = pwd.replace('/','\\')
        pwd = ntpath.normpath(pwd)
        if self.outputfile is not None:
            of = open(self.outputfile, 'a')
        for f in self.smb.listPath(self.share, pwd):
            if display is True:
                # Determine file type character
                if f.is_directory():
                    type_char = 'd'
                elif f.is_dfs_link():
                    type_char = 'l'
                elif f.is_reparse_point():
                    type_char = 'j'  # junction/symlink
                else:
                    type_char = '-'

                line = "%crw-rw-rw- %10d  %s %s" % (
                    type_char, f.get_filesize(), time.ctime(float(f.get_mtime_epoch())),
                    f.get_longname())

                # For DFS links, show target path
                if f.is_dfs_link():
                    target = self._get_dfs_target(f.get_longname())
                    if target:
                        line += " -> %s" % target
                    else:
                        line += " [DFS]"

                if self.outputfile:
                    of.write(line + "\n")
                print(line)
            self.completion.append((f.get_longname(), f.is_directory()))
        if self.outputfile:
            of.close()

    def _get_dfs_target(self, filename):
        """Get DFS target path for a file. Returns None if not available."""
        try:
            # Build full DFS path
            full_path = '\\\\' + self.smb.getRemoteHost() + '\\' + self.share
            file_path = ntpath.join(self.pwd, filename)
            if file_path.startswith('\\'):
                full_path += file_path
            else:
                full_path += '\\' + file_path

            # Check cache first
            if full_path in self._dfs_referral_cache:
                cached = self._dfs_referral_cache[full_path]
                if cached['referrals']:
                    return cached['referrals'][0]['network_address']
                return None

            # Get DFS referral
            referral = self.smb.getDfsReferral(full_path)
            self._dfs_referral_cache[full_path] = referral

            if referral and referral['referrals']:
                return referral['referrals'][0]['network_address']
        except Exception:
            pass
        return None
    
    def do_lls(self, currentDir):
        if currentDir == "":
            currentDir = "./"
        else:
            pass
        for LINE in os.listdir(currentDir):
            print(LINE)

    def do_listFiles(self, share, ip):
        retList = []
        retFiles = []
        retInt = 0
        try:                
            for LINE in self.smb.listPath(self.share, ip):
                if(LINE.get_longname() == "." or LINE.get_longname() == ".."):
                    pass
                else:
                    retInt = retInt + 1
                    print(ip.strip("*").replace("//","/") + LINE.get_longname())
                    if(LINE.is_directory()):
                        retval = ip.strip("*").replace("//","/") + LINE.get_longname()
                        retList.append(retval)
                    else:
                        retval = ip.strip("*").replace("//","/") + LINE.get_longname()
                        retFiles.append(retval)
        except:
            pass
        return retList,retFiles,retInt

    def do_tree(self, filepath):
        folderList = []
        retList = []
        totalFilesRead = 0
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        if self.tid is None:
            LOG.error("No share selected")
            return

        filepath = filepath.replace("\\", "/")
        if not filepath.startswith("/"):
            filepath = self.pwd.replace("\\", "/")  + "/" + filepath
        if(not filepath.endswith("/*")):
            filepath = filepath + "/*"
        filepath = os.path.abspath(filepath).replace("//","/")

        for LINE in self.smb.listPath(self.share, filepath):
            if(LINE.is_directory()):
                if(LINE.get_longname() == "." or LINE.get_longname() == ".."):
                    pass
                else:
                    totalFilesRead = totalFilesRead + 1 
                    folderList.append(filepath.strip("*") + LINE.get_longname())
            else:
                print(filepath.strip("*") + LINE.get_longname())
        for ITEM in folderList:
            ITEM = ITEM + "/*"
            try: 
                retList, retFiles, retInt = self.do_listFiles(self.share,ITEM)
                for q in retList:
                    folderList.append(q)
                totalFilesRead = totalFilesRead + retInt
            except:
                pass
        print("Finished - " + str(totalFilesRead) + " files and folders")

    def do_rm(self, filename):
        if self.tid is None:
            LOG.error("No share selected")
            return
        f = ntpath.join(self.pwd, filename)
        file = f.replace('/','\\')
        self.smb.deleteFile(self.share, file)

    def do_mkdir(self, path):
        if self.tid is None:
            LOG.error("No share selected")
            return
        p = ntpath.join(self.pwd, path)
        pathname = p.replace('/','\\')
        self.smb.createDirectory(self.share,pathname)

    def do_rmdir(self, path):
        if self.tid is None:
            LOG.error("No share selected")
            return
        p = ntpath.join(self.pwd, path)
        pathname = p.replace('/','\\')
        self.smb.deleteDirectory(self.share, pathname)

    def do_put(self, pathname):
        if self.tid is None:
            LOG.error("No share selected")
            return
        src_path = pathname
        dst_name = os.path.basename(src_path)

        fh = open(pathname, 'rb')
        f = ntpath.join(self.pwd,dst_name)
        finalpath = f.replace('/','\\')
        self.smb.putFile(self.share, finalpath, fh.read)
        fh.close()

    def complete_get(self, text, line, begidx, endidx, include = 1):
        # include means
        # 1 just files
        # 2 just directories
        p = line.replace('/','\\')
        if p.find('\\') < 0:
            items = []
            if include == 1:
                mask = 0
            else:
                mask = 0x010
            for i in self.completion:
                if i[1] == mask:
                    items.append(i[0])
            if text:
                return  [
                    item for item in items
                    if item.upper().startswith(text.upper())
                ]
            else:
                return items

    def do_mget(self, mask):
        if mask == '':
            LOG.error("A mask must be provided")
            return
        if self.tid is None:
            LOG.error("No share selected")
            return
        self.do_ls(mask,display=False)
        if len(self.completion) == 0:
            LOG.error("No files found matching the provided mask")
            return 
        for file_tuple in self.completion:
            if file_tuple[1] == 0:
                filename = file_tuple[0]
                filename = filename.replace('/', '\\')
                fh = open(ntpath.basename(filename), 'wb')
                pathname = ntpath.join(self.pwd, filename)
                try:
                    LOG.info("Downloading %s" % (filename))
                    self.smb.getFileEx(self.share, pathname, fh.write)
                except:
                    fh.close()
                    os.remove(filename)
                    raise
                fh.close()

    def do_get(self, filename):
        if self.tid is None:
            LOG.error("No share selected")
            return
        filename = filename.replace('/','\\')
        fh = open(ntpath.basename(filename),'wb')
        pathname = ntpath.join(self.pwd,filename)
        try:
            self.smb.getFileEx(self.share, pathname, fh.write)
        except:
            fh.close()
            os.remove(filename)
            raise
        fh.close()

    def complete_cat(self, text, line, begidx, endidx):
        return self.complete_get(text, line, begidx, endidx, include=1)
    
    def do_cat(self, filename):
        if self.tid is None:
            LOG.error("No share selected")
            return
        filename = filename.replace('/','\\')
        fh = BytesIO()
        pathname = ntpath.join(self.pwd,filename)
        try:
            self.smb.getFileEx(self.share, pathname, fh.write)
        except:
            raise
        output = fh.getvalue()
        encoding = chardet.detect(output)["encoding"]
        error_msg = "[-] Output cannot be correctly decoded, are you sure the text is readable ?"
        if self.outputfile is not None:
            f = open(self.outputfile, 'a')
        if encoding:
            try:
                if self.outputfile:
                    f.write(output.decode(encoding) + '\n')
                    f.close()
                print(output.decode(encoding))
            except:
                if self.outputfile:
                    f.write(error_msg + '\n')
                    f.close()
                print(error_msg)
            finally:
                fh.close()
        else:
            if self.outputfile:
                f.write(error_msg + '\n')
                f.close()
            print(error_msg)
            fh.close()

    def do_close(self, line):
        self.do_logoff(line)

    def do_list_snapshots(self, line):
        l = line.split(' ')
        if len(l) > 0:
            pathName= l[0].replace('/','\\')

        # Relative or absolute path?
        if pathName.startswith('\\') is not True:
            pathName = ntpath.join(self.pwd, pathName)

        snapshotList = self.smb.listSnapshots(self.tid, pathName)

        if not snapshotList:
            print("No snapshots found")
            return

        for timestamp in snapshotList:
            print(timestamp)

    def do_dfs_info(self, line):
        """Show DFS referral information for a path"""
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return

        path = line.strip() if line.strip() else ''

        # Build full DFS path
        full_path = '\\\\' + self.smb.getRemoteHost() + '\\' + (self.share or '')
        if path:
            path = path.replace('/', '\\')
            if not path.startswith('\\'):
                path = ntpath.join(self.pwd, path)
            full_path += path
        elif self.pwd:
            full_path += self.pwd

        try:
            referral = self.smb.getDfsReferral(full_path)
            print("DFS Referral for: %s" % full_path)
            print("Path consumed: %d characters" % referral.get('path_consumed', 0))
            print("")
            if referral.get('referrals'):
                print("Targets:")
                for i, ref in enumerate(referral['referrals']):
                    server_type = ref.get('server_type', 'unknown')
                    ttl = ref.get('ttl', 0)
                    network_addr = ref.get('network_address', 'N/A')
                    print("  [%d] %s (%s, TTL=%ds)" % (i+1, network_addr, server_type, ttl))
            else:
                print("No referrals found (path may not be a DFS link)")
        except Exception as e:
            LOG.error("Failed to get DFS referral: %s" % str(e))

    def do_mount(self, line):
        l = line.split(' ')
        if len(l) > 1:
            target  = l[0].replace('/','\\')
            pathName= l[1].replace('/','\\')

        # Relative or absolute path?
        if pathName.startswith('\\') is not True:
            pathName = ntpath.join(self.pwd, pathName)

        self.smb.createMountPoint(self.tid, pathName, target)

    def do_umount(self, mountpoint):
        mountpoint = mountpoint.replace('/','\\')

        # Relative or absolute path?
        if mountpoint.startswith('\\') is not True:
            mountpoint = ntpath.join(self.pwd, mountpoint)

        mountPath = ntpath.join(self.pwd, mountpoint)

        self.smb.removeMountPoint(self.tid, mountPath)

    def do_EOF(self, line):
        print('Bye!\n')
        return True
