<?php
include 'Net/SFTP.php';
include 'Net/SFTP/Stream.php';
include 'Net/SCP.php';
include 'System/SSH/Agent.php';
include 'Crypt/RSA.php';

if (!function_exists('ssh2_connect')) {
    define('SSH2_TERM_UNIT_CHARS',  0);
    define('SSH2_TERM_UNIT_PIXELS', 1);
    define('SSH2_STREAM_STDIO', 0);
    define('SSH2_STREAM_STDERR', 1);
    define('SSH2_FINGERPRINT_MD5', 0);
    define('SSH2_FINGERPRINT_SHA1', 1);
    define('SSH2_FINGERPRINT_HEX', 0);
    define('SSH2_FINGERPRINT_RAW', 2);

    // ssh2.tunnel is not supported
    stream_wrapper_register('ssh2.sftp', 'Net_SFTP_Stream');

    // phpseclib doesn't let you do SSH2 initially and then "upgrade" to SFTP. if you want to do SFTP
    // you have specify SFTP from the onset. that said, just because phpseclib will initialize a
    // connection with SFTP doesn't mean you can't execute commands on it and do non-SFTP stuff on it
    function ssh2_connect($host, $port = 22, $methods = array(), $callbacks = array())
    {
        $session = new Net_SFTP($host, $port);
        $session->enableQuietMode();
        return $session;
    }

    function ssh2_auth_agent($session, $username)
    {
        $agent = new System_SSH_Agent();
        return $session->login($username, $agent);
    }

    // phpseclib doesn't support hostbased authentication
    function ssh2_auth_hostbased_file($session, $username, $hostname, $pubkeyfile, $privkeyfile, $passphrase = NULL, $local_username = NULL)
    {
        return false;
    }

    // phpseclib does not provide a mechanism to get supported authentication methods
    function ssh2_auth_none($session, $username)
    {
        if ($session->login($username)) {
            return true;
        }

        return array();
    }

    function ssh2_auth_password($session, $username, $password)
    {
        return $session->login($username, $password);
    }

    // only RSA keys are currently supported
    function ssh2_auth_pubkey_file($session, $username, $pubkeyfile, $privkeyfile, $passphrase = NULL)
    {
        $privkey = new Crypt_RSA();
        if (isset($passphrase)) {
            $privkey->setPassword($passphrase);
        }
        $privkey->loadKey(file_get_contents($privkeyfile));
        if ($privkey === false) {
            return false;
        }
        return $session->login($username, $privkey);
    }

    // phpseclib only supports one type of pty: vt100
    // environmental variables cannot be set through phpseclib
    // the only $width_height_type option supported is SSH2_TERM_UNIT_CHARS
    function ssh2_exec($session, $command, $pty = NULL, $env = NULL, $width = 80, $height = 25, $width_height_type = SSH2_TERM_UNIT_CHARS)
    {
        if (isset($pty)) {
            $session->enablePTY();
        }
        if ($width_height_type == SSH2_TERM_UNIT_CHARS) {
            $session->setWindowSize($width, $height);
        }
        $res = fopen('php://memory', 'w+');
        fputs($res, $session->exec($command));
        rewind($res);
        if (isset($pty)) {
            $session->disablePTY();
        }
        $session->setWindowSize(80, 24);
        return $res;
    }

    // phpseclib does not work in the same way libssh2 does. ssh2_exec returns
    // a resource stream that you can do fread on. phpseclib's Net_SSH2::exec()
    // returns a string. ssh2_exec() emulates libssh2 by dumping the string to
    // php://memory but it's only an emulation and you can't extract $session
    // from $channel. with phpseclib the way you'd get STDERR is by doing
    // $session->getStdError()
    function ssh2_fetch_stream($channel, $streamid)
    {
        return false;
    }

    function ssh2_fingerprint($session, $flags = 0)
    {
        $hostkey = substr($session->getServerPublicHostKey(), 8);
        $hostkey = ($flags & 1) ? sha1($hostkey) : md5($hostkey);
        return ($flags & 2) ? pack('H*', $hostkey) : strtoupper($hostkey);
    }

    function ssh2_methods_negotiated($session)
    {
        return array(
            'client_to_server' => array(
                'crypt' => $session->getEncryptionAlgorithmsClient2Server(),
                'comp' => $session->getCompressionAlgorithmsClient2Server(),
                'mac' => $session->getMACAlgorithmsClient2Server()),
            'server_to_client' => array(
                'crypt' => $session->getEncryptionAlgorithmsServer2Client(),
                'comp' => $session->getCompressionAlgorithmsServer2Client(),
                'mac' => $session->getMACAlgorithmsServer2Client())
        );
    }

    // not implemented in phpseclib
    function ssh2_publickey_add($pkey, $algoname, $blob, $overwrite = false, $attributes = array())
    {
        return false;
    }

    // not implemented in phpseclib
    function ssh2_publickey_init($session)
    {
        return false;
    }

    // not implemented in phpseclib
    function ssh2_publickey_list($pkey)
    {
        return false;
    }

    // not implemented in phpseclib
    function ssh2_publickey_remove($pkey, $algoname, $blob)
    {
        return false;
    }

    function ssh2_scp_recv($session, $remote_file, $local_file)
    {
        $scp = new Net_SCP($session);
        return $scp->get($remote_file, $local_file);
    }

    // phpseclib does not let you change the $create_mode
    function ssh2_scp_send($session, $local_file, $remote_file, $create_mode = 0644)
    {
        $scp = new Net_SCP($session);
        return $scp->put($remote_file, $local_file, NET_SCP_LOCAL_FILE);
    }

    function ssh2_sftp($session)
    {
        return $session;
    }

    function ssh2_sftp_chmod($sftp, $filename, $mode)
    {
        return $sftp->chmod($mode, $filename) !== false;
    }

    function ssh2_sftp_lstat($sftp, $path)
    {
        return $sftp->lstat($path);
    }

    function ssh2_sftp_stat($sftp, $path)
    {
        return $sftp->stat($path);
    }

    function ssh2_sftp_mkdir($sftp, $dirname, $mode = 0777, $recursive = false)
    {
        return $sftp->mkdir($dirname, $mode, $recursive);
    }

    function ssh2_sftp_readlink($sftp, $link)
    {
        return $sftp->readlink($link);
    }

    function ssh2_sftp_symlink($sftp, $target, $link)
    {
        return $sftp->symlink($target, $link);
    }

    function ssh2_sftp_unlink($sftp, $filename)
    {
        return $sftp->delete($filename, false);
    }

    // phpseclib supports this via $ssh->read() / $ssh->write() but it is not currently possible to make that
    // work with fread() / fwrite() in the way this function does. a yet to be written stream wrapper may do
    // the trick though.. hard to say.
    function ssh2_shell($session, $term_type = 'vanilla', $env = NULL, $width = 80, $height = 25, $width_height_type = 0)
    {
        return false;
    }

    // phpseclib doesn't currently support tunneling
    function ssh2_tunnel($session, $host, $port)
    {
        return false;
    }
}