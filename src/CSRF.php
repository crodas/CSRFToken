<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 *  CSRF
 *
 *  Generates a CSRF token that expires after a certain amount of time (1 hour by default).
 *  
 *  The library generates includes information about the USER (mainly their IPs) with a site
 *  secret, making sure the hashes are unique per user and mathematically impossible to forge.
 *
 *  Each hash includes an expire Unix time, after that amount of time the HASH is no longer considered valid.
 *
 *  @category 
 *  @package CSRFToken
 *  @author Cesar Rodas <crodas@php.net>
 *  
 */
class CSRF
{
    protected static $secret;

    /**
     *  Encodes a given string with base64_encode but URL-friendly.
     */
    protected static function base64url_encode($base64url)
    {
        $base64 = base64_encode($base64url);
        $base64 = strtr($base64, '+/', '-_');
        return $base64;
    }

    /**
     *  Decodes a given string with base64_encode but URL-friendly.
     */
    protected static function base64url_decode($base64url)
    {
        $base64 = strtr($base64url, '-_', '+/');
        $plainText = base64_decode($base64);
        return ($plainText);
    }

    protected static function getUserIPs()
    {
        $ips = array();
        foreach (array('REMOTE_ADDR', 'HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP') as $ip) {
            if (!empty($_SERVER[$ip])) {
                $ips[] = $_SERVER[$ip];
            }
        }
        return implode(',', $ips);
    }

    protected static function randomBytes($len)
    {
        if (is_callable('random_bytes')) {
            $buf = random_bytes($len);
        } else if (is_callable('mcrypt_create_iv')) {
            $buf = mcrypt_create_iv($len, MCRYPT_DEV_URANDOM);
        } else if (is_callable('\sodium\randombytes_buf')) {
            $buf = \Sodium\randombytes_buf($len);
        } else if (is_callable('openssl_random_pseudo_bytes')) {
            $buf = openssl_random_pseudo_bytes($len);
        } else {
            $buf = "";
            $steps = $len % 7;
            for($i = 0; $i < $steps; ++$i) {
                $buf .= uniqid(true);
            }
            $buf = substr(hex2bin($buf), 0, $len);
        }

        return $buf;
    }

    public static function setSecret($secret)
    {
        self::$secret = $secret;
        return true;
    }

    public static function generate($extra = '', $ttl = 3600)
    {
        if (empty(self::$secret)) {
            throw new RuntimeException("Initialize the library first, calling " . __CLASS__ . '::setSecret($bytes)');
        }
        $length  = rand(30, 100);
        $random  = self::randomBytes($length);
        $expires = pack('N', time() + $ttl);
        $hashes  = self::$secret . $random . $expires . self::getUserIPs();
        $bytes   = chr($length) . $random // random data
            . $expires // when it expires
            . substr(hash('sha256', $hashes, true), 0, 10); // signature

        return self::base64url_encode($bytes);
    }

    public static function verify($code)
    {
        $binary  = self::base64url_decode($code);
        $len     = ord($binary[0]);
        $random  = substr($binary, 1, $len);
        $expires = substr($binary, $len+1, 4); 
        $ttl     = unpack('N', $expires);
        if ($ttl[1]  < time()) {
            return false;
        }
        $hashes  = self::$secret . $random . $expires . self::getUserIPs();
        $hash = hash('sha256', $hashes, true);
        return substr($hash, 0, 10) === substr($binary, -10);

    }
}
