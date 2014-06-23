libssh2-compatibility-layer
===========================

Let's say your application has calls to [PHP's ssh2_* functions](http://php.net/ssh2) but you don't have libssh2 installed. With libssh2-compatibility-layer all you need to do is include phpseclib.php and (assuming you have phpseclib installed in the include_path) and they should work without issue!

An example follows:

```php
<?php
include('phpseclib.php');

$ssh = ssh2_connect('www.domain.tld');
echo ssh2_fingerprint($ssh);
```
