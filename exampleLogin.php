<?php
require_once('./steambot_function.php');

$steambot = new SteamBot();

echo "Please enter your Steam Account Username:".PHP_EOL;
$stdin=fopen('php://stdin','r');
$username=trim(fgets($stdin));

echo "Please enter your Steam Account Password:".PHP_EOL;
$stdin=fopen('php://stdin','r');
$password=trim(fgets($stdin));

echo "Please enter your Steam Account Twofa(If not exist,leave the field blank):".PHP_EOL;
$stdin=fopen('php://stdin','r');
$twofa=trim(fgets($stdin));

$steambot->setProxyServer("127.0.0.1","1080","7gugu:12345");

$loginResponse=$steambot->login($username,$password,$twofa);

echo "Login Response: ".PHP_EOL;
var_dump($loginResponse);
echo "----------".PHP_EOL;




?>