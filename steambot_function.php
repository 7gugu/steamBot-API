<?php
set_time_limit(0);
class SteamBot {
 function toCommunityID($id) {
        if (preg_match('/^STEAM_/', $id)) {
            $parts = explode(':', $id);
            return bcadd(bcadd(bcmul($parts[2], '2'), '76561197960265728'), $parts[1]);
        } elseif (is_numeric($id) && strlen($id) < 16) {
            return bcadd($id, '76561197960265728');
        } else {
            return $id;
        }
    }
function send($token ='',$json,$accountid)
    {
        $url = 'https://steamcommunity.com/tradeoffer/new/send';
        $referer = 'https://steamcommunity.com/tradeoffer/new/?partner='.$accountid.'&token='.$token;
		
        $params = [
            'sessionid' =>$this->getSession(),//身份验证用
            'serverid' => '1',
            'partner' => $this->toCommunityID($accountid),//目标steamID
            'tradeoffermessage' => time(),//交易留言
            'json_tradeoffer' => $json,//交易传参,type:json
            'trade_offer_create_params' => (empty($token) ? "{}" : json_encode([
                'trade_offer_access_token' => $token//目标第三方交易Token
            ]))
        ];
		echo $json."<br>";
		//var_dump($params);
		echo "<br>";
        $response = $this->curl($url, $params,$referer);
        $json = json_decode($response, true);
        if (is_null($json)) {
            echo 'Empty response';
        } else {
            if (isset($json['tradeofferid'])) {
                return  $json['tradeofferid'];
            } else {
                echo $json['strError'];
        
            }
        }
    }
function getApiKey()
    {
        if (is_null(APIKEY)) {
            $url = 'https://steamcommunity.com/dev/apikey';
            $response = $this->curl($url);
            if (preg_match('/<h2>Access Denied<\/h2>/', $response)) {
                $apikey = '';
            } else if (preg_match('/<p>Key: (.*)<\/p>/', $response, $matches)) {
                $apikey = $matches[1];
            } else {
                $apikey = '';
            }	
        } else {
		$apikey=APIKEY;
		}
		return $apikey;
    }
 function getSession()
    {
        $response = $this->curl('https://steamcommunity.com/');
        $pattern = '/g_sessionID = (.*);/';
        preg_match($pattern, $response, $matches);
        if (!isset($matches[1])) {
            echo 'Unexpected response from Steam.';
        }
        $res = str_replace('"', '', $matches[1]);
        return $res;
       
    } 
	function getSteamid(){
        $response = $this->curl('https://steamcommunity.com/');
        $pattern = '/g_steamID = (.*);/';
        preg_match($pattern, $response, $matches);
        if (!isset($matches[1])) {
            echo 'Unexpected response from Steam.';
        }
        $steamid = str_replace('"', '', $matches[1]);
        if ($steamid == 'false') {
            $steamid = 0;
        }
		$res=$steamid;
        return $res;
    }
function curl($url, $post=null,$refer=null,$type="0",$header=null) { 
    $curl = curl_init();
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_HEADER, $header); 
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1); 
    curl_setopt ($curl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_setopt ($curl, CURLOPT_SSL_VERIFYHOST, 0);
	curl_setopt($curl, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:27.0) Gecko/20100101 Firefox/27.0');
	if($post!=null){
   @curl_setopt($curl, CURLOPT_POST, 1);
   @curl_setopt($curl, CURLOPT_POSTFIELDS, $post);
}
   if(isset($refer)){
            curl_setopt($curl, CURLOPT_REFERER, $refer);
        }  
	if($type=="1"){
	curl_setopt($curl, CURLOPT_COOKIEJAR, 'cookie.txt');
	}
	curl_setopt($curl, CURLOPT_COOKIEFILE, 'cookie.txt'); 
   $rs= curl_exec($curl);
    curl_close($curl);
return $rs;	
} 

	function login($username,$password,$twofa){
$post = array ('username' => $username); 
$url = "https://steamcommunity.com/login/getrsakey"; 
$json= json_decode($this->curl($url, $post),true);
include 'Crypt/RSA.php';
include 'Math/BigInteger.php';
$rsa = new Crypt_RSA();
$rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);
$key = [
            'modulus' => new Math_BigInteger($json['publickey_mod'], 16),
            'publicExponent' => new Math_BigInteger($json['publickey_exp'], 16)
        ];
 $rsa->loadKey($key, CRYPT_RSA_PUBLIC_FORMAT_RAW);
   $encryptedPassword = base64_encode($rsa->encrypt($password));
   $params = [
            'username' => $username,
            'password' => $encryptedPassword,
            'twofactorcode' => $twofa,
            'captchagid' => '-1',
            'captcha_text' => '',
            'emailsteamid' => '',
            'emailauth' => '',
            'rsatimestamp' => $json['timestamp'],
            'remember_login' => 'false'
        ];
        $loginResponse = $this->curl('https://steamcommunity.com/login/dologin/', $params,"1",1);
        $loginJson = json_decode($loginResponse, true);
		//var_dump($loginJson);
		return $loginJson;
}
function canceloffer($key,$tradeOfferId) {
		return apirequest($key,
			array(
				'method' => 'CancelTradeOffer/v1',
				'params' => array('tradeofferid' => $tradeOfferId),
			)
		);
	}
function declineoffer($key,$tradeOfferId) {
		 return apirequest($key,
			array(
				'method' => 'DeclineTradeOffer/v1',
				'param' => array('tradeofferid' => $tradeOfferId),
				'post' => 1
			)
		);
	}
function acceptoffer($option) {
	  	$form = array(
	  		'sessionid' => getSession(),
	  		'serverid' => 1,
	  		'tradeofferid' => $option,
			'partner' => '76561198218431108'
	  		);
	  	$referer = 'https://steamcommunity.com/tradeoffer/'.$option.'/';
	  	$response = $this->curl('https://steamcommunity.com/tradeoffer/'.$option.'/accept',$form,$referer);
	  	 return ($response);
	}
function apirequest($key,$option){
$url = 'https://api.steampowered.com/IEconService/'.$option['method'].'/?key='.$key.($option['post'] ? '' : ('&'.http_build_query($option['params'])));
$res=$this->curl($url,$option['param']);
return $res;
}
function getgamelist($nickname){
$content=file_get_contents('http://steamcommunity.com/id/$nickname/inventory/');
$content=preg_replace("/[\t\n\r]+/","",$content);
preg_match_all('/<option data-appid="([\S\s]*?)" value="([\S\s]*?)">([\S\s]*?)<\/option>/',$content,$rs);
return json_encode($rs[1]);
}
function getinventory($steamid,$gameid){
return file_get_contents('http://steamcommunity.com/inventory/'.$steamid.'/'.$gameid.'/2');
}
//计算并生成2步验证所需的密码
/*
	Created by Marlon Colhado
	admin@kazeta.com.br
*/
function intToByte($int)
	{
		return $int & (0xff);
	} 
	
	function startArrayToZero($array)
	{
		$mode = array();
		$intModeArray = 0;
		foreach($array as $test)
		{
			$mode[$intModeArray] = $this->intToByte($test);
			$intModeArray++;
		}
		return $mode;
	}
	
	function getSteamTime($localtime = false)
	{
		if($localtime) return time()+10;
		$data = array('steamid' => 0);
		$url = 'http://api.steampowered.com/ITwoFactorService/QueryTime/v0001';
		$postString = http_build_query($data, '', '&');
		$response = $this->curl($url,$postString);
		$response = json_decode($response);
		return $response->response->server_time;
	}
	
	function createTimeHash($time)
	{
		$time /= 30;
		$timeArray = array();
		for($i = 8; $i > 0; $i--)
		{
			$timeArray[$i - 1] = $this->intToByte($time);
			$time >>= 8;
		}
		$timeArray = array_reverse($timeArray);
		$newTimeArray = "";
		foreach($timeArray as $timeArrayValue)
		{
			$newTimeArray .= chr($timeArrayValue);
		}
		return $newTimeArray;
	}
	
	function createHMac($timeHash, $SharedSecretDecoded)
	{
		$hash = hash_hmac('sha1', $timeHash, $SharedSecretDecoded, false);
		$hmac = unpack('C*', pack('H*', $hash));
		return $hmac;
	}
	
	function GenerateSteamGuardCode($shared_secret)
	{
		if($shared_secret == "Shared Secret Key") return "You need to change the 'Shared Secret Key' to your Shared Secret!";
		$DecodedSharedSecret = base64_decode($shared_secret);
		$timeHash = $this->createTimeHash($this->getSteamTime(false)); // If you need Steam Time instead the local time, use 'false'. (Using local time the response time is less)
		$HMAC = $this->createHMac($timeHash, $DecodedSharedSecret);
		$HMAC = $this->startArrayToZero($HMAC);
		
		$b = $this->intToByte(($HMAC[19] & 0xF));
		$codePoint = ($HMAC[$b] & 0x7F) << 24 | ($HMAC[$b+1] & 0xFF) << 16 | ($HMAC[$b+2] & 0xFF) << 8 | ($HMAC[$b+3] & 0xFF);
		
		$SteamChars = "23456789BCDFGHJKMNPQRTVWXY";
		$code = "";
		for($i = 0; $i < 5; $i++)
		{
			$code = $code."".$SteamChars{floor($codePoint) % strlen($SteamChars)};
			$codePoint /= strlen($SteamChars);
		}
		return $code;
	}
	}
//DEMO PART
$steambot = new SteamBot;
$username = '';
//账户ID
$password = '';
//账户密码
$twofa = "";
//二步验证的密码,若果没有或不使用登录模块时,可不填
$key = "";
//API秘钥
$appid = "";
//游戏id[steam启动游戏的ID]
$assetid = "";
//物品id[通过解析网页中div标签上为item_x_sssss中的ssss部分的数值]
$token = "";
//第三方交易秘钥[第三方交易链接上token的那个值]
$partner = "";
//被交易者id[第三方交易链接上partner的那个值]
if (false) {
    //true为开启登录,false为关闭交易
    $res = $steambot->login($username, $password, $twofa);
    var_dump($res);
    if ($res['requires_twofactor'] == false) {
        if ($res['success'] == true) {
            echo "Login Success</br>";
            echo "Token:" . $res['transfer_parameters']['token'] . "<br>";
        } else {
            echo "Login Fail</br>";
        }
    }
}
echo "SteamId:" . $steambot->getSteamid() . "<br>";
echo "Session:" . $steambot->getSession() . "<br>";
echo "string:" . $steambot->toCommunityID('') . "<br>";
$json = json_encode(array('newversion' => false, 'version' => 2, 'me' => array("assets" => [], "currency" => [], "ready" => false), 'them' => array("assets" => [array("appid" => $appid, "contextid" => "2", "amount" => 1, "assetid" => $assetid)], "currency" => [], "ready" => false)), true);
//交易参数
$id = $steambot->send($token, $json, $partner);
//发起交易
echo $id . "</br>";
//以下的API都需要前往http://steamcommunity.com/dev/apikey申请WebApi才能用
// $rs=canceloffer($key,$id);//第一参数为秘钥,第二参数为交易ID
// $rs=declineoffer($key,$id);//第一参数为秘钥,第二参数为交易ID
// $rs=acceptoffer($id,$partner);//第一参数为交易ID,第二参数为被交易者ID
//=======
$username='';//账户ID
$password='';//账户密码
$twofa="";//二步验证的密码,若果没有或不使用登录模块时,可不填
$key="";//API秘钥
$appid="";//游戏id[steam启动游戏的ID]
$assetid="";//物品id[通过解析网页中div标签上为item_x_sssss中的ssss部分的数值]
$token="";//第三方交易秘钥[第三方交易链接上token的那个值]
$partner="";//被交易者id[第三方交易链接上partner的那个值]
if(false){//true为开启登录,false为关闭登陆
 $res=$steambot->login($username,$password,$twofa);
 var_dump($res);
 if($res['requires_twofactor']==false){
 if($res['success']==true){
		echo "Login Success</br>";
		echo "Token:".$res['transfer_parameters']['token']."<br>";
		}else{
		echo "Login Fail</br>";
		}
		}
		}
		echo "SteamId:".$steambot->getSteamid()."<br>";
		echo "Session:".$steambot->getSession()."<br>";
		echo "string:".$steambot->toCommunityID('')."<br>";
$json=json_encode(array(
		'newversion' => false,
		'version' => 2, 
		'me' => array("assets"=> [],"currency"=> [],"ready"=> false), 
		'them' => array("assets"=>[array("appid"=>$appid,"contextid"=>"2","amount"=>1,"assetid"=>$assetid)],"currency"=>[],"ready"=>false) 
		),true);//交易参数
		$id=$steambot->send($token,$json,$partner);//发起交易
		echo $id."</br>";
		//以下的API都需要前往http://steamcommunity.com/dev/apikey申请WebApi才能用
		// $rs=$steambot->canceloffer($key,$id);//第一参数为秘钥,第二参数为交易ID
		// $rs=$steambot->declineoffer($key,$id);//第一参数为秘钥,第二参数为交易ID
		// $rs=$steambot->acceptoffer($id,$partner);//第一参数为交易ID,第二参数为被交易者ID
		/*		
◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇
◇◇◇◇◆◆◆◆◆◆◆◆◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇
◇◇◇◇◆◆◆◆◆◆◆◆◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇
◇◇◇◇◇◇◇◇◆◆◆◇◇◇◇◇◇◇◇◇◆◆◆◆◆◆◆◇◇◇◇◇◇◇◆◆◆◇◇◆◆◆◇◇◇◇◇◇◇◇◆◆◆◆◆◆◆◇◇◇◇◇◇◇◆◆◆◇◇◆◆◆◇◇◇
◇◇◇◇◇◇◇◇◆◆◆◇◇◇◇◇◇◇◇◆◆◆◆◆◆◆◆◇◇◇◇◇◇◆◆◆◆◇◇◆◆◆◇◇◇◇◇◇◇◆◆◆◆◆◆◆◆◇◇◇◇◇◇◆◆◆◆◇◇◆◆◆◇◇◇
◇◇◇◇◇◇◇◆◆◆◇◇◇◇◇◇◇◇◇◆◆◆◆◆◆◆◆◇◇◇◇◇◇◆◆◆◆◇◇◆◆◆◇◇◇◇◇◇◇◆◆◆◆◆◆◆◆◇◇◇◇◇◇◆◆◆◆◇◇◆◆◆◇◇◇
◇◇◇◇◇◇◇◆◆◆◇◇◇◇◇◇◇◇◆◆◆◆◇◇◆◆◆◇◇◇◇◇◇◆◆◆◆◇◇◆◆◆◇◇◇◇◇◇◆◆◆◆◇◇◆◆◆◇◇◇◇◇◇◆◆◆◆◇◇◆◆◆◇◇◇
◇◇◇◇◇◇◆◆◆◆◇◇◇◇◇◇◇◇◆◆◆◆◇◇◆◆◆◇◇◇◇◇◇◆◆◆◆◇◇◆◆◆◇◇◇◇◇◇◆◆◆◆◇◇◆◆◆◇◇◇◇◇◇◆◆◆◆◇◇◆◆◆◇◇◇
◇◇◇◇◇◇◆◆◆◇◇◇◇◇◇◇◇◇◆◆◆◆◇◇◆◆◆◇◇◇◇◇◇◇◆◆◆◇◆◆◆◆◇◇◇◇◇◇◆◆◆◆◇◇◆◆◆◇◇◇◇◇◇◇◆◆◆◇◆◆◆◆◇◇◇
◇◇◇◇◇◆◆◆◆◇◇◇◇◇◇◇◇◇◇◆◆◆◆◆◆◆◆◇◇◇◇◇◇◇◆◆◆◆◆◆◆◆◇◇◇◇◇◇◇◆◆◆◆◆◆◆◆◇◇◇◇◇◇◇◆◆◆◆◆◆◆◆◇◇◇
◇◇◇◇◇◆◆◆◇◇◇◇◇◇◇◇◇◇◇◆◆◆◆◆◆◆◆◇◇◇◇◇◇◇◆◆◆◆◆◆◆◆◇◇◇◇◇◇◇◆◆◆◆◆◆◆◆◇◇◇◇◇◇◇◆◆◆◆◆◆◆◆◇◇◇
◇◇◇◇◇◆◆◆◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◆◆◆◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◆◆◆◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇
◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◆◆◆◆◆◆◆◆◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◆◆◆◆◆◆◆◆◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇
◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◆◆◆◆◆◆◆◆◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◆◆◆◆◆◆◆◆◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇
◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◆◆◆◆◆◆◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◆◆◆◆◆◆◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇◇
        */
		
		

