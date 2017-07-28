<?php
//==============================可用函数============================================
set_time_limit(0);
function toCommunityID($id){//格式化steamid[返回String]
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
    {//发送交易请求[token:卖家的trade_url上的token,json:交易参数,accountid:卖家的steamID][返回JSON]
        $url = 'https://steamcommunity.com/tradeoffer/new/send';
        $referer = 'https://steamcommunity.com/tradeoffer/new/?partner='.$accountid.'&token='.$token;
		
        $params = [
            'sessionid' =>getSession(),//身份验证用
            'serverid' => '1',
            'partner' => toCommunityID($accountid),//目标steamID
            'tradeoffermessage' => time(),//交易留言
            'json_tradeoffer' => $json,//交易传参,type:json
            'trade_offer_create_params' => (empty($token) ? "{}" : json_encode([
                'trade_offer_access_token' => $token//目标第三方交易Token
            ]))
        ];
        $response = curl($url, $params,$referer);
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
    {//获取API秘钥[返回String]
            $url = 'https://steamcommunity.com/dev/apikey';
            $response = curl($url);
            if (preg_match('/<h2>Access Denied<\/h2>/', $response)) {
                $apikey = '';
            } else if (preg_match('/<p>Key: (.*)<\/p>/', $response, $matches)) {
                $apikey = $matches[1];
            } else {
                $apikey = '';
            }	
        return $apikey;
    }
function getSession()
    {//获取sessionID[返回String]
        $response = curl('http://steamcommunity.com/');
        $pattern = '/g_sessionID = (.*);/';
        preg_match($pattern, $response, $matches);
        if (!isset($matches[1])) {
            echo 'Unexpected response from Steam.';
        }
        $res = str_replace('"', '', $matches[1]);
        return $res;
       
    } 
function getSteamid()
{//获取steamid[返回String]
        $response = curl('http://steamcommunity.com/');
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
//curl封装  
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

	function login($username,$password,$twofa){//模拟登录,获取cookie[username:用户名,password:密码,twofa:二步验证码(无则不需填写)][返回JSON]
$post = array ('username' => $username); 
$url = "https://steamcommunity.com/login/getrsakey"; 
$json= json_decode(curl($url, $post),true);
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
        $loginResponse = curl('https://steamcommunity.com/login/dologin/', $params,"1",1);
        $loginJson = json_decode($loginResponse, true);
        $file=file_get_contents("cookie.txt");
	    if(substr_count($file,'steamcommunity.com	FALSE	/	FALSE	0	sessionid')==0){
        file_put_contents("cookie.txt","steamcommunity.com	FALSE	/	FALSE	0	sessionid\t".getSession()."\r\n", FILE_APPEND);
		}
		return $loginJson;
}
function getoffer($key,$tradeOfferId) {//获取交易细节[key:API秘钥,tradeOfferId:交易ID][返回JSON]
        return apirequest($key,
            array(
                'method' => 'GetTradeOffer/v1',
                'params' => array('tradeofferid' => $tradeOfferId,'language'=>'CN'),
            )
        );
    }
function canceloffer($key,$tradeOfferId) {//取消交易[key:API秘钥,tradeOfferId:交易ID][返回BOOLEAN]
        return apirequest($key,
            array(
                'method' => 'CancelTradeOffer/v1',
                'params' => array('tradeofferid' => $tradeOfferId),
            )
        );
    }
function declineoffer($key,$tradeOfferId) {//拒绝交易[key:API秘钥,tradeOfferId:交易ID][返回BOOLEAN]
         return apirequest($key,
            array(
                'method' => 'DeclineTradeOffer/v1',
                'param' => array('tradeofferid' => $tradeOfferId),
                'post' => 1
            )
        );
    }
function acceptoffer($option,$partner) {//接受交易[option:交易ID,partner:交易者ID(发起这次交易的那个)][返回BOOLEAN]
      	$form = array(
      		'sessionid' => getSession(),
      		'serverid' => 1,
      		'tradeofferid' => $option,
            'partner' => $partner
      		);
      	$referer = 'https://steamcommunity.com/tradeoffer/'.$option.'/';
      	$response = curl('https://steamcommunity.com/tradeoffer/'.$option.'/accept',$form,$referer);
      	 print_r($response);
    }
function apirequest($key,$option){//发起API类请求[key:API秘钥,option:请求参数][返回JSON]
$url = 'https://api.steampowered.com/IEconService/'.$option['method'].'/?key='.$key.($option['post'] ? '' : ('&'.http_build_query($option['params'])));
$res=curl($url,$option['param']);
return $res;
}
function getgamelist($nickname){//获取用户的游戏列表[nickname:玩家昵称][返回JSON]
$content=file_get_contents('http://steamcommunity.com/id/$nickname/inventory/');
$content=preg_replace("/[\t\n\r]+/","",$content);
preg_match_all('/<option data-appid="([\S\s]*?)" value="([\S\s]*?)">([\S\s]*?)<\/option>/',$content,$rs);
return json_encode($rs[1]);
}
function getinventory($steamid,$gameid){//获取用户库存[steamid:用户64位ID,gameid:游戏ID][返回JSON]
return file_get_contents('http://steamcommunity.com/inventory/'.$steamid.'/'.$gameid.'/2');
}
//DEMO PART
$username='';//账户ID
$password='';//账户密码
$twofa="";//二步验证的密码,若果没有或不使用登录模块时,可不填
$key="";//API秘钥
$appid="";//游戏id[steam启动游戏的ID]
$assetid="";//物品id[通过解析网页中div标签上为item_x_sssss中的ssss部分的数值]
$token="";//第三方交易秘钥[第三方交易链接上token的那个值]
$partner="";//被交易者id[第三方交易链接上partner的那个值]
if(false){//true为开启登录,false为关闭登陆
 $res=login($username,$password,$twofa);
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
		echo "SteamId:".getSteamid()."<br>";
		echo "Session:".getSession()."<br>";
		echo "string:".toCommunityID('')."<br>";
$json=json_encode(array(
		'newversion' => false,
		'version' => 2, 
		'me' => array("assets"=> [],"currency"=> [],"ready"=> false), 
		'them' => array("assets"=>[array("appid"=>$appid,"contextid"=>"2","amount"=>1,"assetid"=>$assetid)],"currency"=>[],"ready"=>false) 
		),true);//交易参数
		$id=send($token,$json,$partner);//发起交易
		echo $id."</br>";
		//以下的API都需要前往http://steamcommunity.com/dev/apikey申请WebApi才能用
		// $rs=canceloffer($key,$id);//第一参数为秘钥,第二参数为交易ID
		// $rs=declineoffer($key,$id);//第一参数为秘钥,第二参数为交易ID
		// $rs=acceptoffer($id,$partner);//第一参数为交易ID,第二参数为被交易者ID
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
		
		

