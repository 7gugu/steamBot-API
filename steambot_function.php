<?php
set_time_limit(0);
class SteamBot {
	
	private $device_id = "";
	private $steamid = "";
	private $identity_secret="";
	private $shared_secret="";
	private $confs = array();
	private $session=null;
	private $proxyMode=false;
	private $proxyAddress="127.0.0.1";
	private $proxyPort="1080";
	private $proxyUserPwd="";
	
	/**
	 *	设定SteamID
	 *	@param string $steamid
	 *	@return void
	 */
	public function setSteamID($steamid){
		$this->steamid=$steamid;
	}
	
	/**
	 *	设定DeviceID
	 *	Warning:本库是根据steamID自动计算,所以设定本函数前,需先使用setSteamID()
	 *	@param void
	 *	@return void
	 */
	public function setDeviceID(){
		if(is_null($this->steamid)){return "SteamID is Null!";}
		$this->device_id=$this->getDeviceID($this->steamid);
	}
	
	/**
	 *	设定SharedSecert
	 *	@param string $shared_secret
	 *	@return void
	 */
	public function setSharedSecret($shared_secret){
		$this->shared_secret=$shared_secret;
	}
	
	/**
	 *	设定IdentitySecret
	 *	@param string $identity_secret
	 *	@return void
	 */
	public function setIdentitySecret($identity_secret){
		$this->identity_secret=$identity_secret;
	}
	
	/*
	 * 设置代理服务器
	 * @param String 代理服务器地址
	 * @param String 代理服务器端口
	 * @param String 代理服务器用户名&密码 格式:Username:Password
	 * @output Boolean 输出操作状态
	 */
	public function setProxyServer($proxyAddress,$proxyPort,$proxyUserPwd=""){
		if($proxyAddress!=""&&$proxyPort!=""){
			$this->proxyMode=true;
			$this->proxyAddress=$proxyAddress;
			$this->proxyPort=$proxyPort;
			if($proxyUserPwd!=""){
				$this->proxyUserPwd=$proxyUserPwd;
			}
		}else{
			$this->proxyMode=false;
			return false;
		}
		return true;
	}
	
	/**
	 *	获取API-KEY
	 *	@param void
	 *	@return string $apikey
	 */
	public function getApiKey()
    {
            $url = 'https://steamcommunity.com/dev/apikey';
            $response = $this->curl($url);
            if (preg_match('/<h2>Access Denied<\/h2>/', $response)) {
                $apikey = '';
            } else if (preg_match('/<p>Key: (.*)<\/p>/', $response, $matches)) {
                $apikey = $matches[1];
            } else {
                $apikey = '';
            }	
		return $apikey;
    }
	
	/**
	 *	获取用户游戏列表
	 *	@param string $nickname
	 *	@return string 
	 */
	public function getgamelist($nickname)
	{
		$content=file_get_contents('http://steamcommunity.com/id/'.$nickname.'/inventory/');
		$content=preg_replace("/[\t\n\r]+/","",$content);
		preg_match_all('/<option data-appid="([\S\s]*?)" value="([\S\s]*?)">([\S\s]*?)<\/option>/',$content,$rs);
		return json_encode($rs[1]);
	}
	
	/**
	 *	获取用户库存
	 *	@param string $steamid SteamID
	 *	@param string $gamid 游戏的ID
	 *	@return 库存的HTML,需要自行解析
	 */
	public function getinventory($steamid,$gameid){
		return file_get_contents('http://steamcommunity.com/inventory/'.$steamid.'/'.$gameid.'/2');
	}
	
	/**
	 *	发起一笔饰品交易
	 *	@param string $accountid 社区ID 来源于用户填写的交易链接中的partner
	 *	@param string $token 标识秘钥 来源于用户填写的交易链接中的token
	 *	@param string $json 待交易的JSON串
	 *	@param string $tradeOfferMessage 交易留言
	 *	@return string 成功:交易ID|失败:strError|无法访问:Empty response
	 */
	public function send($accountid,$token ='',$json,$tradeOfferMessage='')
    {
        $url = 'https://steamcommunity.com/tradeoffer/new/send';
        $referer = 'https://steamcommunity.com/tradeoffer/new/?partner='.$accountid.'&token='.$token;
		
        $params = [
            'sessionid' =>$this->getSession(),//身份验证
            'serverid' => '1',//维持原样即可,未知含义
            'partner' => $this->toCommunityID($accountid),//社区ID=>SteamID
            'tradeoffermessage' => $tradeOfferMessage,//交易留言
            'json_tradeoffer' => $json,//交易传参,type:json
            'trade_offer_create_params' => (empty($token) ? "{}" : json_encode([
                'trade_offer_access_token' => $token//目标第三方交易Token
            ]))
        ];
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
	
	/**
	 *	登录Steam账户
	 *	@param string $username 用户名 必填
	 *	@param string $password 用户密码 必填
	 *	@param string $twofa 二步验证码 非必填
	 *	@return string 成功:json|失败:json|无法访问:NULL
	 */
	public function login($username,$password,$twofa)
	{
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
		return $loginJson;
	}
	
	/**
	 *	接受交易报价
	 *	@param string $tradeOfferId 交易的ID(Steam) 
	 *	@param string $partnerId 本次交易的partner值 
	 *	@return string 
	 */
	public function acceptoffer($tradeOfferId,$partnerId) 
	{
		$this->session=$this->getSession();
	  	$form = array(
	  		'sessionid' =>$this->session,
	  		'serverid' => 1,
	  		'tradeofferid' => $tradeOfferId,
			'partner' => $this->toCommunityID($partnerId)
	  		);
	  	$referer = 'https://steamcommunity.com/tradeoffer/'.$tradeOfferId."/";
	  	$response = $this->curl('https://steamcommunity.com/tradeoffer/'.$tradeOfferId.'/accept',$form,$referer,2);
	  	return ($response);
	}
	
	/**
	 *	取消交易报价
	 *	@param string $key 网站的APIKEY
	 *	@param string $tradeOfferId 交易的ID(Steam) 
	 *	@return string 
	 */
	public function canceloffer($key,$tradeOfferId) 
	{
		return $this->apirequest($key,
			array(
				'method' => 'CancelTradeOffer/v1',
				'param' => array('tradeofferid' => $tradeOfferId),
				'post' => 1
			)
		);
	}
	
	/**
	 *	拒绝交易报价
	 *	@param string $key 网站的APIKEY
	 *	@param string $tradeOfferId 交易的ID(Steam) 
	 *	@return string 
	 */
	public function declineoffer($key,$tradeOfferId) 
	{
		 return $this->apirequest($key,
			array(
				'method' => 'DeclineTradeOffer/v1',
				'param' => array('tradeofferid' => $tradeOfferId),
				'post' => 1
			)
		);
	}
	
	/**
	 *	获取已接收的交易报价
	 *	@param string $key 网站的APIKEY
	 *	@return string 
	 */
	public function getoffers($key) 
	{
		$param = json_encode(
			array(
				'get_received_offers'=>true,
				'get_sent_offers'=>false,
				'get_received_offers'=>true,
				'get_descriptions'=>false,
				'language'=>'zh_cn',
				'active_only'=>true,
				'historical_only'=>false,
				'time_historical_cutoff'=>false,
			)
		);
		$url = 'https://api.steampowered.com/IEconService/GetTradeOffers/v1/?key='.$key.'&input_json='.$param;
		return $this->curl($url);
	}

	/**
	 *	获取交易报价的状态
	 *	@param string $key 网站的APIKEY
	 *	@param string $tradeOfferId 交易报价ID
	 *	@return string 
	 */
	public function getOffer($key,$tradeOfferId){
		$param = json_encode(
			array(
				'language'=>'zh_cn',
				'tradeofferid'=>$tradeOfferId,
			)
		);
		$url = 'https://api.steampowered.com/IEconService/GetTradeOffer/v1/?key='.$key.'&input_json='.$param;
		return $this->curl($url);
	}
	
	/**
	 *	社区ID转SteamID
	 *	@param string $id partner的值 
	 *	@return string SteamID
	 */
	private function toCommunityID($id) {
        if (preg_match('/^STEAM_/', $id)) {
            $parts = explode(':', $id);
            return bcadd(bcadd(bcmul($parts[2], '2'), '76561197960265728'), $parts[1]);
        } elseif (is_numeric($id) && strlen($id) < 16) {
            return bcadd($id, '76561197960265728');
        } else {
            return $id;
        }
    }
	
	/**
	 *	获取上次登录的sessionid
	 *	@param void
	 *	@return string SessionID
	 */
	public function getSession()
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
	
	/**
	 *	获取上次登录的SteamID
	 *	@param void
	 *	@return string 成功:SteamID|失败:0|无法访问:Unexpected response from Steam.
	 */
	public function getSteamID(){
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
	
	/**
	 *	Curl封装组件
	 *	@param $url 请求的目标网址
	 *	@param $post 需要POST的数据
	 *	@param $refer
	 *	@param $type 0:正常模式|1:登录模式,生成COOKIE文件|2:接受报价模式
	 *	@param $header 请求头
	 *	@return string 
	 */
	private function curl($url, $post=null,$refer=null,$type="0",$header=null) { 
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_HEADER, $header); 
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1); 
		curl_setopt ($curl, CURLOPT_SSL_VERIFYPEER, 0);
		curl_setopt ($curl, CURLOPT_SSL_VERIFYHOST, 0);
		curl_setopt($curl, CURLOPT_FOLLOWLOCATION, 1);
		curl_setopt($curl, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:27.0) Gecko/20100101 Firefox/27.0');
		if($this->proxyMode){
				curl_setopt($curl, CURLOPT_PROXYAUTH, CURLAUTH_BASIC); //代理认证模式
				curl_setopt($curl, CURLOPT_PROXY, $this->proxyAddress); //代理服务器地址
				curl_setopt($curl, CURLOPT_PROXYPORT, $this->proxyPort); //代理服务器端口
				if($this->proxyUserPwd!=""){
					curl_setopt($curl, CURLOPT_PROXYUSERPWD, $this->proxyUserPwd); //http代理认证帐号，名称:pwd的格式
				}
			}
		if($post!=null){
			@curl_setopt($curl, CURLOPT_POST, 1);
			@curl_setopt($curl, CURLOPT_POSTFIELDS, $post);
		}
		if(isset($refer)){
            curl_setopt($curl, CURLOPT_REFERER, $refer);
        }  
		if($type==1){
			curl_setopt($curl, CURLOPT_COOKIEJAR, 'cookie.txt');
		}
		if($type==2){
			$string=file_get_contents("cookie.txt");
			curl_setopt($curl, CURLOPT_COOKIE, 'sessionid='.$this->session.';'.$this->cookieToString($string));
		}else{
			curl_setopt($curl, CURLOPT_COOKIEFILE, 'cookie.txt');		
		}
		$rs= curl_exec($curl);
		curl_close($curl);
		return $rs;	
	} 
	
	/**
	 *	cookie文件转字符串
	 *  @return String 生成的字符串
	 */
	private function cookieToString($string){
		$cookieString = '';
		$lines = explode("\n", $string);
		foreach($lines as $line){
			if(isset($line[0]) && substr_count($line, "\t") == 6){
				$tokens = explode("\t", $line);
				$tokens = array_map('trim', $tokens);
				$cookieString .= $tokens[5].'='.$tokens[6].'; ';
			}
		}
		return $cookieString;
	}
	
	/**
	 *	Api请求组件
	 *	@param $key 网站的APIKEY
	 *	@param $option 参数数组
	 *	@return string 
	 */
	private function apirequest($key,$option)
	{
		$url = 'https://api.steampowered.com/IEconService/'.$option['method'].'/?key='.$key.($option['post'] ? '' : ('&'.http_build_query($option['param'])));
		if($option['post']==1){
			$res=$this->curl($url,$option['param']);
		}else{
			$res=$this->curl($url,null);
		}
		return $res;
	}
	
	
	/**
	 *	计算2FA验证码
	 *	Created by Marlon Colhado
	 *	admin@kazeta.com.br
	 */
	 
	
	//字符串类型转换
	private function intToByte($int)
	{
		return $int & (0xff);
	} 

	
	private function startArrayToZero($array)
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
	
	//获取时间	
	private function getSteamTime($localtime = false)
	{
		if($localtime) return time()+10;
		$data = array('steamid' => 0);
		$url = 'http://api.steampowered.com/ITwoFactorService/QueryTime/v0001';
		$postString = http_build_query($data, '', '&');
		$response = $this->curl($url,$postString);
		$response = json_decode($response);
		return $response->response->server_time;
	}
	
	//计算时间的hash	
	private function createTimeHash($time)
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
	
	//sha1加密
	private function createHMac($timeHash, $SharedSecretDecoded)
	{
		$hash = hash_hmac('sha1', $timeHash, $SharedSecretDecoded, false);
		$hmac = unpack('C*', pack('H*', $hash));
		return $hmac;
	}
	
	/**
	 * 生成2FA验证码
	 * shared serect key 方法:https://www.7gugu.com/2018/06/24/%E7%BF%BB%E8%AF%91%E4%BD%BF%E7%94%A8steam-app%E8%8E%B7%E5%8F%96%E4%BD%A0%E7%9A%84steam-shared_secret_key/
	 * @param string $shared_secret 
	 * @param string $timemode true使用本地时间[仅用于不可访问steam服务时使用],false使用Steam服务器时间 
	 * @return string 二步验证码
	 */
	public function GenerateSteamGuardCode($timemode=false)
	{
		$DecodedSharedSecret = base64_decode($this->shared_secret);
		$timeHash = $this->createTimeHash($this->getSteamTime($timemode));
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
	
	/**
	 * 使用SteamID生成Device_id
	 * @param void
	 * @return string
	 */
	private function getDeviceID() {
		$sha1 = sha1($this->steamid);
		$cut = substr($sha1, 0, 32);
		$deviceID = preg_replace('/^([0-9a-f]{8})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{12}).*$/', '$1-$2-$3-$4-$5', $cut);
		$prepend = 'android:';
		return $prepend . $deviceID;
	}

	/**
	 * 生成confirmation的URL
	 * @param $tag 动作标识
	 * conf时生成的是确认的页面
	 * detail时生成的是交易的详情页面
	 * allow是同意交易
	 * deny是拒绝交易
	 * cancel是取消交易
	 * @return string 交易确认链接
	 */
    private function generateConfirmationURL($tag = 'conf')
    {
        return 'https://steamcommunity.com/mobileconf/conf?' . $this->generateConfirmationQueryParams($tag);
    }
	
	/**
	 * 生成confirmation的URL的参数
	 * @param $tag 动作标识
	 * @return string 拼接好的参数
	 */
    private function generateConfirmationQueryParams($tag)
    {
        $time = $this->getSteamTime();
        return 'p=' . $this->getDeviceID() . '&a=' . $this->steamid . '&k=' . $this->generateConfirmationHashForTime($time, $tag) . '&t=' . $time . '&m=android&tag=' . $tag;
    }
	
	/**
	 * 生成confirmation的时间HASH
	 * @param $time 时间
	 * @param $tag 动作标识
	 * @return string 时间得HASH
	 */
    private function generateConfirmationHashForTime($time, $tag)
    {
        $identitySecret = base64_decode($this->identity_secret);
        $array = $tag ? substr($tag, 0, 32) : '';
        for ($i = 8; $i > 0; $i--) {
            $array = chr($time & 0xFF) . $array;
            $time >>= 8;
        }
        $code = hash_hmac("sha1", $array, $identitySecret, true);
        return base64_encode($code);
    }
	
	/**
     * 遍历确认列表.
	 * Warning:Steam时不时会抽筋,所以要多遍历一两次,才会获取到列表
     * @return array $confs 交易确认数组
	 * 0:交易ID
	 * 1:交易确认的Key
	 * 2:offerId
	 * 3:交易确认的描述
     */
    public function fetchConfirmations()
    {
        $url = $this->generateConfirmationURL();
        $confirmations = [];
        $response = '';
        try {
            $response = $this->curl($url);
        } catch (Exception $ex) {
            return $confirmations;
		}
		file_put_contents("check.html",$response);
        if (strpos($response, '<div>Nothing to confirm</div>') === false) {
            $confIdRegex = '/data-confid="(\d+)"/';
            $confKeyRegex = '/data-key="(\d+)"/';
            $confOfferRegex = '/data-creator="(\d+)"/';
            $confDescRegex = '/<div>((Confirm|Trade with|Sell -) .+)<\/div>/';
            preg_match_all($confIdRegex, $response, $confIdMatches);
            preg_match_all($confKeyRegex, $response, $confKeyMatches);
            preg_match_all($confOfferRegex, $response, $confOfferMatches);
            preg_match_all($confDescRegex, $response, $confDescMatches);
            if (count($confIdMatches[1]) > 0 && count($confKeyMatches[1]) > 0 && count($confDescMatches) > 0 && count($confOfferMatches) > 0) {
                $checkedConfIds = [];
                for ($i = 0; $i < count($confIdMatches[1]); $i++) {
                    $confId = $confIdMatches[1][$i];
                    if (in_array($confId, $checkedConfIds)) {
                        continue;
                    }
                    $confKey = $confKeyMatches[1][$i];
                    $confOfferId = $confOfferMatches[1][$i];
                    //$confDesc = $confDescMatches[$i];
					$this->confs[$i][0]=$confId;
					$this->confs[$i][1]=$confKey;
					$this->confs[$i][2]=$confOfferId;
					//$this->confs[$i][3]=$confDesc;
				    $checkedConfIds[] = $confId;
                }
            } 
        }
        return $this->confs;
    }
	
	/**
     * 获取交易确认页的TradeOfferId.
	 * Warning:Steam时不时会抽筋,所以要多遍历一两次,才会获取到列表
	 * @param array $confs fetchConfirmations()返回的数组
     * @return string 成功:tradeOfferId|失败:0
     */
    public function getConfirmationTradeOfferId($confirmation)
    {
		for($i=0;i<count($confirmation);$i++){
        $url = 'https://steamcommunity.com/mobileconf/details/' . $confirmation[$i][0] . '?' . $this->generateConfirmationQueryParams('details');
        $response = '';
        $response = $this->curl($url);
        if (!empty($response)) {
            $json = json_decode($response, true);
            if (isset($json['success']) && $json['success']) {
                $html = $json['html'];
                if (preg_match('/<div class="tradeoffer" id="tradeofferid_(\d+)" >/', $html, $matches)) {
                    return $matches[1];
                }
            }
        }
        return '0';
		}
	}
	
    /**
     * 接受确认请求
     * @param array $confs fetchConfirmations()返回的数组
     * @return bool
     */
    public function acceptConfirmation($confirmation)
    {
        return $this->sendConfirmationAjax($confirmation, 'allow');
    }
	
    /**
     * 取消确认请求
     * @param array $confs fetchConfirmations()返回的数组
     * @return bool
     */
    public function cancelConfirmation($confirmation)
    {
        return $this->sendConfirmationAjax($confirmation, 'cancel');
    }
	
	/**
     * 发送确认页请求
     * @param array $confs fetchConfirmations()返回的数组
     * @param string $op 动作标识
     * @return bool
     */
    private function sendConfirmationAjax($confirmation, $op)
    {
        $url = 'https://steamcommunity.com/mobileconf/ajaxop?op=' . $op . '&' . $this->generateConfirmationQueryParams($op) . '&cid=' . $confirmation[0] . '&ck=' . $confirmation[1];
        $response = '';
        try {
            $response = $this->curl($url);
        } catch (Exception $ex) {
        }
        if (!empty($response)) {
            $json = json_decode($response, true);
            return isset($json['success']) && $json['success'];
        }
        return false;
    }
	}