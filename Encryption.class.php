<?php
    # coded by Rotem Kerner
    # http://www.kerneronsec.com/


/**
 * Description of Encryption_Algorithm
 *
 * @author exodus
 */ 

    namespace Encryption{
        
    require_once 'Repository.class.php';

    interface Algorithm_Interface{

        function _run($context);
    }


    abstract class Algorithm implements Algorithm_Interface{

        private $data;
        private $key;

        public function __construct($data = false, $key = false){

            $this->context = array();
            $this->context['data'] = $data;
            $this->context['key'] = $key;


        }

        public function getData(){
            return $this->context['data'];


        }

        public function setData($data){

            $this->context = array_merge($this->context, array('data' => $data));
        }

        public function getKey(){
            return $this->context['key'];
        }

        public function setKey($key){
            $this->context['key'] = $key;
        }

        public function setContext(array $context){
            $this->context = array_merge($this->context, $context);
        }

        public function run(){
            $this->contextCheck($this->context);
            return $this->_run($this->context);
        }

        public function contextCheck($context){
            throw new Exception("method 'contextCheck' must be implemented.");
        }

    }



    class Encryption_Repository extends \Repository{
        static $namespace = 'Encryption\Algorithm_Repository';

    }



}

    namespace Encryption\Algorithm_Repository{

                function declared(){
                    print_r(get_declared_classes());
                }



                class RC4 extends \Encryption\Algorithm{

                  public function _run($context){
                    $key = $context['key'];
                    $data = $context['data'];

                    $keyCrypt = array();
                    foreach(explode(' ', $key) as $hex){
                        array_push($keyCrypt, (int) $hex);
                    }
                    $key = $keyCrypt;

                    $len = strlen($data);
                        for ($z = $y = $x = 0; $x < $len; $x++) {
                                $z = ($z + 1) % 256;
                                $y = ($y + $key[$z] + 0) % 256;
                                $tmp = $key[$z];
                                $key[$z] = $key[$y];
                                $key[$y] = $tmp;
                                $data[$x] = chr(ord($data[$x]) ^ ($key[(($key[$z] + $key[$y]) % 256)]));
                        }

                        return $data;
                }

                public function contextCheck($context){
                    if(empty($context["key"])){
                        throw new Exception("key must be set");
                    }
                    elseif(empty($context["data"])){
                        throw new Exception("data must be set");
                    }
                }
        }


                class RC4_A extends \Encryption\Algorithm{

                    public function _run($context){
                        $key = $context['key'];
                        $data = $context['data'];
                        $keyCrypt = array();
                        foreach(explode(' ', $key) as $hex){
                            array_push($keyCrypt, (int) $hex);
                        }
                        $key = $keyCrypt;
                        $len = strlen($data);

                        for ($z = $y = $x = 0; $x < $len; $x++) {

                                $z = ($z + 3) % 256;
                                $y = ($y + $key[$z] +7) % 256;

                                $tmp = $key[$z];
                                $key[$z] = $key[$y];
                                $key[$y] = $tmp;
                                $data[$x] = chr(ord($data[$x]) ^ ($key[(($key[$z] + $key[$y]) % 256)]));
                        }

                        return $data;
                }
                    public function contextCheck($context){
                        if(empty($context["key"])){
                            throw new Exception("key must be set");
                        }
                        elseif(empty($context["data"])){
                            throw new Exception("data must be set");
                        }
                }
        }



                class RC4_B extends \Encryption\Algorithm{

                    public function _run($context){
                        $key = $context['key'];
                        $data = $context['data'];

                        $keyCrypt = array();
                        foreach(explode(' ', $key) as $hex){
                            array_push($keyCrypt, (int) $hex);
                        }
                        $key = $keyCrypt;
                        $len = strlen($data);

                        for ($z = $y = $x = 0; $x < $len; $x++) {

                                $z = ($z + 7) % 256;
                                $y = ($y + $key[$z] +5) % 256;

                                $tmp = $key[$z];
                                $key[$z] = $key[$y];
                                $key[$y] = $tmp;
                                $data[$x] = chr(ord($data[$x]) ^ ($key[(($key[$z] + $key[$y]) % 256)]));
                        }

                        return $data;
                    }

                    public function contextCheck($context){
                        if(empty($context["key"])){
                            throw new Exception("key must be set");
                        }
                        elseif(empty($context["data"])){
                            throw new Exception("data must be set");
                        }
                    }


                }

                class RC4_C extends \Encryption\Algorithm{

                    public function _run($context){
                        $key = $context['key'];
                        $data = $context['data'];

                        $keyCrypt = array();
                        foreach(explode(' ', $key) as $hex){
                            array_push($keyCrypt, (int) $hex);
                        }
                        $key = $keyCrypt;

                        $len = strlen($data);

                        for ($z = $y = $x = 0; $x < $len; $x++) {

                                $z = ($z + 4) % 256;
                                $y = ($y + $key[$z] + 8) % 256;

                                $tmp = $key[$z];
                                $key[$z] = $key[$y];
                                $key[$y] = $tmp;
                                $data[$x] = chr(ord($data[$x]) ^ ($key[(($key[$z] + $key[$y]) % 256)]));
                        }

                        return $data;
                    }

                    public function contextCheck($context){
                        if(empty($context["key"])){
                            throw new Exception("key must be set");
                        }
                        elseif(empty($context["data"])){
                            throw new Exception("data must be set");
                        }
                    }


                }


                class RC4_D extends \Encryption\Algorithm{

                    public function _run($context){
                        $key = $context['key'];
                        $data = $context['data'];

                        $keyCrypt = array();
                        foreach(explode(' ', $key) as $hex){
                            array_push($keyCrypt, (int) $hex);
                        }
                        $key = $keyCrypt;

                        $len = strlen($data);

                        for ($z = $y = $x = 0; $x < $len; $x++) {

                                $z = ($z + 5) % 256;
                                $y = ($y + $key[$z] + 0) % 256;

                                $tmp = $key[$z];
                                $key[$z] = $key[$y];
                                $key[$y] = $tmp;
                                $data[$x] = chr(ord($data[$x]) ^ ($key[(($key[$z] + $key[$y]) % 256)]));
                        }

                        return $data;
                    }

                    public function contextCheck($context){
                        if(empty($context["key"])){
                            throw new Exception("key must be set");
                        }
                        elseif(empty($context["data"])){
                            throw new Exception("data must be set");
                        }
                    }

                }

                class RC4_Citadel extends \Encryption\Algorithm{


                    public function _run($context){
                        $key = $context['key'];
                        $data = $context['data'];
                        $loginKey = $context['login_key'];


                        $keyCrypt = array();
                        foreach(explode(' ', $key) as $hex){
                            array_push($keyCrypt, (int) $hex);
                        }
                        $key = $keyCrypt;

                      $len = strlen($data);

                      $loginKeyLen = strlen($loginKey);
                      for($z = $y = $x = $w = 0; $x < $len; $x++)
                      {
                        $z = ($z + 1) % 256;
                        $y = ($y + $key[$z]) % 256;
                        $tmp      = $key[$z];
                        $key[$z]  = $key[$y];
                        $key[$y]  = $tmp;
                        $data[$x] = chr(ord($data[$x]) ^ ($key[(($key[$z] + $key[$y]) % 256)]));
                        $data[$x] = chr(ord($data[$x]) ^ ord($loginKey[$w]));
                        if (++$w == $loginKeyLen) $w = 0;
                      }
                    
                      return $data;
                    }


                    public function contextCheck($context){
                        if(empty($context["key"])){
                            throw new Exception("the context value 'key' must be set");
                        }
                        elseif(empty($context["data"])){
                            throw new Exception("the context value 'data' must be set");
                        }
                        elseif(empty($context["login_key"])){
                            throw new Exception("the context value 'login_key' must be set.");
                        }
                    }
                }



                class AES extends \Encryption\Algorithm{

                    public function _run($context){
                        $key = $context['key'];
                        $data = $context['data'];

                        $keyCrypt = false;
                        foreach(explode(' ', $key) as $hex){
                            $keyCrypt .= pack('C',  hexdec($hex));
                        }
                        require_once 'AES.class.php';

                        $aes = new \AES($keyCrypt);
                        return $aes->encrypt($data);
                    }

                    public function contextCheck($context){
                        if(empty($context["key"])){
                            throw new Exception("key must be set");
                        }
                        elseif(empty($context["data"])){
                            throw new Exception("data must be set");
                        }
                    }


                }

                class RC4_Ex extends \Encryption\Algorithm{


                    public function _run($context){
                        $key = $context['key'];
                        $data = $context['data'];
                        $inc1 = $context['key_inc1'] ? $context['key_inc1'] : 1;
                        $inc2 = $context['key_inc2'] ? $context['key_inc2'] : 0;


                        $keyCrypt = array();
                        foreach(explode(' ', $key) as $hex){
                            array_push($keyCrypt, (int) $hex);
                        }
                        $key = $keyCrypt;

                        $len = strlen($data);
                        #print "the incrementers - ".$this->inc1." ".$this->inc2;
                        for ($z = $y = $x = 0; $x < $len; $x++) {

                                $z = ($z + $inc1) % 256;
                                $y = ($y + $key[$z] + $inc2) % 256;

                                $tmp = $key[$z];
                                $key[$z] = $key[$y];
                                $key[$y] = $tmp;
                                $data[$x] = chr(ord($data[$x]) ^ ($key[(($key[$z] + $key[$y]) % 256)]));
                        }

                        return $data;
                    }

                    public function contextCheck($context){
                        if(empty($context["key"])){
                            throw new Exception("key must be set");
                        }
                        elseif(empty($context["data"])){
                            throw new Exception("data must be set");
                        }
                    }


                }
}
?>
