<?php
    require_once 'Zeus.class.php';
    # coded by Rotem Kerner
    # http://www.kerneronsec.com/

    $args = getopt('u:A:B::d:',array('k1:','k2:','k3:'));
    $Zbot = new Zeus\Bot();
    if(!empty($args['u'])){
        $Zbot->setGateUrl($args['u']);
    }
    else{
        print "\n[X] drop point URL must be set";
        usage($argv);
    }

    if(!empty($args['k1'])){
        $Zbot->setKeyWithPass($args['k1']);

    }
    elseif(!empty($args['k2'])){
        $Zbot->setKeyWithHexByes($args['k2']);
    }
    elseif(!empty($args['k3'])){
        $Zbot->setKeyWithDecArray(explode(' ',$args['k3']));
    }
    else{
         print "\n[X] key must be set";
         usage($argv);
    }

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


    # brute force algorithms from algorithm repository
    $algoObject = new Encryption\Algorithm_Reporistory\RC4_Ex();
    for($i = 0 ; $i <= 10; $i++){
        $algoObject->setInc1($i);
        for($b = 0;$b <= 10; $b++){
            $algoObject->setInc2($b);
            $Zbot->setAlgorithm($algoObject);
            print "\n[!] trying RC4 algorithms with incrementers - $i,$b";
            try{
                if($Zbot->uploadFile('test', 'test')){
                    print "\n[V] gateway responeded correctly using ".substr(get_class($algoObject),strrpos(get_class($algoObject), '\\')+1)." algorithms";
                    exit;
                }
            }
            catch(Exception $e){
                if($e->getCode() == ZEUS_EXCEPTION_EMPTY_RESPONSE){
                    print "\n[!] received empty response when using ".substr(get_class($algoObject),strrpos(get_class($algoObject), '\\')+1)." algorithms";
                    
                }
                elseif($e->getCode() == ZEUS_EXCEPTION_UNEXPECTED_RESPONSE){
                    print "\n[X] ".$e->getMessage() ."\n";
                    exit(-1);
                }
                elseif($e->getCode() == ZEUS_EXCEPTION_UNABLE_TO_CONNECT){
                    print "\n[X] ".$e->getMessage() ."\n";
                    exit(-1);
                }
            }

        }

    }
    

?>
