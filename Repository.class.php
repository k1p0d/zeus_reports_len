<?php
    # coded by Rotem Kerner
    # http://www.kerneronsec.com/

    class Repository_Exception extends Exception{};

    abstract class Repository{
        
        static $namespace = '';

        public static function getAll(){
            if(empty(static::$namespace)){
                throw new Repository_Exception("static \$namespace variable must be set");
            }
            $classes = Namespace_Reflector::getClasses(static::$namespace);
            $classInstances = array();
            foreach($classes as $class){

                array_push($classInstances,new $class());
            }
            return $classInstances;
        }

        public static function getByName($name){
            if(empty(static::$namespace)){
                throw new Repository_Exception("static \$namespace variable must be set");
            }
            if(Namespace_Reflector::classExist(static::$namespace, $name)){
                $className = '\\'. static::$namespace .'\\'. $name;
                return new $className();
            }

            return false;

            # maybe one day... if we wont recode all thia in python.
        }

    }

    class Namespace_Reflector{ # kinda hacky but comfortable
        static function getClasses($namespace){
            $classnames = array();
            foreach(get_declared_classes() as $name){
                if(substr($name,0,strlen($namespace)) == $namespace){
                    array_push($classnames, $name);
                }
            }
            if(count($classnames)){
                return $classnames;
            }
        }

        static function classExist($namespace, $class){
            return class_exists('\\' . $namespace . '\\' . $class);
        }

   
    }

?>