<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 01/01/2018
 * Time: 17:16
 */

namespace OAuth2\Tests;

class PHPUnitUtil
{
    public static function callMethod($obj, $name, array $args) {
        $class = new \ReflectionClass($obj);
        $method = $class->getMethod($name);
        $method->setAccessible(true);
        return $method->invokeArgs($obj, $args);
    }
}