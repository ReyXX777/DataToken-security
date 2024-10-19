<?php

class Database {
    private static $connection = null;

    public static function getConnection() {
        if (self::$connection === null) {
            $config = require(__DIR__ . '/../config/config.php');
            self::$connection = new PDO(
                "mysql:host=" . $config['db_host
