<?php

require 'vendor/autoload.php';

date_default_timezone_set('Asia/Tokyo');

define("TWIG_TEMPLATE_FOLDER", realpath(__DIR__) . "/views");
define("AVATAR_MAX_SIZE", 1 * 1024 * 1024);

function getPDO()
{
    static $pdo = null;
    if (!is_null($pdo)) {
        return $pdo;
    }

    $host = getenv('ISUBATA_DB_HOST') ?: 'localhost';
    $port = getenv('ISUBATA_DB_PORT') ?: '3306';
    $user = getenv('ISUBATA_DB_USER') ?: 'root';
    $password = getenv('ISUBATA_DB_PASSWORD') ?: '';
    $dsn = "mysql:host={$host};port={$port};dbname=isubata;charset=utf8mb4";

    $pdo = new PDO(
        $dsn,
        $user,
        $password,
        [
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
        ]
    );
    $pdo->query("SET SESSION sql_mode='TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY'");
    return $pdo;
}

function icon_put () {
    $stmt = getPDO()->prepare("SELECT distinct name FROM image");
    $stmt->execute();
    $rows = $stmt->fetchAll();
    foreach($rows as $row) {
        $stmt2 = getPDO()->prepare("SELECT name, data FROM image where name = ? ORDER BY id LIMIT 1");
        $stmt2->execute([$row['name']]);
        $row2 = $stmt2->fetch();
        file_put_contents('../public/icons/' . $row2['name'], $row2['data']);
        // ob_start();
        // echo $row2['data'];
        // file_put_contents('../public/icons/' . $row2['name'], ob_get_clean());
    }

    // $limit = 20;
    // $offset = 0;
    // while(true) {
    //     echo "limit:{$limit}, offset:{$offset}" . PHP_EOL;
    //     $stmt = getPDO()->prepare("SELECT id, name, data FROM image ORDER BY id LIMIT ? OFFSET ? ");
    //     $stmt->bindParam(1, $limit, PDO::PARAM_INT);
    //     $stmt->bindParam(2, $offset, PDO::PARAM_INT);
    //     $stmt->execute();
    //     $rows = $stmt->fetchAll();
    //     if (empty($rows)) {
    //         break;
    //     }
    //     foreach($rows as $row) {
    //         ob_start();
    //         echo $row['data'];
    //         file_put_contents('./icon/' . $row['name'], ob_get_clean());
    //     }
    //     $offset = $limit;
    //     $limit += 20;
    // }
}

icon_put();