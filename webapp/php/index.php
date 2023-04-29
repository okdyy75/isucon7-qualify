<?php

require 'vendor/autoload.php';

use Slim\Http\Request;
use Slim\Http\Response;

use Dflydev\FigCookies\FigResponseCookies;
use Dflydev\FigCookies\FigRequestCookies;
use Dflydev\FigCookies\Cookie;
use Dflydev\FigCookies\SetCookie;

date_default_timezone_set('Asia/Tokyo');

define("TWIG_TEMPLATE_FOLDER", realpath(__DIR__) . "/views");
define("AVATAR_MAX_SIZE", 1 * 1024 * 1024);

define("DEFAULT_CHANNELS", [
    ['id' => 1, 'name' => '1ちゃんねる', 'description' => 'ここは 1ちゃんねるです'],
    ['id' => 2, 'name' => '2ちゃんねる', 'description' => 'ここは 2ちゃんねるです'],
    ['id' => 3, 'name' => '3ちゃんねる', 'description' => 'ここは 3ちゃんねるです'],
    ['id' => 4, 'name' => '4ちゃんねる', 'description' => 'ここは 4ちゃんねるです'],
    ['id' => 5, 'name' => '5ちゃんねる', 'description' => 'ここは 5ちゃんねるです'],
    ['id' => 6, 'name' => '6ちゃんねる', 'description' => 'ここは 6ちゃんねるです'],
    ['id' => 7, 'name' => '7ちゃんねる', 'description' => 'ここは 7ちゃんねるです'],
    ['id' => 8, 'name' => '8ちゃんねる', 'description' => 'ここは 8ちゃんねるです'],
    ['id' => 9, 'name' => '9ちゃんねる', 'description' => 'ここは 9ちゃんねるです'],
    ['id' => 10, 'name' => '10ちゃんねる', 'description' => 'ここは 10ちゃんねるです'],
]);

function logger(string $msg) {
    $time = DateTime::createFromFormat('U.u', microtime(true));
    file_put_contents('./app.log', $time->format('Y-m-d H:i:s.u') . ' ' . $msg . PHP_EOL . PHP_EOL, FILE_APPEND);
}

if (!function_exists('getallheaders')) {
    function getallheaders()
    {
        $headers = array();

        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
        }

        return $headers;
    }
}

function getRedis()
{
    static $redis = null;
    if (!is_null($redis)) {
        return $redis;
    }
    $redis = new Predis\Client('tcp://redis:6379');
    return $redis;
}

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

// $app = new \Slim\App();

$c = new \Slim\Container([
    'settings' => [
        'displayErrorDetails' => true,
    ],
]);
$app = new \Slim\App($c);

$container = $app->getContainer();

$container['view'] = function ($container) {
    $view = new \Slim\Views\Twig(TWIG_TEMPLATE_FOLDER, []);
    $view->addExtension(
        new \Slim\Views\TwigExtension(
            $container['router'],
            $container['request']->getUri()
        )
    );
    return $view;
};

// $app->get('/initialize', function (Request $request, Response $response) {
//     $dbh = getPDO();
//     $dbh->query("DELETE FROM user WHERE id > 1000");
//     $dbh->query("DELETE FROM image WHERE id > 1001");
//     $dbh->query("DELETE FROM channel WHERE id > 10");
//     $dbh->query("DELETE FROM message WHERE id > 10000");
//     $dbh->query("DELETE FROM haveread");
//     $response->withStatus(204);
// });

$app->get('/initialize', function (Request $request, Response $response) {
    // logger($_SERVER['REQUEST_URI'] . ' L' . __LINE__ . PHP_EOL . '_GET' . print_r($_GET, true) . '_POST' . print_r($_POST, true) . '_FILES' . print_r($_FILES, true) . '_COOKIE' . print_r($_COOKIE, true) . 'getallheaders' . print_r(getallheaders(), true));
    // $rds = getRedis();
    // $rds->del('channel');
    // $rds->del('haveread');
    // $rds->hmset('channel', DEFAULT_CHANNELS);
    
    // apcu_delete("channel");
    // apcu_delete("haveread");

    $dbh = getPDO();
    $dbh->query("DELETE FROM user WHERE id > 1000");
    $dbh->query("DELETE FROM image WHERE id > 1001");
    $dbh->query("DELETE FROM channel WHERE id > 10");
    $dbh->query("DELETE FROM message WHERE id > 10000");
    $dbh->query("DELETE FROM haveread");
    if ($request->getParam('type') == 'ddl') {
        $dbh->query("ALTER TABLE channel MODIFY description varchar(37)");
        $dbh->query("ALTER TABLE user MODIFY name varchar(21)");
        $dbh->query("ALTER TABLE user MODIFY display_name varchar(28)");
        $dbh->query("ALTER TABLE user MODIFY avatar_icon varchar(44)");
        $dbh->query("ALTER TABLE image DROP data");
        $dbh->query("ALTER TABLE user DROP salt");
        $dbh->query("ALTER TABLE user DROP password");
        $dbh->query("ALTER TABLE user DROP created_at");
        $dbh->query("ALTER TABLE haveread DROP updated_at");
        $dbh->query("ALTER TABLE haveread DROP created_at");
        $dbh->query("ALTER TABLE channel DROP updated_at");
        $dbh->query("ALTER TABLE channel DROP created_at");
    }

    $response->withStatus(204);
});

function db_get_user($dbh, $userId)
{
    $stmt = $dbh->prepare("SELECT * FROM user WHERE id = ?");
    $stmt->execute([$userId]);
    return $stmt->fetch();
}

// function db_get_user($dbh, $userId)
// {
//     $stmt = $dbh->prepare("SELECT * FROM user WHERE id = ?");
//     $stmt->execute([$userId]);
//     return $stmt->fetch();
// }

function db_add_message($dbh, $channelId, $userId, $message)
{
    $stmt = $dbh->prepare("INSERT INTO message (channel_id, user_id, content, created_at) VALUES (?, ?, ?, NOW())");
    $stmt->execute([$channelId, $userId, $message]);
}

// function db_add_message($dbh, $channelId, $userId, $message)
// {
//     $stmt = $dbh->prepare("INSERT INTO message (channel_id, user_id, content, created_at) VALUES (?, ?, ?, NOW())");
//     $stmt->execute([$channelId, $userId, $message]);
// }

$loginRequired = function (Request $request, Response $response, $next) use ($container) {
    $userId = FigRequestCookies::get($request, 'user_id')->getValue();
    if (!$userId) {
        return $response->withRedirect('/login', 303);
    }

    $request = $request->withAttribute('user_id', $userId);
    $container['view']->offsetSet('user_id', $userId);

    $user = db_get_user(getPDO(), $userId);
    if (!$user) {
        $response = FigResponseCookies::remove($response, 'user_id');
        return $response->withRedirect('/login', 303);
    }

    $request = $request->withAttribute('user', $user);
    $container['view']->offsetSet('user', $user);

    $response = $next($request, $response);
    return $response;
};

// $loginRequired = function (Request $request, Response $response, $next) use ($container) {
//     logger($_SERVER['REQUEST_URI'] . ' L' . __LINE__ . PHP_EOL . '_GET' . print_r($_GET, true) . '_POST' . print_r($_POST, true) . '_FILES' . print_r($_FILES, true) . '_COOKIE' . print_r($_COOKIE, true) . 'getallheaders' . print_r(getallheaders(), true));
//     $userId = FigRequestCookies::get($request, 'user_id')->getValue();
//     if (!$userId) {
//         return $response->withRedirect('/login', 303);
//     }

//     $request = $request->withAttribute('user_id', $userId);
//     $container['view']->offsetSet('user_id', $userId);

//     $user = db_get_user(getPDO(), $userId);
//     if (!$user) {
//         $response = FigResponseCookies::remove($response, 'user_id');
//         return $response->withRedirect('/login', 303);
//     }

//     $request = $request->withAttribute('user', $user);
//     $container['view']->offsetSet('user', $user);

//     $response = $next($request, $response);
//     return $response;
// };

function random_string($length)
{
    $str = "";
    while ($length--) {
        $str .= str_shuffle("1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")[0];
    }
    return $str;
}

// function register($dbh, $userName, $password)
// {
//     $salt = random_string(20);
//     $passDigest = sha1(utf8_encode($salt . $password));
//     $stmt = $dbh->prepare(
//         "INSERT INTO user (name, salt, password, display_name, avatar_icon, created_at) ".
//         "VALUES (?, ?, ?, ?, 'default.png', NOW())"
//     );
//     $stmt->execute([$userName, $salt, $passDigest, $userName]);
//     $stmt = $dbh->query("SELECT LAST_INSERT_ID() AS last_insert_id");
//     return $stmt->fetch()['last_insert_id'];
// }

function register($dbh, $userName, $password)
{
    $stmt = $dbh->prepare(
        "INSERT INTO user (name, display_name, avatar_icon) ".
        "VALUES (?, ?, 'default.png')"
    );
    $stmt->execute([$userName, $userName]);
    $stmt = $dbh->query("SELECT LAST_INSERT_ID() AS last_insert_id");
    return $stmt->fetch()['last_insert_id'];
}

$app->get('/', function (Request $request, Response $response) {
    if (FigRequestCookies::get($request, 'user_id')->getValue()) {
        return $response->withRedirect('/channel/1', 303);
    }
    return $this->view->render($response, 'index.twig', []);
});

// $app->get('/', function (Request $request, Response $response) {
//     logger($_SERVER['REQUEST_URI'] . ' L' . __LINE__ . PHP_EOL . '_GET' . print_r($_GET, true) . '_POST' . print_r($_POST, true) . '_FILES' . print_r($_FILES, true) . '_COOKIE' . print_r($_COOKIE, true) . 'getallheaders' . print_r(getallheaders(), true));
//     if (FigRequestCookies::get($request, 'user_id')->getValue()) {
//         return $response->withRedirect('/channel/1', 303);
//     }
//     return $this->view->render($response, 'index.twig', []);
// });

// function get_channel_list_info($focusedChannelId = null)
// {
//     $stmt = getPDO()->query("SELECT * FROM channel ORDER BY id");
//     $channels = $stmt->fetchall();
//     $description = "";

//     foreach ($channels as $channel) {
//         if ((int)$channel['id'] === (int)$focusedChannelId) {
//             $description = $channel['description'];
//             break;
//         }
//     }
//     return [$channels, $description];
// }

function get_channel_list_info($focusedChannelId = null)
{
    $rds = getRedis();
    $channels = $rds->hgetall('channel');
    // $channels = apcu_fetch("channel");
    // if ($channels === false) {
    //     $channels = [];
    // }
    
    $description = "";
    if (!is_null($focusedChannelId)) {
        foreach ($channels as $channel) {
            if ((int)$channel['id'] === (int)$focusedChannelId) {
                $description = $channel['description'];
                break;
            }
        }
    }

    return [$channels, $description];
}

$app->get('/channel/{channel_id}', function (Request $request, Response $response) {
    $channelId = $request->getAttribute('channel_id');
    list($channels, $description) = get_channel_list_info($channelId);
    return $this->view->render(
        $response,
        'channel.twig',
        [
            'channels' => $channels,
            'channel_id' => $channelId,
            'description' => $description
        ]
    );
})->add($loginRequired);

// $app->get('/channel/{channel_id}', function (Request $request, Response $response) {
//     $channelId = $request->getAttribute('channel_id');
//     list($channels, $description) = get_channel_list_info($channelId);
//     return $this->view->render(
//         $response,
//         'channel.twig',
//         [
//             'channels' => $channels,
//             'channel_id' => $channelId,
//             'description' => $description
//         ]
//     );
// })->add($loginRequired);

$app->get('/register', function (Request $request, Response $response) {
    return $this->view->render($response, 'register.twig', []);
});

// $app->get('/register', function (Request $request, Response $response) {
//     logger($_SERVER['REQUEST_URI'] . ' L' . __LINE__ . PHP_EOL . '_GET' . print_r($_GET, true) . '_POST' . print_r($_POST, true) . '_FILES' . print_r($_FILES, true) . '_COOKIE' . print_r($_COOKIE, true) . 'getallheaders' . print_r(getallheaders(), true));
//     return $this->view->render($response, 'register.twig', []);
// });

$app->post('/register', function (Request $request, Response $response) {
    $name     = $request->getParam('name');
    $password = $request->getParam('password');
    if (!$name || !$password) {
        return $response->withStatus(400);
    }
    try {
        $userId = register(getPDO(), $name, $password);
    } catch (PDOException $e) {
        if ($e->errorInfo[1] === 1062) {
            return $response->withStatus(409);
        }
        throw $e;
    }
    $response = FigResponseCookies::set($response, SetCookie::create('user_id', $userId));
    return $response->withRedirect('/', 303);
});

// $app->post('/register', function (Request $request, Response $response) {
//     logger($_SERVER['REQUEST_URI'] . ' L' . __LINE__ . PHP_EOL . '_GET' . print_r($_GET, true) . '_POST' . print_r($_POST, true) . '_FILES' . print_r($_FILES, true) . '_COOKIE' . print_r($_COOKIE, true) . 'getallheaders' . print_r(getallheaders(), true));
//     $name     = $request->getParam('name');
//     $password = $request->getParam('password');
//     if (!$name || !$password) {
//         return $response->withStatus(400);
//     }
//     try {
//         $userId = register(getPDO(), $name, $password);
//     } catch (PDOException $e) {
//         if ($e->errorInfo[1] === 1062) {
//             return $response->withStatus(409);
//         }
//         throw $e;
//     }
//     $response = FigResponseCookies::set($response, SetCookie::create('user_id', $userId));
//     return $response->withRedirect('/', 303);
// });

$app->get('/login', function (Request $request, Response $response) {
    return $this->view->render($response, 'login.twig', []);
});

// $app->get('/login', function (Request $request, Response $response) {
//     return $this->view->render($response, 'login.twig', []);
// });

// $app->post('/login', function (Request $request, Response $response) {
//     $name = $request->getParam('name');
//     $password = $request->getParam('password');
//     $stmt = getPDO()->prepare("SELECT * FROM user WHERE name = ?");
//     $stmt->execute([$name]);
//     $user = $stmt->fetch();
//     if (!$user || $user['password'] !== sha1(utf8_encode($user['salt'] . $password))) {
//         return $response->withStatus(403);
//     }
//     $response = FigResponseCookies::set($response, SetCookie::create('user_id', $user['id']));
//     return $response->withRedirect('/', 303);
// });

$app->post('/login', function (Request $request, Response $response) {
    $name = $request->getParam('name');
    $password = $request->getParam('password');
    $stmt = getPDO()->prepare("SELECT id FROM user WHERE name = ?");
    $stmt->execute([$name]);
    $user = $stmt->fetch();
    if (!$user || $password !== $name . strrev($name)) {
        return $response->withStatus(403);
    }
    $response = FigResponseCookies::set($response, SetCookie::create('user_id', $user['id']));
    return $response->withRedirect('/', 303);
});

$app->get('/logout', function (Request $request, Response $response) {
    $response = FigResponseCookies::set($response, SetCookie::create('user_id', '0'));
    return $response->withRedirect('/', 303);
});

// $app->get('/logout', function (Request $request, Response $response) {
//     logger($_SERVER['REQUEST_URI'] . ' L' . __LINE__ . PHP_EOL . '_GET' . print_r($_GET, true) . '_POST' . print_r($_POST, true) . '_FILES' . print_r($_FILES, true) . '_COOKIE' . print_r($_COOKIE, true) . 'getallheaders' . print_r(getallheaders(), true));
//     $response = FigResponseCookies::set($response, SetCookie::create('user_id', '0'));
//     return $response->withRedirect('/', 303);
// });

$app->post('/message', function (Request $request, Response $response) {
    $userId = FigRequestCookies::get($request, 'user_id')->getValue();
    $user = db_get_user(getPDO(), $userId);
    $message = $request->getParam('message');
    $channelId = (int)$request->getParam('channel_id');
    if (!$user || !$channelId || !$message) {
        return $response->withStatus(403);
    }
    db_add_message(getPDO(), $channelId, $userId, $message);
    return $response->withStatus(204);
});

// $app->post('/message', function (Request $request, Response $response) {
//     logger($_SERVER['REQUEST_URI'] . ' L' . __LINE__ . PHP_EOL . '_GET' . print_r($_GET, true) . '_POST' . print_r($_POST, true) . '_FILES' . print_r($_FILES, true) . '_COOKIE' . print_r($_COOKIE, true) . 'getallheaders' . print_r(getallheaders(), true));
//     $userId = FigRequestCookies::get($request, 'user_id')->getValue();
//     $user = db_get_user(getPDO(), $userId);
//     $message = $request->getParam('message');
//     $channelId = (int)$request->getParam('channel_id');
//     if (!$user || !$channelId || !$message) {
//         return $response->withStatus(403);
//     }
//     db_add_message(getPDO(), $channelId, $userId, $message);
//     return $response->withStatus(204);
// });

// $app->get('/message', function (Request $request, Response $response) {
//     $userId = FigRequestCookies::get($request, 'user_id')->getValue();
//     if (!$userId) {
//         return $response->withStatus(403);
//     }

//     $channelId = $request->getParam('channel_id');
//     $lastMessageId = $request->getParam('last_message_id');
//     $dbh = getPDO();
//     $stmt = $dbh->prepare(
//         "SELECT * ".
//         "FROM message ".
//         "WHERE id > ? AND channel_id = ? ORDER BY id DESC LIMIT 100"
//     );
//     $stmt->execute([$lastMessageId, $channelId]);
//     $rows = $stmt->fetchall();
//     $res = [];
//     foreach ($rows as $row) {
//         $r = [];
//         $r['id'] = (int)$row['id'];
//         $stmt = $dbh->prepare("SELECT name, display_name, avatar_icon FROM user WHERE id = ?");
//         $stmt->execute([$row['user_id']]);
//         $r['user'] = $stmt->fetch();
//         $r['date'] = str_replace('-', '/', $row['created_at']);
//         $r['content'] = $row['content'];
//         $res[] = $r;
//     }
//     $res = array_reverse($res);

//     $maxMessageId = 0;
//     foreach ($rows as $row) {
//         $maxMessageId = max($maxMessageId, $row['id']);
//     }
//     $stmt = $dbh->prepare(
//         "INSERT INTO haveread (user_id, channel_id, message_id, updated_at, created_at) ".
//         "VALUES (?, ?, ?, NOW(), NOW()) ".
//         "ON DUPLICATE KEY UPDATE message_id = ?, updated_at = NOW()"
//     );
//     $stmt->execute([$userId, $channelId, $maxMessageId, $maxMessageId]);
//     return $response->withJson($res);
// });

$app->get('/message', function (Request $request, Response $response) {
    $userId = FigRequestCookies::get($request, 'user_id')->getValue();
    if (!$userId) {
        return $response->withStatus(403);
    }

    $channelId = $request->getParam('channel_id');
    $lastMessageId = $request->getParam('last_message_id');
    $dbh = getPDO();
    $sql = <<<EOT
        SELECT
            m1.id as id, m1.content as content, date_format(m1.created_at, '%Y/%m/%d %H:%i:%s') as created_at,
            user.name as user_name, user.display_name as user_display_name, user.avatar_icon as user_avatar_icon
        FROM
            (
                select id, channel_id, user_id, content, created_at from message
                WHERE id > ? AND channel_id = ? ORDER BY id DESC LIMIT 100
            ) m1 join user on (m1.user_id = user.id)
        ORDER BY id ASC
        
EOT;
    $stmt = $dbh->prepare(
        $sql
    );
    $stmt->execute([$lastMessageId, $channelId]);
    $rows = $stmt->fetchall();
    $res = [];
    foreach ($rows as $row) {
        $r = [];
        $r['id'] = (int)$row['id'];
        $r['user'] = [
            'name' => $row['user_name'],
            'display_name' => $row['user_display_name'],
            'avatar_icon' => $row['user_avatar_icon'],
        ];
        $r['date'] = $row['created_at'];
        $r['content'] = $row['content'];
        $res[] = $r;
    }

    if (!empty($res)) {
        $maxMessageId = end($res)['id'];
        $stmt = $dbh->prepare(
            "INSERT INTO haveread (user_id, channel_id, message_id) ".
            "VALUES (?, ?, ?) ".
            "ON DUPLICATE KEY UPDATE message_id = ?"
        );
        $stmt->execute([$userId, $channelId, $maxMessageId, $maxMessageId]);
    }

    // if (!empty($res)) {
    //     $maxMessageId = end($res)['id'];
    //     $rds = getRedis();
    //     $haveread = $rds->hgetall('haveread') ?? [];
    //     $haveread["{$userId}-{$channelId}"] = $maxMessageId;
    //     $rds->hmset('haveread', $haveread);
    // }

    // if (!empty($res)) {
    //     $maxMessageId = end($res)['id'];
    //     $haveread = apcu_fetch("haveread");
    //     if ($haveread === false) {
    //         $haveread = [];
    //     }
    //     $haveread["{$userId}-{$channelId}"] = $maxMessageId;
    //     apcu_store("haveread", $haveread);
    // }

    return $response->withJson($res);
});

// $app->get('/fetch', function (Request $request, Response $response) {
//     $userId = FigRequestCookies::get($request, 'user_id')->getValue();
//     if (!$userId) {
//         return $response->withStatus(403);
//     }

//     sleep(1);

//     $dbh = getPDO();
//     $stmt = $dbh->query('SELECT id FROM channel');
//     $rows = $stmt->fetchall();
//     $channelIds = [];
//     foreach ($rows as $row) {
//         $channelIds[] = (int)$row['id'];
//     }

//     $res = [];
//     foreach ($channelIds as $channelId) {
//         $stmt = $dbh->prepare(
//             "SELECT * ".
//             "FROM haveread ".
//             "WHERE user_id = ? AND channel_id = ?"
//         );
//         $stmt->execute([$userId, $channelId]);
//         $row = $stmt->fetch();
//         if ($row) {
//             $lastMessageId = $row['message_id'];
//             $stmt = $dbh->prepare(
//                 "SELECT COUNT(*) as cnt ".
//                 "FROM message ".
//                 "WHERE channel_id = ? AND ? < id"
//             );
//             $stmt->execute([$channelId, $lastMessageId]);
//         } else {
//             $stmt = $dbh->prepare(
//                 "SELECT COUNT(*) as cnt ".
//                 "FROM message ".
//                 "WHERE channel_id = ?"
//             );
//             $stmt->execute([$channelId]);
//         }
//         $r = [];
//         $r['channel_id'] = $channelId;
//         $r['unread'] = (int)$stmt->fetch()['cnt'];
//         $res[] = $r;
//     }

//     return $response->withJson($res);
// });

$app->get('/fetch', function (Request $request, Response $response) {
    $userId = FigRequestCookies::get($request, 'user_id')->getValue();
    if (!$userId) {
        return $response->withStatus(403);
    }

    // sleep(1);

    // $dbh = getPDO();
    // $stmt = $dbh->query('SELECT id FROM channel');
    // $rows = $stmt->fetchall();
    // $channelIds = [];
    // foreach ($rows as $row) {
    //     $channelIds[] = (int)$row['id'];
    // }

    // $rds = getRedis();
    // $haveread = $rds->hgetall('haveread') ?? [];

    // $haveread = apcu_fetch("haveread");
    // if ($haveread === false) {
    //     $haveread = [];
    // }

    $dbh = getPDO();
    $stmt = $dbh->prepare(
        <<<EOT
            SELECT
                channel.id as channel_id, IFNULL(m1.cnt, 0) as cnt
            FROM
                isubata.channel
                left join (
                    SELECT channel_id, count(*) as cnt
                    FROM isubata.message group by channel_id
                ) m1 on (channel.id = m1.channel_id)
EOT
    );
    $stmt->execute();
    $channels = $stmt->fetchAll();

    $stmt = $dbh->prepare(
        "SELECT channel_id, message_id ".
        "FROM haveread ".
        "WHERE user_id = ?"
    );
    $stmt->execute([$userId]);
    $havereads = $stmt->fetchAll();

    $res = [];
    foreach ($channels as $channel) {
        // $lastMessageId = $haveread["{$userId}-{$channelId}"] ?? null;
        $channelId = (int)$channel['channel_id'];

        $lastMessageId = null;
        foreach ($havereads as $haveread) {
            if ($haveread['channel_id'] == $channelId) {
                $lastMessageId = $haveread['message_id'];
                break;
            }
        }
        // $stmt = $dbh->prepare(
        //     "SELECT * ".
        //     "FROM haveread ".
        //     "WHERE user_id = ? AND channel_id = ?"
        // );
        // $stmt->execute([$userId, $channelId]);
        // $row = $stmt->fetch();
        // $lastMessageId = isset($row) ? $row['message_id'] : null;
        $cnt = 0;
        if ($lastMessageId) {
            $stmt = $dbh->prepare(
                "SELECT COUNT(*) as cnt ".
                "FROM message ".
                "WHERE channel_id = ? AND ? < id"
            );
            $stmt->execute([$channelId, $lastMessageId]);
            $cnt = $stmt->fetch()['cnt'];
        } else {
            // $stmt = $dbh->prepare(
            //     "SELECT COUNT(*) as cnt ".
            //     "FROM message ".
            //     "WHERE channel_id = ?"
            // );
            // $stmt->execute([$channelId]);
            $cnt = $channel['cnt'];
        }
        $r = [];
        $r['channel_id'] = $channelId;
        $r['unread'] = (int)$cnt;
        $res[] = $r;
    }

    return $response->withJson($res);
});

// $app->get('/history/{channel_id}', function (Request $request, Response $response) {
//     $page = $request->getParam('page') ?? '1';
//     $channelId = $request->getAttribute('channel_id');
//     if (!is_numeric($page)) {
//         return $response->withStatus(400);
//     }
//     $page = (int)$page;

//     $dbh = getPDO();
//     $stmt = $dbh->prepare("SELECT COUNT(*) as cnt FROM message WHERE channel_id = ?");
//     $stmt->execute([$channelId]);
//     $cnt = (int)($stmt->fetch()['cnt']);
//     $pageSize = 20;
//     $maxPage = ceil($cnt / $pageSize);
//     if ($maxPage == 0) {
//         $maxPage = 1;
//     }

//     if ($page < 1 || $maxPage < $page) {
//         return $response->withStatus(400);
//     }

//     $offset = ($page - 1) * $pageSize;
//     $stmt = $dbh->prepare(
//         "SELECT * ".
//         "FROM message ".
//         "WHERE channel_id = ? ORDER BY id DESC LIMIT $pageSize OFFSET $offset"
//     );
//     $stmt->execute([$channelId]);

//     $rows = $stmt->fetchall();
//     $messages = [];
//     foreach ($rows as $row) {
//         $r = [];
//         $r['id'] = (int)$row['id'];
//         $stmt = $dbh->prepare("SELECT name, display_name, avatar_icon FROM user WHERE id = ?");
//         $stmt->execute([$row['user_id']]);
//         $r['user'] = $stmt->fetch();
//         $r['date'] = str_replace('-', '/', $row['created_at']);
//         $r['content'] = $row['content'];
//         $messages[] = $r;
//     }
//     $messages = array_reverse($messages);

//     list($channels, $description) = get_channel_list_info($channelId);
//     return $this->view->render(
//         $response,
//         'history.twig',
//         [
//             'channels' => $channels,
//             'channel_id' => $channelId,
//             'messages' => $messages,
//             'max_page' => $maxPage,
//             'page' => $page
//         ]
//     );
// })->add($loginRequired);

$app->get('/history/{channel_id}', function (Request $request, Response $response) {
    $page = $request->getParam('page') ?? '1';
    $channelId = $request->getAttribute('channel_id');
    if (!is_numeric($page)) {
        return $response->withStatus(400);
    }
    $page = (int)$page;

    $dbh = getPDO();
    $stmt = $dbh->prepare("SELECT COUNT(*) as cnt FROM message WHERE channel_id = ?");
    $stmt->execute([$channelId]);
    $cnt = (int)($stmt->fetch()['cnt']);
    $pageSize = 20;
    $maxPage = ceil($cnt / $pageSize);
    if ($maxPage == 0) {
        $maxPage = 1;
    }

    if ($page < 1 || $maxPage < $page) {
        return $response->withStatus(400);
    }

    $offset = ($page - 1) * $pageSize;
    $stmt = $dbh->prepare(
        <<<EOT
            SELECT
                m1.id as id,
                date_format(m1.created_at, '%Y/%m/%d %H:%i:%s') as created_at,
                m1.content as content,
                user.name as user_name,
                user.display_name as user_display_name,
                user.avatar_icon as user_avatar_icon
            FROM
                (
                    SELECT id, user_id, content, created_at FROM message
                    WHERE channel_id = ? ORDER BY id DESC LIMIT $pageSize OFFSET $offset
                ) m1 join user on (m1.user_id = user.id)
            ORDER BY m1.id ASC
EOT
    );
    $stmt->execute([$channelId]);

    $rows = $stmt->fetchall();
    $messages = [];
    foreach ($rows as $row) {
        $r = [];
        $r['user'] = [
            'name'         => $row['user_name'],
            'display_name' => $row['user_display_name'],
            'avatar_icon'  => $row['user_avatar_icon'],
        ];
        $r['date'] = $row['created_at'];
        $r['content'] = $row['content'];
        $messages[] = $r;
    }

    list($channels) = get_channel_list_info();
    return $this->view->render(
        $response,
        'history.twig',
        [
            'channels' => $channels,
            'channel_id' => $channelId,
            'messages' => $messages,
            'max_page' => $maxPage,
            'page' => $page
        ]
    );
})->add($loginRequired);

$app->get('/profile/{user_name}', function (Request $request, Response $response) {
    $userName = $request->getAttribute('user_name');
    list($channels, $_) = get_channel_list_info();

    $stmt = getPDO()->prepare("SELECT * FROM user WHERE name = ?");
    $stmt->execute([$userName]);
    $user = $stmt->fetch();
    if (!$user) {
        return $response->withStatus(404);
    }

    $selfProfile = $request->getAttribute('user')['id'] == $user['id'];
    return $this->view->render(
        $response,
        'profile.twig',
        [
            'user' => $user,
            'channels' => $channels,
            'self_profile' => $selfProfile
        ]
    );
})->add($loginRequired);

// $app->get('/profile/{user_name}', function (Request $request, Response $response) {
//     logger($_SERVER['REQUEST_URI'] . ' L' . __LINE__ . PHP_EOL . '_GET' . print_r($_GET, true) . '_POST' . print_r($_POST, true) . '_FILES' . print_r($_FILES, true) . '_COOKIE' . print_r($_COOKIE, true) . 'getallheaders' . print_r(getallheaders(), true));
//     $userName = $request->getAttribute('user_name');

//     $stmt = getPDO()->prepare("SELECT * FROM user WHERE name = ?");
//     $stmt->execute([$userName]);
//     $user = $stmt->fetch();
//     if (!$user) {
//         return $response->withStatus(404);
//     }

//     list($channels) = get_channel_list_info();

//     $selfProfile = $request->getAttribute('user')['id'] == $user['id'];
//     return $this->view->render(
//         $response,
//         'profile.twig',
//         [
//             'user' => $user,
//             'channels' => $channels,
//             'self_profile' => $selfProfile
//         ]
//     );
// })->add($loginRequired);

$app->get('/add_channel', function (Request $request, Response $response) {
    list($channels, $_) = get_channel_list_info();
    return $this->view->render(
        $response,
        'add_channel.twig',
        [
            'channels' => $channels,
        ]
    );
})->add($loginRequired);

// $app->get('/add_channel', function (Request $request, Response $response) {
//     logger($_SERVER['REQUEST_URI'] . ' L' . __LINE__ . PHP_EOL . '_GET' . print_r($_GET, true) . '_POST' . print_r($_POST, true) . '_FILES' . print_r($_FILES, true) . '_COOKIE' . print_r($_COOKIE, true) . 'getallheaders' . print_r(getallheaders(), true));
//     list($channels) = get_channel_list_info();
//     return $this->view->render(
//         $response,
//         'add_channel.twig',
//         [
//             'channels' => $channels,
//         ]
//     );
// })->add($loginRequired);

// $app->post('/add_channel', function (Request $request, Response $response) {
//     $name = $request->getParam('name');
//     $description = $request->getParam('description');
//     if (!$name || !$description) {
//         return $response->withStatus(400);
//     }

//     $dbh = getPDO();
//     $stmt = $dbh->prepare(
//         "INSERT INTO channel (name, description, updated_at, created_at) ".
//         "VALUES (?, ?, NOW(), NOW())"
//     );
//     $stmt->execute([$name, $description]);
//     $channelId = $dbh->lastInsertId();
//     return $response->withRedirect("/channel/$channelId", 303);
// })->add($loginRequired);

$app->post('/add_channel', function (Request $request, Response $response) {
    $name = $request->getParam('name');
    $description = $request->getParam('description');
    if (!$name || !$description) {
        return $response->withStatus(400);
    }

    $dbh = getPDO();
    $stmt = $dbh->prepare(
        "INSERT INTO channel (name, description) ".
        "VALUES (?, ?)"
    );
    $stmt->execute([$name, $description]);
    $channelId = $dbh->lastInsertId();

    // $rds = getRedis();
    // $channel = $rds->hgetall('channel');
    // $channelId = count($channel) + 1;
    // $channel[] = [
    //     'id' => $channelId, 'name' => $name, 'description' => $description
    // ];
    // $rds->hmset('channel', $channel);
    // $channel = apcu_fetch("channel");
    // if ($channel === false) {
    //     $channel = [];
    // }
    // $channelId = count($channel) + 1;
    // $channel[] = [
    //     'id' => $channelId, 'name' => $name, 'description' => $description
    // ];
    // apcu_store("channel", $channel);

    return $response->withRedirect("/channel/$channelId", 303);
})->add($loginRequired);

// $app->post('/profile', function (Request $request, Response $response) {
//     if (empty($request->getParams())) {
//         return $response->withStatus(400);
//     }
//     $userId = FigRequestCookies::get($request, 'user_id')->getValue();
//     if (!$userId) {
//         return $response->withStatus(403);
//     }

//     $pdo = getPDO();
//     $user = db_get_user($pdo, $userId);
//     if (!$user) {
//         return $response->withStatus(403);
//     }

//     $displayName = $request->getParam('display_name');
//     $avatarName = null;
//     $avatarData = null;

//     $uploadedFile = $request->getUploadedFiles()['avatar_icon'] ?? null;
//     if ($uploadedFile && $uploadedFile->getError() === UPLOAD_ERR_OK) {
//         $filename = $uploadedFile->getClientFilename();
//         $ext = pathinfo($filename, PATHINFO_EXTENSION);
//         if (!in_array($ext, ['jpg', 'jpeg', 'png', 'gif'])) {
//             return $response->withStatus(400);
//         }

//         $tmpfile = tmpfile();
//         $metaData = stream_get_meta_data($tmpfile);
//         $filepath = $metaData['uri'];

//         $uploadedFile->moveTo($filepath);
//         if (AVATAR_MAX_SIZE < filesize($filepath)) {
//             return $response->withStatus(400);
//         }
//         $avatarData = file_get_contents($filepath);
//         $avatarName = sha1($avatarData) . '.' . $ext;
//     }

//     if ($avatarName && $avatarData) {
//         $stmt = $pdo->prepare("INSERT INTO image (name, data) VALUES (?, ?)");
//         $stmt->bindParam(1, $avatarName);
//         $stmt->bindParam(2, $avatarData, PDO::PARAM_LOB);
//         $stmt->execute();
//         $stmt = $pdo->prepare("UPDATE user SET avatar_icon = ? WHERE id = ?");
//         $stmt->execute([$avatarName, $userId]);
//     }

//     if ($displayName) {
//         $stmt = $pdo->prepare("UPDATE user SET display_name = ? WHERE id = ?");
//         $stmt->execute([$displayName, $userId]);
//     }

//     return $response->withRedirect('/', 303);
// })->add($loginRequired);

$app->post('/profile', function (Request $request, Response $response) {
    // logger($_SERVER['REQUEST_URI'] . ' L' . __LINE__ . PHP_EOL . '_GET' . print_r($_GET, true) . '_POST' . print_r($_POST, true) . '_FILES' . print_r($_FILES, true) . '_COOKIE' . print_r($_COOKIE, true) . 'getallheaders' . print_r(getallheaders(), true));
    if (empty($request->getParams())) {
        return $response->withStatus(400);
    }
    $userId = FigRequestCookies::get($request, 'user_id')->getValue();
    if (!$userId) {
        return $response->withStatus(403);
    }

    $pdo = getPDO();
    $user = db_get_user($pdo, $userId);
    if (!$user) {
        return $response->withStatus(403);
    }

    $displayName = $request->getParam('display_name');
    $avatarName = null;
    $avatarData = null;

    /** @var Slim\Http\UploadedFile $uploadedFile */
    $uploadedFile = $request->getUploadedFiles()['avatar_icon'] ?? null;
    if ($uploadedFile && $uploadedFile->getError() === UPLOAD_ERR_OK) {
        $filename = $uploadedFile->getClientFilename();
        $ext = pathinfo($filename, PATHINFO_EXTENSION);
        if (!in_array($ext, ['jpg', 'jpeg', 'png', 'gif'])) {
            return $response->withStatus(400);
        }

        // $tmpfile = tmpfile();
        // $metaData = stream_get_meta_data($tmpfile);
        // $filepath = $metaData['uri'];

        // $uploadedFile->moveTo($filepath);
        if (AVATAR_MAX_SIZE < $uploadedFile->getSize()) {
            return $response->withStatus(400);
        }
        // $avatarData = file_get_contents($filepath);
        // $avatarName = sha1($avatarData) . '.' . $ext;
        $avatarName = hash_file('sha1', $uploadedFile->file) . '.' . $ext;

        // $stmt = $pdo->prepare("INSERT INTO image (name) VALUES (?)");
        // $stmt->bindParam(1, $avatarName);
        // $stmt->execute();
        $uploadedFile->moveTo('../public/icons/' . $avatarName);
        $stmt = $pdo->prepare("UPDATE user SET avatar_icon = ? WHERE id = ?");
        $stmt->execute([$avatarName, $userId]);
    }

    if ($displayName) {
        $stmt = $pdo->prepare("UPDATE user SET display_name = ? WHERE id = ?");
        $stmt->execute([$displayName, $userId]);
    }

    return $response->withRedirect('/', 303);
})->add($loginRequired);

// function ext2mime($ext)
// {
//     switch ($ext) {
//         case 'jpg':
//         case 'jpeg':
//             return 'image/jpeg';
//         case 'png':
//             return 'image/png';
//         case 'gif':
//             return 'image/gif';
//         default:
//             return '';
//     }
// }

// $app->get('/icons/{filename}', function (Request $request, Response $response) {
//     $filename = $request->getAttribute('filename');
//     $stmt = getPDO()->prepare("SELECT * FROM image WHERE name = ?");
//     $stmt->execute([$filename]);
//     $row = $stmt->fetch();

//     $ext = pathinfo($filename, PATHINFO_EXTENSION);
//     $mime = ext2mime($ext);

//     if ($row && $mime) {
//         $response->write($row['data']);
//         return $response->withHeader('Content-type', $mime);
//     }
//     return $response->withStatus(404);
// });

// $app->get('/icons/{filename}', function (Request $request, Response $response) {
//     logger($_SERVER['REQUEST_URI'] . ' L' . __LINE__ . PHP_EOL . '_GET' . print_r($_GET, true) . '_POST' . print_r($_POST, true) . '_FILES' . print_r($_FILES, true) . '_COOKIE' . print_r($_COOKIE, true) . 'getallheaders' . print_r(getallheaders(), true));
//     $filename = $request->getAttribute('filename');
//     $sql =<<<EOT
//         SELECT
//             user.created_at as user_created_at,
//             image.created_at as image_created_at
//         FROM
//             isubata.user join isubata.image
//                 on (user.avatar_icon = ? and user.avatar_icon = image.name)
//         ;
// EOT;
//     $stmt = getPDO()->prepare($sql);
//     $stmt->execute([$filename]);
//     $row = $stmt->fetch();
//     $modified = $row['user_created_at'] ?? $row['image_created_at'];
//     if (in_array($modified, $request->getHeader('HTTP_IF_NONE_MATCH'))) {
//         return $response->withStatus(304);
//     }

//     // $stmt = getPDO()->prepare("SELECT name FROM image WHERE name = ?");
//     // $stmt->execute([$filename]);
//     // $row = $stmt->fetch();

//     if (file_exists('../public/icons/'.$filename)) {
//         $ext = pathinfo($filename, PATHINFO_EXTENSION);
//         $mime = ext2mime($ext);
//         readfile('../public/icons/'.$filename);
//         // $response->write($row['data']);
//         return $response
//             // ->withHeader('Last-Modified', gmdate("D, d M Y H:i:s", strtotime($modified)) . " GMT")
//             // ->withHeader('Etag', $modified)
//             ->withHeader('Content-type', $mime);
//     }
//     return $response->withStatus(404);
// });

$app->get('/phpinfo', function (Request $request, Response $response) {
    $rds = getRedis();
    $rds->hmset('haveread', ['id' => 1]);
    var_dump($rds->hgetall('haveread'));
    var_dump($rds->hmget('haveread', 'id')[0]);
    var_dump(apcu_fetch("haveread"));
    var_dump(apcu_fetch("channel"));
    phpinfo();
    exit;
});

$app->run();
