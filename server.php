<?php

$usersFile = __DIR__ . "/users.json";
$logFile = __DIR__ . "/logs/system.log";

if (!file_exists(__DIR__ . "/logs"))
{
    mkdir(__DIR__ . "/logs", 0777, true);
}

function writeLog($message)
{
    global $logFile;

    $line =
        "[" . date("Y-m-d H:i:s") . "] "
        . $message
        . PHP_EOL;

    file_put_contents(
        $logFile,
        $line,
        FILE_APPEND
    );
}

if (!file_exists($usersFile))
{
    file_put_contents($usersFile, "{}");
}

$users = json_decode(
    file_get_contents($usersFile),
    true
);

$action = $_GET["action"] ?? "";

$username = $_POST["username"] ?? "";
$password = $_POST["password"] ?? "";

session_start();

if (!isset($_SESSION["tokens"]))
{
    $_SESSION["tokens"] = [];
}

switch ($action)
{
    case "register":

        if (isset($users[$username]))
        {
            echo "Deze gebruikersnaam bestaat al.";
            exit;
        }

        $users[$username] = password_hash(
            $password,
            PASSWORD_BCRYPT
        );

        file_put_contents(
            $usersFile,
            json_encode(
                $users,
                JSON_PRETTY_PRINT
            )
        );

        writeLog("ACCOUNT AANGEMAAKT | user=$username");

        echo "Account succesvol aangemaakt.";
        break;

    case "login":

        if (!isset($users[$username]))
        {
            writeLog("MISLUKTE LOGIN | user=$username");

            echo "Gebruikersnaam of wachtwoord is onjuist.";
            exit;
        }

        if (!password_verify($password, $users[$username]))
        {
            writeLog("MISLUKTE LOGIN | user=$username");

            echo "Gebruikersnaam of wachtwoord is onjuist.";
            exit;
        }

        $token = bin2hex(
            random_bytes(16)
        );

        $_SESSION["tokens"][$token] = [
            "username" => $username,
            "ip" => $_SERVER["REMOTE_ADDR"]
        ];

        writeLog("LOGIN SUCCESVOL | user=$username");

        echo json_encode([
            "success" => true,
            "token" => $token
        ]);

        break;

    case "lookup":

        $token = $_POST["token"] ?? "";

        if (!isset($_SESSION["tokens"][$token]))
        {
            writeLog("ONGELDIGE LOOKUP | token=$token");

            echo "Je bent niet ingelogd.";
            exit;
        }

        echo json_encode([
            "success" => true
        ]);

        break;

    default:

        echo "Gebruik register, login of lookup.";
} 