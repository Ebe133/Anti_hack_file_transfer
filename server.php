<?php

$usersFile = __DIR__ . "/users.json";

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
            die("Gebruikersnaam bestaat al");
        }

        $users[$username] =
            password_hash(
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

        echo "Account aangemaakt";
        break;

    case "login":

        if (!isset($users[$username]))
        {
            die("Onbekende gebruiker");
        }

        if (
            !password_verify(
                $password,
                $users[$username]
            )
        )
        {
            die("Verkeerd wachtwoord");
        }

        $token =
            bin2hex(
                random_bytes(16)
            );

        $_SESSION["tokens"][$token] = [
            "username" => $username,
            "ip" => $_SERVER["REMOTE_ADDR"]
        ];

        echo json_encode([
            "success" => true,
            "token" => $token
        ]);

        break;

    case "lookup":

        $token =
            $_POST["token"] ?? "";

        if (
            !isset(
                $_SESSION["tokens"][$token]
            )
        )
        {
            die("Geen geldig token");
        }

        echo json_encode([
            "success" => true
        ]);

        break;

    default:

        echo "Gebruik register, login of lookup";
} 