<?php
session_start();

$users = json_decode(file_get_contents("users.json"), true);

$username = $_POST['username'];
$password = $_POST['password'];

foreach($users as $user)
{
    if($user['username'] === $username &&
       password_verify($password, $user['passwordHash']))
    {
        $token = bin2hex(random_bytes(32));

        $_SESSION['tokens'][$token] = $username;

        echo json_encode([
            "success" => true,
            "token" => $token
        ]);

        exit;
    }
}

echo json_encode([
    "success" => false
]);