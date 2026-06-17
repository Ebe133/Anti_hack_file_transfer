<?php
session_start();

$token = $_POST['token'];

if(isset($_SESSION['tokens'][$token]))
{
    echo json_encode([
        "valid" => true
    ]);
}
else
{
    echo json_encode([
        "valid" => false
    ]);
} 