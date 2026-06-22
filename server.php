<?php
/**
 * Day 3: PHP Central Auth & Directory Server (server.php)
 *
 * Dual mode:
 * - Web mode (PHP-FPM/Apache): JSON API for hosted central server endpoints.
 * - CLI mode: legacy TCP socket daemon for local development/tests.
 */

error_reporting(E_ALL);
ini_set('display_errors', '1');

$userDbFile = __DIR__ . '/users.json';
$sessionDbFile = __DIR__ . '/sessions.json';

if (!file_exists($userDbFile)) {
    file_put_contents($userDbFile, json_encode([]));
}
if (!file_exists($sessionDbFile)) {
    file_put_contents($sessionDbFile, json_encode([]));
}

function loadJsonFile(string $filePath, array $fallback = []): array {
    if (!file_exists($filePath)) {
        return $fallback;
    }

    $raw = file_get_contents($filePath);
    if ($raw === false || $raw === '') {
        return $fallback;
    }

    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : $fallback;
}

function saveJsonFile(string $filePath, array $data): void {
    file_put_contents($filePath, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

function jsonResponse(array $data, int $statusCode = 200): void {
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
}

function valideerSessie(string $token, array $sessies): bool {
    foreach ($sessies as $info) {
        if (isset($info['token']) && hash_equals((string)$info['token'], $token)) {
            return true;
        }
    }
    return false;
}

function verwerkActie(array $data, string $ip, array &$gebruikers, array &$sessies): array {
    // Hack-detectie op gebruikersnaam (indien aanwezig)
    if (isset($data['username'])) {
        $checkUser = trim((string)$data['username']);
        if ($checkUser !== '' && !preg_match('/^[a-zA-Z0-9_\-]+$/', $checkUser)) {
            return ['status' => 'error', 'message' => 'Gebruikersnaam bevat ongeldige tekens'];
        }
    }

    // Hack-detectie op session_token (indien aanwezig)
    if (isset($data['session_token'])) {
        $checkToken = trim((string)$data['session_token']);
        if ($checkToken !== '' && !preg_match('/^[0-9a-fA-F]{32}$/', $checkToken)) {
            return ['status' => 'error', 'message' => 'Ongeldig sessietoken'];
        }
    }

    // Hack-detectie op address (indien aanwezig)
    if (isset($data['address'])) {
        $checkAddress = trim((string)$data['address']);
        if ($checkAddress !== '' && preg_match('/[\'"<>;()\\$]/', $checkAddress)) {
            return ['status' => 'error', 'message' => 'Ongeldig adresformaat'];
        }
    }

    if (!isset($data['action'])) {
        return ['status' => 'error', 'message' => 'Ongeldig verzoekformaat'];
    }

    $actie = (string)$data['action'];

    switch ($actie) {
        case 'register':
            $user = trim((string)($data['username'] ?? ''));
            $pass = (string)($data['password'] ?? '');

            if ($user === '' || $pass === '') {
                return ['status' => 'error', 'message' => 'Gebruikersnaam en wachtwoord zijn verplicht'];
            }

            if (strlen($user) < 3 || strlen($user) > 32) {
                return ['status' => 'error', 'message' => 'Gebruikersnaam moet tussen 3 en 32 tekens bevatten'];
            }

            $gereserveerd = ['admin', 'root', 'system', 'anonymous', 'administrator', 'nexus', 'server', 'directory'];
            if (in_array(strtolower($user), $gereserveerd, true)) {
                return ['status' => 'error', 'message' => 'Gereserveerde gebruikersnaam is niet toegestaan'];
            }

            if (isset($gebruikers[$user])) {
                return ['status' => 'error', 'message' => 'Gebruikersnaam bestaat al'];
            }

            $gebruikers[$user] = password_hash($pass, PASSWORD_BCRYPT);
            return ['status' => 'success', 'message' => 'Account aangemaakt'];

        case 'login':
            $user = trim((string)($data['username'] ?? ''));
            $pass = (string)($data['password'] ?? '');
            $adres = trim((string)($data['address'] ?? ''));

            if (!isset($gebruikers[$user]) || !password_verify($pass, (string)$gebruikers[$user])) {
                return ['status' => 'error', 'message' => 'Ongeldige inloggegevens'];
            }

            if ($adres !== '' && !preg_match('/^[a-z2-7]{52}\.b32\.i2p$/', $adres)) {
                return ['status' => 'error', 'message' => 'Ongeldig I2P-adres formaat'];
            }

            $token = bin2hex(random_bytes(16));
            $sessies[$user] = [
                'address' => $adres,
                'token' => $token,
                'updated_at' => time(),
                'ip' => $ip,
            ];

            return [
                'status' => 'success',
                'session_token' => $token,
            ];

        case 'update_address':
            $mijnToken = (string)($data['session_token'] ?? '');
            $adres = trim((string)($data['address'] ?? ''));

            if (!valideerSessie($mijnToken, $sessies)) {
                return ['status' => 'error', 'message' => 'Sessie is ongeldig of verlopen'];
            }

            if ($adres === '' || !preg_match('/^[a-z2-7]{52}\.b32\.i2p$/', $adres)) {
                return ['status' => 'error', 'message' => 'Geldig I2P Base32 adres (.b32.i2p) is verplicht'];
            }

            foreach ($sessies as &$info) {
                if (isset($info['token']) && hash_equals((string)$info['token'], $mijnToken)) {
                    $info['address'] = $adres;
                    $info['updated_at'] = time();
                    return ['status' => 'success', 'message' => 'Adres succesvol bijgewerkt'];
                }
            }
            unset($info);

            return ['status' => 'error', 'message' => 'Sessie niet gevonden'];

        case 'lookup':
            $mijnToken = (string)($data['session_token'] ?? '');
            $doelGebruiker = trim((string)($data['target'] ?? ''));

            if ($doelGebruiker === '' || !preg_match('/^[a-zA-Z0-9_\-]+$/', $doelGebruiker)) {
                return ['status' => 'error', 'message' => 'Gebruikersnaam bevat ongeldige tekens'];
            }

            if (!valideerSessie($mijnToken, $sessies)) {
                return ['status' => 'error', 'message' => 'Sessie is ongeldig of verlopen'];
            }

            if (!isset($sessies[$doelGebruiker]) || empty($sessies[$doelGebruiker]['address'])) {
                return ['status' => 'error', 'message' => "Gebruiker '$doelGebruiker' is offline of I2P is nog niet gereed"];
            }

            $sessies[$doelGebruiker]['updated_at'] = time();

            return [
                'status' => 'success',
                'address' => $sessies[$doelGebruiker]['address'],
            ];

        default:
            return ['status' => 'error', 'message' => 'Onbekende actie'];
    }
}

// ---------------------------
// Web mode: hosted JSON API
// ---------------------------
if (PHP_SAPI !== 'cli') {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

    if ($method !== 'POST') {
        jsonResponse([
            'status' => 'error',
            'message' => 'Gebruik POST met JSON payload.'
        ], 405);
        exit;
    }

    $raw = file_get_contents('php://input');
    $data = json_decode($raw ?? '', true);

    if (!is_array($data)) {
        jsonResponse(['status' => 'error', 'message' => 'Ongeldig JSON-formaat'], 400);
        exit;
    }

    $gebruikers = loadJsonFile($userDbFile, []);
    $sessies = loadJsonFile($sessionDbFile, []);

    // Verwijder zeer oude sessies (24 uur)
    $now = time();
    foreach ($sessies as $user => $info) {
        $updatedAt = isset($info['updated_at']) ? (int)$info['updated_at'] : 0;
        if ($updatedAt > 0 && ($now - $updatedAt) > 86400) {
            unset($sessies[$user]);
        }
    }

    $response = verwerkActie($data, $ip, $gebruikers, $sessies);

    saveJsonFile($userDbFile, $gebruikers);
    saveJsonFile($sessionDbFile, $sessies);

    jsonResponse($response, $response['status'] === 'success' ? 200 : 400);
    exit;
}

// ---------------------------------
// CLI mode: legacy socket auth node
// ---------------------------------
if (!extension_loaded('sockets')) {
    fwrite(STDERR, "PHP sockets extensie ontbreekt in CLI mode.\n");
    exit(1);
}

$poort = isset($argv[1]) ? (int)$argv[1] : 8000;
$actieveSessies = [];

$server = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
if ($server === false) {
    die("Kan socket niet maken: " . socket_strerror(socket_last_error()) . "\n");
}

socket_set_option($server, SOL_SOCKET, SO_REUSEADDR, 1);

if (socket_bind($server, '0.0.0.0', $poort) === false) {
    die("Kan socket niet binden op poort $poort: " . socket_strerror(socket_last_error($server)) . "\n");
}

if (socket_listen($server, 10) === false) {
    die("Kan niet luisteren op socket: " . socket_strerror(socket_last_error($server)) . "\n");
}

echo "Centrale PHP Directory Server gestart op poort $poort...\n";

while (true) {
    $clientSocket = socket_accept($server);
    if ($clientSocket === false) {
        continue;
    }

    socket_getpeername($clientSocket, $clientIp);
    socket_set_option($clientSocket, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 5, 'usec' => 0]);
    socket_set_option($clientSocket, SOL_SOCKET, SO_SNDTIMEO, ['sec' => 5, 'usec' => 0]);

    try {
        behandelVerbinding($clientSocket, (string)$clientIp, $userDbFile, $actieveSessies);
    } catch (Exception $e) {
        echo "Fout bij afhandeling: " . $e->getMessage() . "\n";
        socket_close($clientSocket);
    }
}

function behandelVerbinding(mixed $socket, string $ip, string $dbFile, array &$sessies): void {
    $verzoek = leesRegel($socket);
    if ($verzoek === false) {
        socket_close($socket);
        return;
    }

    $data = json_decode($verzoek, true);
    if (!is_array($data)) {
        stuurAntwoord($socket, ['status' => 'error', 'message' => 'Ongeldig JSON-formaat']);
        socket_close($socket);
        return;
    }

    $gebruikers = loadJsonFile($dbFile, []);
    $response = verwerkActie($data, $ip, $gebruikers, $sessies);
    saveJsonFile($dbFile, $gebruikers);

    stuurAntwoord($socket, $response);
    socket_close($socket);
}

function leesRegel(mixed $socket): string|false {
    $buffer = '';
    $maxLen = 4096;

    while (strlen($buffer) < $maxLen) {
        $chunk = @socket_read($socket, 1024);
        if ($chunk === false || $chunk === '') {
            return false;
        }

        $buffer .= $chunk;
        $nlPos = strpos($buffer, "\n");
        if ($nlPos !== false) {
            return substr($buffer, 0, $nlPos);
        }
    }

    return false;
}

function stuurAntwoord(mixed $socket, array $data): void {
    $res = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
    @socket_write($socket, $res);
}
?>
