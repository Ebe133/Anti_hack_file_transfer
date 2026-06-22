<?php
/**
 * Day 3: PHP Central Auth & Directory Server (server.php)
 * 
 * Dit script fungeert als een anonieme lookup- en inlogserver.
 * - Slaat accounts (username -> bcrypt hash) persistent op in users.json.
 * - Slaat actieve inlogsessies (username -> I2P destination) UITSLUITEND op in het RAM-geheugen (in-memory).
 * - Bevat geen encryptiesleutels en is niet betrokken bij de bestandsoverdracht zelf.
 */

error_reporting(E_ALL);
ini_set('display_errors', '1');

if (!extension_loaded('sockets')) {
    dl('php_sockets.dll');
}

$poort = isset($argv[1]) ? (int)$argv[1] : 8000;
$userDbFile = __DIR__ . '/users.json';

// In-memory array voor actieve online sessies: username -> [address, token]
$actieveSessies = [];
// In-memory array voor bijhouden mislukte inlogpogingen per IP (voor brute-force detectie)
$mislukteInlogs = [];

if (!file_exists($userDbFile)) {
    file_put_contents($userDbFile, json_encode([]));
}

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
    if ($clientSocket !== false) {
        socket_getpeername($clientSocket, $clientIp);
        try {
            behandelVerbinding($clientSocket, $clientIp, $userDbFile, $actieveSessies, $mislukteInlogs);
        } catch (Exception $e) {
            echo "Fout bij afhandeling: " . $e->getMessage() . "\n";
            socket_close($clientSocket);
        }
    }
}

/**
 * Behandelt inkomende registratie-, login- en lookup-verzoeken van peers.
 */
function behandelVerbinding($socket, $ip, $dbFile, &$sessies, &$mislukteInlogs) {
    $verzoek = leesRegel($socket);
    if ($verzoek === false) {
        socket_close($socket);
        return;
    }
    
    $data = json_decode($verzoek, true);
    if ($verzoek !== '' && $data === null) {
        echo "[$ip] [HACK POGING] Ongeldige JSON-payload of HTTP-probe ontvangen: " . json_encode($verzoek) . "\n";
        stuurAntwoord($socket, ['status' => 'error', 'message' => 'Ongeldig JSON-formaat']);
        return;
    }
    
    if (!$data || !isset($data['action'])) {
        echo "[$ip] Ongeldig verzoekformaat of actie ontbreekt\n";
        stuurAntwoord($socket, ['status' => 'error', 'message' => 'Ongeldig verzoekformaat']);
        return;
    }
    
    // Hack-detectie op gebruikersnaam (indien aanwezig)
    if (isset($data['username'])) {
        $checkUser = trim($data['username']);
        if (!empty($checkUser) && !preg_match('/^[a-zA-Z0-9_\-]+$/', $checkUser)) {
            echo "[$ip] [HACK POGING] Verdachte/ongeldige tekens in gebruikersnaam: '" . $checkUser . "'\n";
            stuurAntwoord($socket, ['status' => 'error', 'message' => 'Gebruikersnaam bevat ongeldige tekens']);
            return;
        }
    }
    
    // Hack-detectie op session_token (indien aanwezig)
    if (isset($data['session_token'])) {
        $checkToken = trim($data['session_token']);
        if (!empty($checkToken) && !preg_match('/^[0-9a-fA-F]{32}$/', $checkToken)) {
            echo "[$ip] [HACK POGING] Ongeldig sessietoken formaat gedetecteerd: '" . $checkToken . "'\n";
            stuurAntwoord($socket, ['status' => 'error', 'message' => 'Ongeldig sessietoken']);
            return;
        }
    }
    
    // Hack-detectie op address (indien aanwezig)
    if (isset($data['address'])) {
        $checkAddress = trim($data['address']);
        if (!empty($checkAddress) && preg_match('/[\'"<>;()\\\$]/', $checkAddress)) {
            echo "[$ip] [HACK POGING] Mogelijk injectie-payload in adres gedetecteerd: '" . $checkAddress . "'\n";
            stuurAntwoord($socket, ['status' => 'error', 'message' => 'Ongeldig adresformaat']);
            return;
        }
    }
    
    $actie = $data['action'];
    $gebruikers = json_decode(file_get_contents($dbFile), true);
    
    switch ($actie) {
        case 'register':
            // Registreer een nieuwe gebruiker met bcrypt
            $user = trim($data['username'] ?? '');
            $pass = $data['password'] ?? '';
            
            if (empty($user) || empty($pass)) {
                echo "[$ip] Registratie mislukt: Gebruikersnaam of wachtwoord leeg\n";
                stuurAntwoord($socket, ['status' => 'error', 'message' => 'Gebruikersnaam en wachtwoord zijn verplicht']);
                break;
            }
            if (isset($gebruikers[$user])) {
                echo "[$ip] Registratie mislukt: Gebruikersnaam '$user' bestaat al\n";
                stuurAntwoord($socket, ['status' => 'error', 'message' => 'Gebruikersnaam bestaat al']);
                break;
            }
            
            // Wachtwoord beveiligen met bcrypt
            $gebruikers[$user] = password_hash($pass, PASSWORD_BCRYPT);
            file_put_contents($dbFile, json_encode($gebruikers, JSON_PRETTY_PRINT));
            
            echo "[$ip] Gebruiker geregistreerd: $user\n";
            stuurAntwoord($socket, ['status' => 'success', 'message' => 'Account aangemaakt']);
            break;
            
        case 'login':
            // Peer logt in en registreert zijn I2P destination (.b32.i2p) of IP:poort
            $user = trim($data['username'] ?? '');
            $pass = $data['password'] ?? '';
            $adres = trim($data['address'] ?? '');
            
            if (!isset($gebruikers[$user]) || !password_verify($pass, $gebruikers[$user])) {
                if (!isset($mislukteInlogs[$ip])) {
                    $mislukteInlogs[$ip] = 0;
                }
                $mislukteInlogs[$ip]++;
                
                if ($mislukteInlogs[$ip] >= 5) {
                    echo "[$ip] [HACK POGING] Brute-force gedetecteerd voor gebruiker: $user (poging " . $mislukteInlogs[$ip] . ")\n";
                } else {
                    echo "[$ip] Mislukte inlogpoging voor: $user\n";
                }
                stuurAntwoord($socket, ['status' => 'error', 'message' => 'Ongeldige inloggegevens']);
                break;
            }
            
            if (empty($adres)) {
                echo "[$ip] Inloggen mislukt voor '$user': adres of I2P-bestemming ontbreekt\n";
                stuurAntwoord($socket, ['status' => 'error', 'message' => 'Adres of I2P-bestemming verplicht']);
                break;
            }
            
            // Genereer uniek sessietoken en sla sessie uitsluitend in-memory (RAM) op
            $token = bin2hex(random_bytes(16));
            $sessies[$user] = [
                'address' => $adres,
                'token' => $token
            ];
            
            // Reset mislukte inlogpogingen bij succesvolle inlog
            $mislukteInlogs[$ip] = 0;
            
            echo "[$ip] Gebruiker ingelogd: $user op adres: $adres\n";
            stuurAntwoord($socket, [
                'status' => 'success',
                'session_token' => $token
            ]);
            break;
            
        case 'lookup':
            // Zoek anonieme peer op via zijn gebruikersnaam
            $mijnToken = $data['session_token'] ?? '';
            $doelGebruiker = trim($data['target'] ?? '');
            
            // Valideer of de opzoeker een geldige actieve sessie heeft in het geheugen
            if (!valideerSessie($mijnToken, $sessies)) {
                echo "[$ip] Lookup mislukt: ongeldig of verlopen sessietoken\n";
                stuurAntwoord($socket, ['status' => 'error', 'message' => 'Sessie is ongeldig of verlopen']);
                break;
            }
            
            if (!isset($sessies[$doelGebruiker])) {
                echo "[$ip] Lookup voor '$doelGebruiker' mislukt: gebruiker is offline\n";
                stuurAntwoord($socket, ['status' => 'error', 'message' => "Gebruiker '$doelGebruiker' is offline"]);
                break;
            }
            
            // Geef het geregistreerde adres (IP:poort of I2P .b32.i2p domein) terug
            echo "[$ip] Lookup succesvol: '$doelGebruiker' opgevraagd door client. Adres: " . $sessies[$doelGebruiker]['address'] . "\n";
            stuurAntwoord($socket, [
                'status' => 'success',
                'address' => $sessies[$doelGebruiker]['address']
            ]);
            break;
            
        default:
            echo "[$ip] Onbekende actie ontvangen: $actie\n";
            stuurAntwoord($socket, ['status' => 'error', 'message' => 'Onbekende actie']);
            break;
    }
    
    socket_close($socket);
}

/**
 * Controleert of het sessietoken van de vrager in het geheugen aanwezig is.
 */
function valideerSessie($token, $sessies) {
    foreach ($sessies as $user => $info) {
        if ($info['token'] === $token) {
            return true;
        }
    }
    return false;
}

/**
 * Lees data tot de eerste newline (\n)
 */
function leesRegel($socket) {
    $buffer = '';
    $maxLen = 4096;
    while (strlen($buffer) < $maxLen) {
        $char = @socket_read($socket, 1);
        if ($char === false || $char === '') {
            return false;
        }
        if ($char === "\n") {
            return $buffer;
        }
        $buffer .= $char;
    }
    return false;
}

/**
 * Stuurt een JSON reactie terug naar de socket.
 */
function stuurAntwoord($socket, $data) {
    $res = json_encode($data) . "\n";
    @socket_write($socket, $res);
}
?>
