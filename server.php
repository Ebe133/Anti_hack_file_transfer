<?php
error_reporting(E_ALL);
ini_set('display_errors', PHP_SAPI === 'cli' ? '1' : '0');

$dDir = (is_dir($p = dirname(__DIR__) . '/nexus_data') || @mkdir($p, 0700, true)) ? $p : __DIR__ . '/nexus_data';
@mkdir($dDir, 0700, true);

$uDb = $dDir . '/users.db.json';
$sDb = $dDir . '/sessions.db.json';
$aDb = $dDir . '/auth_state.db.json';

foreach ([$uDb, $sDb] as $f) {
  if (!file_exists($f)) {file_put_contents($f, '{}'); @chmod($f, 0600);}
}

function ld(string $p, array $fb = []): array {
  if (!file_exists($p)) return $fb;
  $fp = @fopen($p, 'rb');
  if (!$fp) return $fb;
  @flock($fp, LOCK_SH);
  $d = stream_get_contents($fp);
  @flock($fp, LOCK_UN);
  fclose($fp);
  $r = json_decode($d ?: '', true);
  return is_array($r) ? $r : $fb;
}

function sv(string $p, array $d): void {
  @mkdir(dirname($p), 0700, true);
  $j = json_encode($d, JSON_PRETTY_PRINT);
  $t = $p . '.tmp';
  $fp = @fopen($t, 'wb');
  if (!$fp) return;
  @flock($fp, LOCK_EX);
  fwrite($fp, $j);
  fflush($fp);
  @flock($fp, LOCK_UN);
  fclose($fp);
  @rename($t, $p);
  @chmod($p, 0600);
}

function log_msg(string $m): void {
  if (PHP_SAPI === 'cli') echo "$m\n";
  else error_log($m);
}

function jres(array $d, int $c = 200): void {
  http_response_code($c);
  header('Content-Type: application/json; charset=utf-8');
  header('X-Content-Type-Options: nosniff');
  header('Cache-Control: no-store');
  echo json_encode($d) . "\n";
}

function chkLim(string $ip, string $aDb): ?array {
  $s = ld($aDb, []);
  $t = time();
  foreach ($s as $k => $e) {
    $ws = isset($e['ws']) ? (int)$e['ws'] : $t;
    $bu = isset($e['bu']) ? (int)$e['bu'] : 0;
    if (($t - $ws) > 86400 && $bu < $t) unset($s[$k]);
  }
  if (!isset($s[$ip])) $s[$ip] = ['ws' => $t, 'cnt' => 0, 'fl' => 0, 'bu' => 0];
  $e = &$s[$ip];
  if ($e['bu'] > $t) {sv($aDb, $s); return ['status' => 'error', 'message' => 'Blocked'];}
  if (($t - (int)$e['ws']) >= 60) {$e['ws'] = $t; $e['cnt'] = 0;}
  $e['cnt']++;
  if ($e['cnt'] > 60) {$e['bu'] = $t + 60; sv($aDb, $s); return ['status' => 'error', 'message' => 'Rate limit'];}
  sv($aDb, $s);
  return null;
}

function procAct(array $d, string $ip, array &$u, array &$s): array {
  if (!isset($d['action'])) return ['status' => 'error', 'message' => 'No action'];
  $a = (string)$d['action'];
  switch ($a) {
    case 'register':
      $user = trim((string)($d['username'] ?? ''));
      $pass = (string)($d['password'] ?? '');
      if (!$user || !$pass) return ['status' => 'error', 'message' => 'Required'];
      if (strlen($user) < 3 || strlen($user) > 32) return ['status' => 'error', 'message' => 'Length 3-32'];
      $res = ['admin', 'root', 'system', 'anonymous', 'administrator', 'nexus', 'server', 'directory'];
      if (in_array(strtolower($user), $res, true)) return ['status' => 'error', 'message' => 'Reserved'];
      if (isset($u[$user])) return ['status' => 'error', 'message' => 'Exists'];
      $u[$user] = password_hash($pass, PASSWORD_BCRYPT);
      return ['status' => 'success', 'message' => 'Created'];

    case 'login':
      $user = trim((string)($d['username'] ?? ''));
      $pass = (string)($d['password'] ?? '');
      $addr = trim((string)($d['address'] ?? ''));
      $dum = '$2y$10$reZ1lKex5oG1U1W1E1E1Eu1V1E1E1E1E1E1E1E1E1E1E1E1E1E1E1';
      $ex = isset($u[$user]);
      $h = $ex ? (string)$u[$user] : $dum;
      if (!password_verify($pass, $h) || !$ex) return ['status' => 'error', 'message' => 'Invalid'];
      if ($addr && !preg_match('/^[a-z2-7]{52}\.b32\.i2p$/', $addr)) return ['status' => 'error', 'message' => 'Bad addr'];
      $tok = bin2hex(random_bytes(16));
      $s[$user] = ['addr' => $addr, 'tok' => $tok, 'upd' => time(), 'ip' => $ip];
      return ['status' => 'success', 'session_token' => $tok];

    case 'update_address':
      $tok = (string)($d['session_token'] ?? '');
      $addr = trim((string)($d['address'] ?? ''));
      if (!$addr || !preg_match('/^[a-z2-7]{52}\.b32\.i2p$/', $addr)) return ['status' => 'error', 'message' => 'Bad addr'];
      foreach ($s as &$i) {
        if (isset($i['tok']) && hash_equals((string)$i['tok'], $tok)) {
          $i['addr'] = $addr;
          $i['upd'] = time();
          return ['status' => 'success', 'message' => 'Updated'];
        }
      }
      return ['status' => 'error', 'message' => 'Not found'];

    case 'lookup':
      $tok = (string)($d['session_token'] ?? '');
      $tgt = trim((string)($d['target'] ?? ''));
      if (!$tgt || !preg_match('/^[a-zA-Z0-9_\-]+$/', $tgt)) return ['status' => 'error', 'message' => 'Bad user'];
      $found = false;
      foreach ($s as $u => $i) {
        if (hash_equals((string)($i['tok'] ?? ''), $tok)) {$found = true; break;}
      }
      if (!$found) return ['status' => 'error', 'message' => 'Bad token'];
      if (!isset($s[$tgt]) || !$s[$tgt]['addr']) return ['status' => 'error', 'message' => 'Offline'];
      $s[$tgt]['upd'] = time();
      return ['status' => 'success', 'address' => $s[$tgt]['addr']];

    case 'verify_session':
      $tok = (string)($d['session_token'] ?? '');
      $user = trim((string)($d['username'] ?? ''));
      if (!$user || !preg_match('/^[a-zA-Z0-9_\-]+$/', $user)) return ['status' => 'error', 'message' => 'Bad user'];
      if (!isset($s[$user]) || !hash_equals((string)($s[$user]['tok'] ?? ''), $tok)) return ['status' => 'error', 'message' => 'Bad token'];
      return ['status' => 'success', 'message' => 'Valid'];

    default:
      return ['status' => 'error', 'message' => 'Unknown action'];
  }
}

if (PHP_SAPI !== 'cli') {
  $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
  $m = $_SERVER['REQUEST_METHOD'] ?? 'GET';

  $lf = $dDir . '/db.lock';
  $lfp = fopen($lf, 'c');
  if ($lfp) flock($lfp, LOCK_EX);

  $rl = chkLim($ip, $aDb);
  if ($rl) {
    if ($lfp) {flock($lfp, LOCK_UN); fclose($lfp);}
    jres($rl, 429);
    exit;
  }

  if ($m !== 'POST') {
    if ($lfp) {flock($lfp, LOCK_UN); fclose($lfp);}
    jres(['status' => 'error', 'message' => 'POST only'], 405);
    exit;
  }

  $raw = file_get_contents('php://input');
  if (strlen($raw) > 8192) {
    if ($lfp) {flock($lfp, LOCK_UN); fclose($lfp);}
    jres(['status' => 'error', 'message' => 'Too large'], 413);
    exit;
  }

  $d = json_decode($raw, true);
  if (!is_array($d)) {
    if ($lfp) {flock($lfp, LOCK_UN); fclose($lfp);}
    jres(['status' => 'error', 'message' => 'Bad JSON'], 400);
    exit;
  }

  $u = ld($uDb, []);
  $s = ld($sDb, []);

  $t = time();
  foreach ($s as $usr => $i) {
    $upd = isset($i['upd']) ? (int)$i['upd'] : 0;
    if ($upd > 0 && ($t - $upd) > 180) unset($s[$usr]);
  }

  $res = procAct($d, $ip, $u, $s);

  sv($uDb, $u);
  sv($sDb, $s);

  if ($lfp) {flock($lfp, LOCK_UN); fclose($lfp);}
  jres($res, $res['status'] === 'success' ? 200 : 400);
  exit;
}

if (!extension_loaded('sockets')) {die("Need sockets ext\n");}

$port = isset($argv[1]) ? (int)$argv[1] : 8000;
$srv = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
if (!$srv) die("Create failed\n");
socket_set_option($srv, SOL_SOCKET, SO_REUSEADDR, 1);
if (!socket_bind($srv, '0.0.0.0', $port)) die("Bind failed\n");
if (!socket_listen($srv, 10)) die("Listen failed\n");
echo "Listening on 0.0.0.0:$port\n";

while (true) {
  $c = socket_accept($srv);
  if (!$c) continue;
  $ip = '';
  socket_getpeername($c, $ip);
  $buf = '';
  while (strlen($buf) < 8192) {
    $d = socket_read($c, 4096);
    if (!$d || $d === false) break;
    $buf .= $d;
    $nl = strpos($buf, "\n");
    if ($nl !== false) {
      $ln = substr($buf, 0, $nl);
      $data = json_decode($ln, true);
      $res = is_array($data) ? procAct($data, $ip, $u, $s) : ['status' => 'error'];
      socket_write($c, json_encode($res) . "\n");
      break;
    }
  }
  socket_close($c);
}
