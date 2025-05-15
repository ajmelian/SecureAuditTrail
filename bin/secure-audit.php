#!/usr/bin/env php
<?php
/**
 * Script de demostración CLI para SecureAuditTrail
 *
 * Permite registrar eventos, verificar integridad, rotar claves, listar y ver eventos o enviar a RabbitMQ.
 *
 * @author Aythami Melián
 * @date 2025-05-15
 * @license GPL-3.0
 */

// Intentar resolver el path real de autoload.php para mayor compatibilidad
\$autoloadPath = __DIR__ . '/../vendor/autoload.php';
if (!file_exists(\$autoloadPath)) {
    // Buscar en caso de ejecución desde instalación global
    \$autoloadPath = dirname(__DIR__) . '/vendor/autoload.php';
    if (!file_exists(\$autoloadPath)) {
        die("❌ No se pudo encontrar vendor/autoload.php. Asegúrate de haber ejecutado 'composer install'.\n");
    }
}
require_once \$autoloadPath;

use SecureAuditTrail\SecureAuditTrail;
use SecureAuditTrail\EncryptionManager;

function readEnv(string $path): array {
    if (!file_exists($path)) {
        die("❌ Archivo .env no encontrado.\n");
    }
    return parse_ini_file($path);
}

// Leer configuración desde .env
$env = readEnv(__DIR__ . '/../.env');
$pdo = new PDO("mysql:host={$env['DB_HOST']};dbname={$env['DB_NAME']};charset=utf8mb4", $env['DB_USER'], $env['DB_PASS'], [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
]);
$manager = new EncryptionManager($env['APP_KEY'] ?? 'default_secure_key');
$audit = new SecureAuditTrail($pdo, $manager);

// CLI
$command = isset($argv[1]) && is_string($argv[1]) ? trim($argv[1]) : null;

switch ($command) {
    case 'register':
        $type = isset($argv[2]) && is_string($argv[2]) ? trim($argv[2]) : 'manual_event';
        $data = ['executed_by' => get_current_user(), 'timestamp' => time()];
        $audit->recordEvent($type, $data);
        echo "✅ Evento registrado con tipo: {$type}\n";
        break;

    case 'verify':
        if ($audit->verifyIntegrity()) {
            echo "✅ Integridad verificada. Todos los registros están intactos.\n";
        } else {
            echo "⚠️ Integridad comprometida. Revisa el log.\n";
        }
        break;

    case 'rotate':
        $newKey = isset($argv[2]) && is_string($argv[2]) ? trim($argv[2]) : null;
        if (!$newKey) {
            echo "❌ Debes proporcionar la nueva clave como segundo argumento.\n";
            exit(1);
        }
        $manager->rotateKey($newKey);
        echo "🔁 Clave de cifrado rotada correctamente.\n";
        break;

    case 'queue':
        $type = isset($argv[2]) && is_string($argv[2]) ? trim($argv[2]) : 'queued_event';
        $data = ['user' => get_current_user(), 'from_cli' => true, 'timestamp' => time()];
        $audit->publishEventToQueue($type, $data);
        echo "📤 Evento enviado a la cola RabbitMQ: {$type}\n";
        break;

    case 'list':
        $limit = isset($argv[2]) && is_numeric($argv[2]) ? intval($argv[2]) : 10;
        $stmt = $pdo->prepare("SELECT id, event_type, created_at FROM secure_audit_trails ORDER BY id DESC LIMIT ?");
        $stmt->execute([$limit]);
        $events = $stmt->fetchAll(PDO::FETCH_ASSOC);

        echo "🧒‍📋 Últimos {$limit} eventos:\n";
        foreach ($events as $e) {
            echo "- [{$e['id']}] {$e['event_type']} @ {$e['created_at']}\n";
        }
        break;

    case 'view':
        $id = isset($argv[2]) && is_numeric($argv[2]) ? intval($argv[2]) : 0;
        if ($id < 1) {
            echo "❌ Debes proporcionar un ID válido del evento.\n";
            exit(1);
        }

        $stmt = $pdo->prepare("SELECT event_type, event_data, created_at FROM secure_audit_trails WHERE id = ?");
        $stmt->execute([$id]);
        $event = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$event) {
            echo "⚠️ Evento no encontrado.\n";
        } else {
            $data = $manager->decrypt($event['event_data']) ?: '🔐 Error al descifrar datos';
            echo "📄 Evento #{$id}:\n";
            echo "  Tipo     : {$event['event_type']}\n";
            echo "  Fecha    : {$event['created_at']}\n";
            echo "  Contenido: {$data}\n";
        }
        break;

    default:
        echo <<<HELP
🛡️ SecureAuditTrail CLI Demo 🛡️

Uso:
  php bin/secure-audit [comando] [opciones]

Comandos:
  register [tipo]       Registra un evento directamente en la base de datos
  verify                Verifica la integridad de toda la cadena de eventos
  rotate [clave]        Rota la clave de cifrado actual por una nueva
  queue [tipo]          Envia un evento a la cola RabbitMQ
  list [n]              Lista los últimos N eventos registrados (por defecto 10)
  view [id]             Muestra los datos descifrados de un evento por su ID

Ejemplos:
  php bin/secure-audit register login_sistema
  php bin/secure-audit verify
  php bin/secure-audit rotate nueva_clave_segura_123
  php bin/secure-audit queue acceso_remoto
  php bin/secure-audit list 20
  php bin/secure-audit view 7

HELP;
}
