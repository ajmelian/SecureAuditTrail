<?php
/**
 * SecureAuditTrail - Sistema seguro de auditoría con cifrado y encadenamiento hash.
 *
 * Registra eventos de forma inmutable, cifrada y con verificación de integridad,
 * permitiendo trazabilidad avanzada y cumplimiento normativo.
 *
 * Requiere una base de datos compatible con PDO y un gestor de cifrado como EncryptionManager.
 *
 * @author Aythami Melián
 * @date 2025-05-15
 * @license GPL-3.0
 */

namespace SecureAuditTrail;

use PDO;
use PhpAmqpLib\Connection\AMQPStreamConnection;
use PhpAmqpLib\Message\AMQPMessage;

class SecureAuditTrail
{
    private PDO $db;
    private EncryptionManager $encryptionManager;

    /**
     * Constructor.
     *
     * @param PDO $db Instancia PDO de la base de datos.
     * @param EncryptionManager $encryptionManager Gestor de cifrado.
     */
    public function __construct(PDO $db, EncryptionManager $encryptionManager)
    {
        $this->db = $db;
        $this->encryptionManager = $encryptionManager;
    }

    /**
     * Registra un evento de auditoría cifrado y con hash encadenado.
     *
     * @param string $eventType Tipo del evento (ej: login, delete_user).
     * @param array $eventData Datos asociados al evento.
     * @return void
     */
    public function recordEvent(string $eventType, array $eventData): void
    {
        $dataJson = json_encode($eventData);
        $encryptedData = $this->encryptionManager->encrypt($dataJson);
        $previousHash = $this->getLastEventHash() ?? str_repeat('0', 64);
        $eventHash = hash('sha256', $encryptedData . $previousHash);

        $stmt = $this->db->prepare("INSERT INTO secure_audit_trails (event_type, event_data, event_hash, previous_hash, created_at)
                                    VALUES (?, ?, ?, ?, NOW())");
        $stmt->execute([$eventType, $encryptedData, $eventHash, $previousHash]);
    }

    /**
     * Obtiene el hash del último evento registrado.
     *
     * @return string|null Hash del último evento o null si no hay registros.
     */
    private function getLastEventHash(): ?string
    {
        $stmt = $this->db->query("SELECT event_hash FROM secure_audit_trails ORDER BY id DESC LIMIT 1");
        return $stmt->fetchColumn() ?: null;
    }

    /**
     * Verifica la integridad de todos los eventos encadenados.
     *
     * @return bool True si todos los hashes coinciden, False si hay integridad comprometida.
     */
    public function verifyIntegrity(): bool
    {
        $stmt = $this->db->query("SELECT event_data, event_hash, previous_hash FROM secure_audit_trails ORDER BY id ASC");
        $previousHash = str_repeat('0', 64);

        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $calculatedHash = hash('sha256', $row['event_data'] . $previousHash);
            if ($calculatedHash !== $row['event_hash']) {
                $this->triggerTamperingAlert($row);
                return false;
            }
            $previousHash = $row['event_hash'];
        }
        return true;
    }

    /**
     * Envía una alerta en caso de detectar manipulación en la integridad.
     *
     * @param array $compromisedRow Fila sospechosa o manipulada.
     * @return void
     */
    private function triggerTamperingAlert(array $compromisedRow): void
    {
        $message = "ALERTA: Integridad comprometida en SecureAuditTrail. Hash: {$compromisedRow['event_hash']}";

        // Enviar por email
        mail('admin@codesecureforge.com', 'ALERTA DE INTEGRIDAD', $message);

        // Enviar por Telegram si está configurado
        $token = getenv('TELEGRAM_TOKEN');
        $chatId = getenv('TELEGRAM_CHAT_ID');
        if ($token && $chatId) {
            $url = "https://api.telegram.org/bot{$token}/sendMessage?chat_id={$chatId}&text=" . urlencode($message);
            @file_get_contents($url);
        }

        error_log($message);
    }

    /**
     * Publica un evento en una cola RabbitMQ para procesamiento asincrónico.
     *
     * @param string $eventType Tipo del evento.
     * @param array $eventData Datos asociados al evento.
     * @return void
     */
    public function publishEventToQueue(string $eventType, array $eventData): void
    {
        $connection = new AMQPStreamConnection('localhost', 5672, 'guest', 'guest');
        $channel = $connection->channel();
        $channel->queue_declare('audit_events', false, true, false, false);

        $payload = json_encode(['type' => $eventType, 'data' => $eventData]);
        $msg = new AMQPMessage($payload, ['delivery_mode' => AMQPMessage::DELIVERY_MODE_PERSISTENT]);

        $channel->basic_publish($msg, '', 'audit_events');

        $channel->close();
        $connection->close();
    }
}
