<?php
/**
 * Pruebas unitarias para la clase SecureAuditTrail.
 *
 * Valida el registro de eventos, la integridad de la cadena y el cifrado de los datos.
 *
 * @author Aythami Melián
 * @date 2025-05-15
 * @license GPL-3.0
 */

use PHPUnit\Framework\TestCase;
use SecureAuditTrail\SecureAuditTrail;
use SecureAuditTrail\EncryptionManager;

class SecureAuditTrailTest extends TestCase
{
    private PDO $pdo;
    private EncryptionManager $encryptionManager;
    private SecureAuditTrail $audit;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->exec("CREATE TABLE secure_audit_trails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            event_data TEXT NOT NULL,
            event_hash TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");

        $this->encryptionManager = new EncryptionManager('test_secret_key');
        $this->audit = new SecureAuditTrail($this->pdo, $this->encryptionManager);
    }

    public function testCanRegisterEvent(): void
    {
        $this->audit->recordEvent('test_event', ['foo' => 'bar']);

        $stmt = $this->pdo->query("SELECT COUNT(*) FROM secure_audit_trails");
        $this->assertEquals(1, $stmt->fetchColumn());
    }

    public function testVerifyIntegrityReturnsTrueInitially(): void
    {
        $this->audit->recordEvent('integrity_check', ['step' => 1]);
        $this->audit->recordEvent('integrity_check', ['step' => 2]);
        $this->assertTrue($this->audit->verifyIntegrity());
    }

    public function testVerifyIntegrityFailsOnTampering(): void
    {
        $this->audit->recordEvent('integrity_fail', ['ok' => true]);
        $this->pdo->exec("UPDATE secure_audit_trails SET event_data = 'malicious_data' WHERE id = 1");
        $this->assertFalse($this->audit->verifyIntegrity());
    }

    public function testEncryptedDataIsUnreadableWithoutKey(): void
    {
        $this->audit->recordEvent('secure_event', ['confidential' => 'yes']);

        $stmt = $this->pdo->query("SELECT event_data FROM secure_audit_trails LIMIT 1");
        $encrypted = $stmt->fetchColumn();

        $wrongManager = new EncryptionManager('wrong_key');
        $this->assertNull($wrongManager->decrypt($encrypted));
    }
}
