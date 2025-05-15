<?php
/**
 * Pruebas unitarias para la clase EncryptionManager.
 *
 * Valida el cifrado, descifrado, y la rotación segura de claves.
 *
 * @author Aythami Melián
 * @date 2025-05-15
 * @license GPL-3.0
 */

use PHPUnit\Framework\TestCase;
use SecureAuditTrail\EncryptionManager;

class EncryptionManagerTest extends TestCase
{
    private EncryptionManager $manager;

    protected function setUp(): void
    {
        $this->manager = new EncryptionManager('clave_segura');
    }

    public function testEncryptAndDecrypt(): void
    {
        $original = 'mensaje confidencial';
        $encrypted = $this->manager->encrypt($original);
        $this->assertNotEquals($original, $encrypted);

        $decrypted = $this->manager->decrypt($encrypted);
        $this->assertEquals($original, $decrypted);
    }

    public function testDecryptWithWrongKeyFails(): void
    {
        $encrypted = $this->manager->encrypt('dato');
        $otro = new EncryptionManager('clave_erronea');
        $this->assertNull($otro->decrypt($encrypted));
    }

    public function testRotateKeyChangesDecryption(): void
    {
        $original = 'dato importante';
        $encrypted = $this->manager->encrypt($original);

        $this->manager->rotateKey('clave_nueva');
        $this->assertNull($this->manager->decrypt($encrypted));
    }
}

