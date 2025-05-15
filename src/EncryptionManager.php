<?php
/**
 * EncryptionManager - Clase para cifrado y descifrado seguro de datos usando AES-256-GCM.
 *
 * Proporciona mecanismos de cifrado simétrico robusto para registrar eventos de auditoría con confidencialidad,
 * integridad y posibilidad de rotación de claves.
 *
 * @author Aythami Melián
 * @date 2025-05-15
 * @license GPL-3.0
 */

namespace SecureAuditTrail;

class EncryptionManager
{
    /**
     * Clave simétrica derivada para cifrado
     * @var string
     */
    private string $key;

    /**
     * Constructor que establece la clave base para derivar la clave AES segura.
     *
     * @param string $key Clave secreta base proporcionada por el usuario.
     */
    public function __construct(string $key)
    {
        $this->key = hash('sha256', $key, true);
    }

    /**
     * Cifra los datos en texto plano usando AES-256-GCM.
     *
     * @param string $data Texto plano a cifrar.
     * @return string Cadena base64 con el nonce + tag + datos cifrados.
     */
    public function encrypt(string $data): string
    {
        $nonce = random_bytes(12);
        $ciphertext = openssl_encrypt($data, 'aes-256-gcm', $this->key, OPENSSL_RAW_DATA, $nonce, $tag);
        return base64_encode($nonce . $tag . $ciphertext);
    }

    /**
     * Descifra un mensaje cifrado con AES-256-GCM.
     *
     * @param string $encrypted Datos cifrados en base64.
     * @return string|null Texto plano si es exitoso, o null si la autenticación falla.
     */
    public function decrypt(string $encrypted): ?string
    {
        $decoded = base64_decode($encrypted);
        $nonce = substr($decoded, 0, 12);
        $tag = substr($decoded, 12, 16);
        $ciphertext = substr($decoded, 28);
        return openssl_decrypt($ciphertext, 'aes-256-gcm', $this->key, OPENSSL_RAW_DATA, $nonce, $tag);
    }

    /**
     * Rota la clave de cifrado a una nueva clave secreta base.
     * Guarda la clave anterior en un archivo de respaldo codificado en base64.
     *
     * @param string $newKey Nueva clave secreta base.
     * @return void
     */
    public function rotateKey(string $newKey): void
    {
        file_put_contents('key_backup_' . date('Ymd') . '.key', base64_encode($this->key));
        $this->key = hash('sha256', $newKey, true);
    }
}

