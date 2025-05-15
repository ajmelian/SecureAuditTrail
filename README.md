# SecureAuditTrail

**SecureAuditTrail** es un sistema de registro de auditoría inmutable y cifrado, diseñado en PHP 8 para garantizar la integridad, confidencialidad y trazabilidad de eventos críticos dentro de una aplicación. Utiliza encadenamiento hash estilo blockchain, cifrado AES-256-GCM y registro asincrónico con RabbitMQ, siendo ideal para entornos que requieren cumplimiento normativo y alta seguridad.

> 🗓️ Fecha de creación: 15 de mayo de 2025  
> 👨‍💻 Autor: Aythami Melián Perdomo  
> ⚖️ Licencia: GNU GPL v3

---

## ✅ Características destacadas

- 🔐 **Cifrado AES-256-GCM** de los datos registrados.
- ⛓️ **Encadenamiento de Hashes** estilo blockchain para prevenir manipulación.
- 🧪 **Verificación de Integridad** de la cadena completa.
- ⚠️ **Alertas automáticas** vía Email y Telegram ante detección de manipulación.
- 🥒 **Registro asincrónico** mediante RabbitMQ.
- 🔁 **Rotación segura de claves** de cifrado.

---

## 🛠️ Requisitos

- PHP 8.1 o superior
- Extensiones: `openssl`, `pdo`, `mbstring`
- RabbitMQ (opcional pero recomendado)
- MySQL 5.7+ o MariaDB / PostgreSQL

---

## 📦 Instalación

```bash
composer install
cp .env.example .env
# Edita el archivo .env con tus credenciales de base de datos
```

### ▶️ Instalación de la base de datos

```php
use SecureAuditTrail\SecureAuditTrail;

SecureAuditTrail::install(__DIR__ . '/.env');
```

Esto creará la tabla `secure_audit_trails`.

---

## ⚙️ Uso básico

### 1. Inicializar el sistema

```php
use SecureAuditTrail\SecureAuditTrail;
use SecureAuditTrail\EncryptionManager;

$pdo = new PDO('mysql:host=localhost;dbname=secure_audit_db', 'usuario', 'contraseña');
$encryption = new EncryptionManager('mi_clave_secreta');
$auditTrail = new SecureAuditTrail($pdo, $encryption);
```

### 2. Registrar un evento

```php
$auditTrail->recordEvent('user_login', [
  'username' => 'admin',
  'ip' => $_SERVER['REMOTE_ADDR']
]);
```

### 3. Verificar integridad

```php
if ($auditTrail->verifyIntegrity()) {
    echo "✅ Todo en orden";
} else {
    echo "⚠️ Integridad comprometida";
}
```

---

## 🥪 Registro Asincrónico con RabbitMQ

### Enviar evento a la cola

```php
$auditTrail->publishEventToQueue('login', ['user' => 'ajmelian']);
```

### Iniciar el worker

```bash
php worker.php
```

Esto leerá eventos desde RabbitMQ y los registrará automáticamente.

---

## 🔐 Rotar clave de cifrado

```php
$encryption->rotateKey('nueva_clave_muy_segura_123');
```

Esto cambiará la clave para nuevos registros, guardando la anterior como respaldo.

---

## 📤 Notificaciones de manipulación

El sistema envía alertas automáticas cuando detecta corrupción de integridad:

- **Email:** A `admin@codesecureforge.com`
- **Telegram:** Configura tu bot con estas variables de entorno:

```env
TELEGRAM_TOKEN=tu_bot_token
TELEGRAM_CHAT_ID=tu_chat_id
```

---

## 🧪 Pruebas unitarias

Incluye pruebas con PHPUnit. Para ejecutarlas:

```bash
vendor/bin/phpunit tests/
```

---

## 📖 Licencia

Este proyecto está licenciado bajo los términos de la **GNU General Public License v3.0**.

---

## 🤓 Autor

Desarrollado por **Aythami Melián Perdomo**  
💼 [LinkedIn](https://www.linkedin.com/in/aythami-melian/)  
📂 Proyectos en [https://github.com/ajmelian](https://github.com/ajmelian)

---

## ⭐ ¡Dale una estrella!

Si este proyecto te ha sido útil o te inspira, ¡considera darle una ⭐ en GitHub y compartirlo con tu red!
