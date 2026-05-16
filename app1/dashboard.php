<?php
require_once __DIR__ . "/multiotp_helper.php";
require_once __DIR__ . "/auditoria.php";

// El dashboard solo debe abrirse despues de validar OTP.
if (!mfa_require_authenticated($_SESSION)) {
    // Auditoria de intento no autorizado.
    registrarAuditoria($conn, mfa_current_user($_SESSION), 'ACCESO_NO_AUTORIZADO', 'Intento en dashboard.php');
    header('Location: login.php');
    exit();
}
$usuario = mfa_current_user($_SESSION);
// Auditoria de acceso al dashboard.
registrarAuditoria($conn, $usuario, 'ACCESO_DASHBOARD', 'Ingreso al dashboard');
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <style>
        body {
            margin: 0;
            min-height: 100vh;
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            background: #f3f7fb;
            color: #1b2a41;
            display: grid;
            place-items: center;
            padding: 20px;
        }

        .panel {
            background: #fff;
            border: 1px solid #d9e2ec;
            border-radius: 14px;
            padding: 26px;
            max-width: 520px;
            width: 100%;
            text-align: center;
            box-shadow: 0 12px 30px rgba(27, 42, 65, 0.08);
        }

        a {
            display: inline-block;
            margin-top: 16px;
            text-decoration: none;
            color: #0f766e;
            font-weight: 700;
        }
    </style>
</head>
<body>
    <section class="panel">
        <h1>Bienvenido, <?php echo htmlspecialchars($usuario, ENT_QUOTES, 'UTF-8'); ?></h1>
        <p>Inicio de sesion completado con MFA/TOTP.</p>
        <a href="usuarios.php">Gestionar usuarios (ABM)</a>
        <br>
        <a href="transferencias.php">Modulo de transferencias bancarias</a>
        <br>
        <a href="setup_otp.php">Configurar o regenerar OTP</a>
        <br>
        <a href="logout.php">Cerrar sesion</a>
    </section>
</body>
</html>
