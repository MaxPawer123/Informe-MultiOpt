<?php
require_once __DIR__ . '/multiotp_helper.php';
require_once __DIR__ . '/auditoria.php';

if (!mfa_require_pending_or_authenticated($_SESSION)) {
    // Auditoria de intento no autorizado.
    registrarAuditoria($conn, mfa_current_user($_SESSION), 'ACCESO_NO_AUTORIZADO', 'Intento en verify_otp.php');
    header('Location: login.php');
    exit();
}

$mensaje = '';
$error = '';
$usuario = mfa_current_user($_SESSION);

if (mfa_is_authenticated($_SESSION)) {
    header('Location: dashboard.php');
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $otp = isset($_POST['otp']) ? trim((string) $_POST['otp']) : '';

    if ($otp === '') {
        $error = 'Debes ingresar el codigo OTP de 6 digitos.';
        // Auditoria de OTP vacio.
        registrarAuditoria($conn, $usuario, 'OTP_INCORRECTO', 'OTP vacio');
    } elseif (!mfa_multiotp_available()) {
        $error = 'No se encontro multiOTP en C:\\multiotp\\multiotp.exe.';
        // Auditoria de error de MFA.
        registrarAuditoria($conn, $usuario, 'ERROR_IMPORTANTE', 'multiOTP no disponible en verificacion');
    } else {
        $check = mfa_validate_otp($usuario, $otp);

        if ($check['ok']) {
            mfa_finish_session($_SESSION, $usuario);
            // Auditoria de OTP correcto.
            registrarAuditoria($conn, $usuario, 'OTP_CORRECTO', 'Validacion OTP exitosa');
            header('Location: dashboard.php');
            exit();
        }

        $error = 'OTP incorrecto o no valido para este usuario.';
        // Auditoria de OTP incorrecto.
        $detalleOtp = $check['output'] !== '' ? $check['output'] : 'OTP incorrecto';
        registrarAuditoria($conn, $usuario, 'OTP_INCORRECTO', $detalleOtp);
        if ($check['output'] !== '') {
            $mensaje = $check['output'];
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verificar OTP</title>
    <style>
        :root {
            --bg: #f3f7fb;
            --card: #ffffff;
            --text: #1b2a41;
            --muted: #5f6c80;
            --accent: #0f766e;
            --accent-dark: #115e59;
            --border: #d9e2ec;
            --err-bg: #fee2e2;
            --err-text: #991b1b;
            --ok-bg: #e0f2fe;
            --ok-text: #075985;
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            min-height: 100vh;
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            color: var(--text);
            background: radial-gradient(circle at top right, #dff3ef 0%, var(--bg) 45%);
            display: grid;
            place-items: center;
            padding: 20px;
        }

        .card {
            width: 100%;
            max-width: 520px;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 28px;
            box-shadow: 0 12px 30px rgba(27, 42, 65, 0.1);
        }

        h1 { margin: 0 0 8px; }

        .subtitle {
            margin: 0 0 18px;
            color: var(--muted);
            font-size: 0.95rem;
        }

        .error, .info {
            padding: 10px 12px;
            border-radius: 10px;
            margin-bottom: 14px;
            font-size: 0.92rem;
        }

        .error { background: var(--err-bg); color: var(--err-text); }
        .info { background: var(--ok-bg); color: var(--ok-text); }

        label {
            display: block;
            margin: 12px 0 6px;
            font-weight: 600;
            font-size: 0.92rem;
        }

        input {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid var(--border);
            border-radius: 10px;
            font-size: 0.95rem;
        }

        button, .btn {
            display: inline-block;
            border: none;
            border-radius: 10px;
            padding: 11px 14px;
            background: var(--accent);
            color: #fff;
            font-weight: 700;
            cursor: pointer;
            text-decoration: none;
            text-align: center;
        }

        button:hover, .btn:hover { background: var(--accent-dark); }

        .actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 16px;
        }

        .actions .btn.secondary {
            background: #334155;
        }

        .actions .btn.secondary:hover {
            background: #1f2937;
        }

        .hint {
            color: var(--muted);
            font-size: 0.9rem;
            margin-top: 10px;
        }
    </style>
</head>
<body>
<main class="card">
    <h1>Verificacion MFA</h1>
    <p class="subtitle">Usuario temporal: <?php echo htmlspecialchars($usuario, ENT_QUOTES, 'UTF-8'); ?></p>

    <?php if ($error !== ''): ?>
        <div class="error"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
    <?php endif; ?>

    <?php if ($mensaje !== ''): ?>
        <div class="info"><pre style="margin:0; white-space:pre-wrap;"><?php echo htmlspecialchars($mensaje, ENT_QUOTES, 'UTF-8'); ?></pre></div>
    <?php endif; ?>

    <form method="POST" autocomplete="off">
        <label for="otp">Codigo OTP</label>
        <input id="otp" name="otp" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required>

        <button type="submit">Validar OTP</button>
    </form>

    <p class="hint">Si es tu primer acceso y aun no escaneaste el QR, entra en configuracion OTP antes de validar el codigo.</p>

    <div class="actions">
        <a class="btn" href="setup_otp.php">Configurar OTP</a>
        <a class="btn secondary" href="logout.php">Cancelar</a>
    </div>
</main>
</body>
</html>
