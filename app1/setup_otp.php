<?php
require_once __DIR__ . '/multiotp_helper.php';

if (!mfa_require_pending_or_authenticated($_SESSION)) {
    header('Location: login.php');
    exit();
}

$usuario = mfa_current_user($_SESSION);
$error = '';
$mensaje = '';
$qrDataUri = '';
$createResult = null;
$qrResult = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!mfa_multiotp_available()) {
        $error = 'No se encontro multiOTP en C:\\multiotp\\multiotp.exe.';
    } else {
        $setup = mfa_create_token_and_qr($usuario);
        $createResult = $setup['create_result'];
        $qrResult = $setup['qr_result'];
        $qrDataUri = $setup['qr_data_uri'];

        if ($setup['ok'] && $qrDataUri !== '') {
            $mensaje = 'Token TOTP generado correctamente. Escanea el QR con Google Authenticator o una app compatible.';
        } elseif ($setup['ok']) {
            $mensaje = 'El token fue creado, pero no se pudo generar el QR en imagen.';
        } else {
            $error = 'No se pudo crear el token OTP para este usuario.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configurar OTP</title>
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
            --ok-bg: #dcfce7;
            --ok-text: #166534;
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            min-height: 100vh;
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            color: var(--text);
            background: radial-gradient(circle at top right, #dff3ef 0%, var(--bg) 45%);
            padding: 20px;
        }

        .wrap {
            max-width: 980px;
            margin: 0 auto;
            display: grid;
            gap: 16px;
        }

        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
            box-shadow: 0 12px 30px rgba(27, 42, 65, 0.1);
        }

        h1, h2 { margin-top: 0; }

        .muted { color: var(--muted); }

        .error, .success {
            padding: 10px 12px;
            border-radius: 10px;
            margin-bottom: 14px;
            font-size: 0.93rem;
        }

        .error { background: var(--err-bg); color: var(--err-text); }
        .success { background: var(--ok-bg); color: var(--ok-text); }

        .actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .btn {
            border: none;
            border-radius: 10px;
            padding: 11px 14px;
            background: var(--accent);
            color: #fff;
            font-weight: 700;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }

        .btn:hover { background: var(--accent-dark); }

        .btn.secondary { background: #334155; }
        .btn.secondary:hover { background: #1f2937; }

        .layout {
            display: grid;
            gap: 18px;
            grid-template-columns: minmax(0, 1fr) 340px;
        }

        .qr-box {
            padding: 18px;
            border: 1px dashed var(--border);
            border-radius: 14px;
            background: #f8fbfd;
            text-align: center;
        }

        .qr-box img {
            max-width: 100%;
            height: auto;
            border-radius: 12px;
            background: #fff;
            padding: 8px;
        }

        .code {
            background: #0f172a;
            color: #dbeafe;
            padding: 14px;
            border-radius: 12px;
            overflow: auto;
            font-size: 0.9rem;
            white-space: pre-wrap;
            word-break: break-word;
        }

        ul {
            margin-top: 0;
            padding-left: 20px;
        }

        @media (max-width: 900px) {
            .layout { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
<div class="wrap">
    <section class="card">
        <h1>Configuracion OTP</h1>
        <p class="muted">Usuario actual: <?php echo htmlspecialchars($usuario, ENT_QUOTES, 'UTF-8'); ?></p>
        <div class="actions">
            <a class="btn secondary" href="verify_otp.php">Volver a verificar OTP</a>
            <a class="btn secondary" href="dashboard.php">Ir al dashboard</a>
            <a class="btn secondary" href="logout.php">Cerrar sesion</a>
        </div>
    </section>

    <section class="card layout">
        <div>
            <h2>Pasos</h2>
            <ul>
                <li>Presiona el boton para crear o regenerar el token TOTP del usuario actual.</li>
                <li>Escanea la imagen QR con Google Authenticator, Microsoft Authenticator, FreeOTP o una app compatible.</li>
                <li>Luego vuelve a <strong>Verificar OTP</strong> e ingresa el codigo de 6 digitos.</li>
            </ul>

            <form method="POST">
                <button class="btn" type="submit">Generar QR de Google Authenticator</button>
            </form>

            <?php if ($error !== ''): ?>
                <div class="error"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
            <?php endif; ?>

            <?php if ($mensaje !== ''): ?>
                <div class="success"><?php echo htmlspecialchars($mensaje, ENT_QUOTES, 'UTF-8'); ?></div>
            <?php endif; ?>

            <?php if ($createResult !== null): ?>
                <h2>Respuesta de multiOTP</h2>
                <div class="code"><?php echo htmlspecialchars(trim($createResult['output'] . "\n" . $qrResult['output']), ENT_QUOTES, 'UTF-8'); ?></div>
            <?php endif; ?>
        </div>

        <div class="qr-box">
            <h2>QR</h2>
            <?php if ($qrDataUri !== ''): ?>
                <img src="<?php echo htmlspecialchars($qrDataUri, ENT_QUOTES, 'UTF-8'); ?>" alt="QR de OTP">
            <?php else: ?>
                <p class="muted">Aun no se ha generado el QR.</p>
            <?php endif; ?>
        </div>
    </section>
</div>
</body>
</html>