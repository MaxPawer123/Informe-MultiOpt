<?php
session_start();
require_once __DIR__ . '/conexion.php';
require_once __DIR__ . '/multiotp_helper.php';
require_once __DIR__ . '/auditoria.php';

$mensaje = '';
$error = '';
$qrDataUri = '';
$createResult = null;
$qrResult = null;
$usuarioCreado = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nuevoUsuario = isset($_POST['usuario']) ? trim($_POST['usuario']) : '';
    $nuevaPassword = isset($_POST['password']) ? $_POST['password'] : '';
    $confirmarPassword = isset($_POST['password_confirm']) ? $_POST['password_confirm'] : '';

    if ($nuevoUsuario === '' || $nuevaPassword === '') {
        $error = 'Usuario y contraseña son obligatorios.';
    } elseif (strlen($nuevoUsuario) < 3) {
        $error = 'El nombre de usuario debe tener al menos 3 caracteres.';
    } elseif (strlen($nuevaPassword) < 4) {
        $error = 'La contraseña debe tener al menos 4 caracteres.';
    } elseif ($nuevaPassword !== $confirmarPassword) {
        $error = 'Las contraseñas no coinciden.';
    } else {
        // Verificar si el usuario ya existe
        $check = $conn->prepare("SELECT usuario FROM usuarios WHERE usuario = ?");
        $check->bind_param("s", $nuevoUsuario);
        $check->execute();
        $exists = $check->get_result();

        if ($exists->num_rows > 0) {
            $error = 'El nombre de usuario ya está en uso. Elige otro.';
        } else {
            $hash = sha1($nuevaPassword);
            $stmt = $conn->prepare("INSERT INTO usuarios (usuario, password) VALUES (?, ?)");
            $stmt->bind_param("ss", $nuevoUsuario, $hash);

            if ($stmt->execute()) {
                registrarAuditoria($conn, $nuevoUsuario, 'REGISTRO_USUARIO', 'Usuario registrado exitosamente');
                $usuarioCreado = $nuevoUsuario;

                // Generar token TOTP y QR automaticamente
                if (mfa_multiotp_available()) {
                    $setup = mfa_create_token_and_qr($nuevoUsuario);
                    $createResult = $setup['create_result'];
                    $qrResult = $setup['qr_result'];
                    $qrDataUri = $setup['qr_data_uri'];

                    if ($setup['ok'] && $qrDataUri !== '') {
                        $mensaje = '¡Registro exitoso! Escanea el código QR con tu app de autenticación.';
                        registrarAuditoria($conn, $nuevoUsuario, 'OTP_GENERADO', 'Token TOTP generado en registro');
                    } elseif ($setup['ok']) {
                        $mensaje = 'Usuario creado y token generado, pero no se pudo crear la imagen QR.';
                    } else {
                        $mensaje = 'Usuario creado correctamente, pero hubo un problema al generar el token OTP. Podrás configurarlo después del login.';
                    }
                } else {
                    $mensaje = 'Usuario creado correctamente. multiOTP no está disponible para generar el QR en este momento.';
                }
            } else {
                $error = 'No se pudo crear el usuario. Intenta nuevamente.';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registro de Usuario</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #f0f4f8;
            --card: #ffffff;
            --text: #1b2a41;
            --muted: #64748b;
            --accent: #0f766e;
            --accent-dark: #115e59;
            --accent-light: #ccfbf1;
            --border: #e2e8f0;
            --ok-bg: #f0fdf4;
            --ok-text: #166534;
            --err-bg: #fef2f2;
            --err-text: #991b1b;
            --shadow: 0 4px 24px rgba(15, 118, 110, 0.08);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            min-height: 100vh;
            font-family: 'Inter', 'Segoe UI', sans-serif;
            color: var(--text);
            background: linear-gradient(135deg, #e0f7f4 0%, #f0f4f8 50%, #eef2f7 100%);
            display: grid;
            place-items: center;
            padding: 24px 16px;
        }

        .container {
            width: 100%;
            max-width: 520px;
            display: grid;
            gap: 20px;
        }

        /* Mostrar QR grande cuando se genera */
        .container.has-qr { max-width: 900px; }

        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 32px 28px;
            box-shadow: var(--shadow);
            animation: fadeUp 0.5s ease both;
        }

        @keyframes fadeUp {
            from { opacity: 0; transform: translateY(16px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .header-icon {
            width: 56px; height: 56px;
            background: linear-gradient(135deg, var(--accent), #0891b2);
            border-radius: 16px;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.5rem;
            margin-bottom: 16px;
            box-shadow: 0 8px 20px rgba(15,118,110,0.2);
        }

        h1 { font-size: 1.5rem; font-weight: 800; margin-bottom: 6px; }
        .subtitle { color: var(--muted); font-size: 0.92rem; margin-bottom: 20px; line-height: 1.5; }

        .msg, .err {
            padding: 12px 16px;
            border-radius: 12px;
            margin-bottom: 16px;
            font-size: 0.9rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 8px;
            animation: fadeUp 0.4s ease both;
        }
        .msg { background: var(--ok-bg); color: var(--ok-text); border: 1px solid #bbf7d0; }
        .err { background: var(--err-bg); color: var(--err-text); border: 1px solid #fecaca; }

        .form-group { margin-bottom: 16px; }

        label {
            display: block;
            margin-bottom: 6px;
            font-weight: 600;
            font-size: 0.85rem;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }

        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px 14px;
            border-radius: 12px;
            border: 1.5px solid var(--border);
            font-size: 0.95rem;
            font-family: inherit;
            color: var(--text);
            background: #f8fafc;
            transition: border-color 0.2s, box-shadow 0.2s, background 0.2s;
        }
        input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(15,118,110,0.12);
            background: #fff;
        }

        .btn {
            border: none;
            border-radius: 12px;
            padding: 12px 20px;
            color: #fff;
            cursor: pointer;
            font-weight: 700;
            font-size: 0.92rem;
            font-family: inherit;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: transform 0.15s, box-shadow 0.15s, background 0.15s;
            width: 100%;
            justify-content: center;
        }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(0,0,0,0.15); }
        .btn:active { transform: translateY(0); }
        .btn-main { background: linear-gradient(135deg, var(--accent), var(--accent-dark)); }
        .btn-main:hover { background: linear-gradient(135deg, var(--accent-dark), #0d4d48); }

        .link-row {
            text-align: center;
            margin-top: 20px;
            font-size: 0.9rem;
            color: var(--muted);
        }
        .link-row a {
            color: var(--accent);
            font-weight: 700;
            text-decoration: none;
            transition: color 0.15s;
        }
        .link-row a:hover { color: var(--accent-dark); text-decoration: underline; }

        /* ── QR Result ── */
        .result-layout {
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 24px;
            align-items: start;
        }

        .result-header {
            display: flex;
            align-items: center;
            gap: 14px;
            margin-bottom: 20px;
        }
        .result-header .r-icon {
            width: 48px; height: 48px;
            background: linear-gradient(135deg, #10b981, #0891b2);
            border-radius: 14px;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.4rem;
            flex-shrink: 0;
        }

        .qr-container {
            background: linear-gradient(135deg, #f0fdf9, #e0f2fe);
            border: 2px dashed #a7f3d0;
            border-radius: 18px;
            padding: 24px;
            text-align: center;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 12px;
            min-width: 220px;
            animation: fadeUp 0.6s ease both;
            animation-delay: 0.2s;
        }
        .qr-container img {
            width: 200px; height: 200px;
            border-radius: 14px;
            background: #fff;
            padding: 12px;
            box-shadow: 0 8px 28px rgba(0,0,0,0.12);
        }
        .qr-label {
            font-size: 0.8rem;
            font-weight: 700;
            color: var(--accent);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .qr-apps {
            font-size: 0.76rem;
            color: var(--muted);
        }

        .steps-box {
            background: linear-gradient(135deg, #f0fdf4, #ecfdf5);
            border: 1px solid #bbf7d0;
            border-radius: 14px;
            padding: 18px 20px;
            margin-top: 16px;
        }
        .steps-box h3 {
            font-size: 0.88rem;
            font-weight: 700;
            color: #166534;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }
        .steps-box ol {
            padding-left: 20px;
            font-size: 0.88rem;
            color: #15803d;
            line-height: 1.7;
        }

        .output-label {
            font-size: 0.78rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--muted);
            margin-bottom: 6px;
            margin-top: 16px;
        }
        .code-block {
            background: #0f172a;
            color: #7dd3fc;
            border-radius: 12px;
            padding: 14px 16px;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 0.82rem;
            line-height: 1.6;
            white-space: pre-wrap;
            word-break: break-word;
            border: 1px solid #1e293b;
        }

        .pass-toggle {
            position: relative;
        }
        .pass-toggle input { padding-right: 44px; }
        .pass-toggle .toggle-btn {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            cursor: pointer;
            font-size: 1.1rem;
            color: var(--muted);
            padding: 4px;
            width: auto;
        }
        .pass-toggle .toggle-btn:hover { color: var(--accent); transform: translateY(-50%) scale(1.1); box-shadow: none; }

        @media (max-width: 700px) {
            .result-layout { grid-template-columns: 1fr; }
            .qr-container { min-width: unset; }
        }
    </style>
</head>
<body>

<div class="container <?php echo ($qrDataUri !== '') ? 'has-qr' : ''; ?>">

    <?php if ($usuarioCreado !== '' && ($mensaje !== '' || $qrDataUri !== '')): ?>
        <!-- ── Resultado del registro ── -->
        <section class="card">
            <div class="result-header">
                <div class="r-icon">✅</div>
                <div>
                    <h1 style="margin-bottom:2px;">¡Registro completado!</h1>
                    <span style="font-size:0.88rem;color:var(--muted);">Usuario: <strong><?php echo htmlspecialchars($usuarioCreado, ENT_QUOTES, 'UTF-8'); ?></strong></span>
                </div>
            </div>

            <?php if ($mensaje !== ''): ?>
                <div class="msg">✅ <?php echo htmlspecialchars($mensaje); ?></div>
            <?php endif; ?>

            <div class="result-layout">
                <div>
                    <div class="steps-box">
                        <h3>📋 Próximos pasos</h3>
                        <ol>
                            <li>Abre <strong>Google Authenticator</strong>, <strong>Microsoft Authenticator</strong> o una app compatible.</li>
                            <li>Escanea el código QR que aparece a la derecha.</li>
                            <li>Ve a la pantalla de <strong>Login</strong> e ingresa tus credenciales.</li>
                            <li>Ingresa el código OTP de 6 dígitos que genera la app.</li>
                        </ol>
                    </div>

                    <?php if ($createResult !== null): ?>
                        <p class="output-label">Salida multiOTP</p>
                        <div class="code-block"><?php echo htmlspecialchars(trim($createResult['output'] . "\n" . ($qrResult['output'] ?? '')), ENT_QUOTES, 'UTF-8'); ?></div>
                    <?php endif; ?>

                    <div style="margin-top:20px;">
                        <a class="btn btn-main" href="login.php">🔑 Ir al Login</a>
                    </div>
                </div>

                <?php if ($qrDataUri !== ''): ?>
                <div class="qr-container">
                    <p class="qr-label">📱 Escanea con tu app</p>
                    <img src="<?php echo htmlspecialchars($qrDataUri, ENT_QUOTES, 'UTF-8'); ?>" alt="Código QR para OTP">
                    <p class="qr-apps">Google Authenticator · Microsoft Authenticator · FreeOTP</p>
                </div>
                <?php endif; ?>
            </div>
        </section>

        <div class="link-row">
            <a href="registro.php">Registrar otro usuario</a> &nbsp;·&nbsp; <a href="login.php">Ir al Login</a>
        </div>

    <?php else: ?>
        <!-- ── Formulario de registro ── -->
        <section class="card">
            <div class="header-icon">👤</div>
            <h1>Crear cuenta</h1>
            <p class="subtitle">Registra un nuevo usuario. Al completar el registro se generará automáticamente tu código QR para autenticación de dos factores (2FA).</p>

            <?php if ($error !== ''): ?>
                <div class="err">⚠️ <?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>

            <form method="POST" action="registro.php" autocomplete="off" id="formRegistro">
                <div class="form-group">
                    <label for="reg_usuario">Nombre de usuario</label>
                    <input id="reg_usuario" type="text" name="usuario" required minlength="3" maxlength="50"
                           placeholder="Ej: jperez"
                           value="<?php echo isset($_POST['usuario']) ? htmlspecialchars($_POST['usuario']) : ''; ?>">
                </div>

                <div class="form-group">
                    <label for="reg_password">Contraseña</label>
                    <div class="pass-toggle">
                        <input id="reg_password" type="password" name="password" required minlength="4" placeholder="Mínimo 4 caracteres">
                        <button type="button" class="toggle-btn" onclick="togglePass('reg_password', this)" title="Mostrar/ocultar">👁️</button>
                    </div>
                </div>

                <div class="form-group">
                    <label for="reg_password_confirm">Confirmar contraseña</label>
                    <div class="pass-toggle">
                        <input id="reg_password_confirm" type="password" name="password_confirm" required minlength="4" placeholder="Repite la contraseña">
                        <button type="button" class="toggle-btn" onclick="togglePass('reg_password_confirm', this)" title="Mostrar/ocultar">👁️</button>
                    </div>
                </div>

                <button class="btn btn-main" type="submit">🚀 Registrar y generar QR</button>
            </form>

            <div class="link-row">
                ¿Ya tienes cuenta? <a href="login.php">Inicia sesión aquí</a>
            </div>
        </section>
    <?php endif; ?>
</div>

<script>
    function togglePass(inputId, btn) {
        const input = document.getElementById(inputId);
        if (input.type === 'password') {
            input.type = 'text';
            btn.textContent = '🙈';
        } else {
            input.type = 'password';
            btn.textContent = '👁️';
        }
    }

    // Validacion en cliente
    const form = document.getElementById('formRegistro');
    if (form) {
        form.addEventListener('submit', function(e) {
            const pass = document.getElementById('reg_password').value;
            const confirm = document.getElementById('reg_password_confirm').value;
            if (pass !== confirm) {
                e.preventDefault();
                const existing = form.querySelector('.err');
                if (existing) existing.remove();
                const div = document.createElement('div');
                div.className = 'err';
                div.innerHTML = '⚠️ Las contraseñas no coinciden.';
                form.insertBefore(div, form.firstChild);
            }
        });
    }
</script>

</body>
</html>
